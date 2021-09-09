import boto3
import urllib3
import json
import subprocess
import logging
import time
import os
import shlex
import stat
import socket

log = logging.getLogger()
log.setLevel(logging.INFO)

iot_cert_pem = os.environ['SECRET_IOT_CERT_PEM'].replace('\\n', '\n')
iot_key_pem = os.environ['SECRET_IOT_KEY_PEM'].replace('\\n', '\n')
thing_name = os.environ['SECRET_THING_NAME']
credentials_url = os.environ['SECRET_CREDENTIALS_URL']
region = os.environ['SECRET_REGION']
config_param = os.environ['SECRET_SSM_CONFIG_PARAM']

cert_file = '/tmp/iot.crt'
key_file = '/tmp/iot.key'
key_filename = '/tmp/ssh-key-file.pem'

retries = urllib3.Retry(connect=5, read=2, redirect=5)
http = urllib3.PoolManager(
    cert_file=cert_file,
    key_file=key_file,
    cert_reqs="CERT_REQUIRED",
    headers={
        'x-amzn-iot-thingname': thing_name
    },
    retries=retries
)

with open(cert_file, 'w') as f:
    f.write(iot_cert_pem)
    # Set read/write for file owner only
os.chmod(cert_file, stat.S_IRWXU)

with open(key_file, 'w') as f:
    f.write(iot_key_pem)
    # Set read/write for file owner only
os.chmod(key_file, stat.S_IRWXU)


def get_boto_session():
    resp = http.request(
        "GET", credentials_url)
    if resp.status != 200:
        raise Exception("Failed to retrieve STS token: {}".format(resp.reason))
    creds = json.loads(resp.data)['credentials']
    return boto3.session.Session(aws_access_key_id=creds['accessKeyId'], aws_secret_access_key=creds['secretAccessKey'], aws_session_token=creds['sessionToken'], region_name=region)


def get_open_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    s.listen(1)
    port = s.getsockname()[1]
    s.close()
    return port


if __name__ == '__main__':
    sess = get_boto_session()
    ssm_client = sess.client('ssm')
    secrets_client = sess.client('secretsmanager')

    # Get the SSM config parameter
    config = json.loads(ssm_client.get_parameter(
        Name=config_param,
        WithDecryption=True
    )['Parameter']['Value'])

    ssh_key_pem = secrets_client.get_secret_value(
        SecretId=config['ssh_key_secret_arn'],
    )['SecretString']

    with open(key_filename, 'w') as f:
        f.write(ssh_key_pem)
    # Set read/write for file owner only
    os.chmod(key_filename, stat.S_IRWXU)

    # For tracking whether our processes are working properly
    port_forward_fail_count = 0

    while True:
        # Get an available port number
        local_ssh_port = get_open_port()

        # Create the port forwarding command/parameters
        target = config['rds_proxy_id']
        document = 'AWS-StartPortForwardingSession'
        parameters = {
            'portNumber': [
                str(config['ssh_port'])  # '5432',
            ],
            'localPortNumber': [
                str(local_ssh_port)  # '5432'
            ]
        }
        try:
            # Start the EC2 session to the RDS proxy
            response = ssm_client.start_session(
                Target=target,
                DocumentName=document,
                Parameters=parameters
            )
        except Exception as e:
            log.error("Failed to create session with EC2 instance: {}".format(e))
            time.sleep(2)
            # It might be a credentials error: try getting a new session and client
            sess = get_boto_session()
            ssm_client = sess.client('ssm')
            continue

        # Start the port forwarding to 22
        port_forward_command = [
            'session-manager-plugin',
            json.dumps(response),
            region,
            'StartSession',
            '',
            json.dumps({
                'Target': target,
                'DocumentName': document,
                'Parameters': parameters
            }),
            'https://ssm.{}.amazonaws.com'.format(region)
        ]
        log.info('Starting port forwarding session on local port {}...'.format(
            local_ssh_port))
        port_forward_start_time = time.time()
        p = subprocess.Popen(
            port_forward_command, stderr=subprocess.PIPE)

        # Create the remote port forward commands
        rpf_flags = ' '.join(['-R {}:{}:{}:{}'.format(r['local_host'], r['local_port'], r['remote_host'],
                                                      r['remote_port']) for r in config['remote_port_forwards']])
        # Create the SSH command
        ssh_command = "ssh -N -i '{}' -p {} {} -o UserKnownHostsFile=/dev/null -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no {}@localhost".format(
            key_filename, local_ssh_port, rpf_flags, config['ssh_user'])
        ssh_command_split = shlex.split(ssh_command)

        # Give the port forwarding session a second to get started
        time.sleep(2)

        ssh_fail_count = 0

        # As long as the port forwarding session is open, keep trying to reconnect the SSH tunnel
        while p.returncode is None:
            log.info('Starting SSH using command: `{}`'.format(ssh_command))

            # Get the start time of the process
            ssh_start_time = time.time()
            res = subprocess.run(ssh_command)
            # Check how long the process ran
            ssh_elapsed_seconds = time.time() - ssh_start_time

            # Print the process output
            if res.returncode != 0 or res.stderr != b'':
                if res.stderr is None:
                    res.stderr = b''
                log.error('SSH tunnel failed with exit code {} and stderr: {}'.format(
                    res.returncode, res.stderr.decode('utf-8')))
            else:
                log.warn('SSH tunnel exited')

            # If it ran > 30 seconds, we'll consider that a successful session
            if ssh_elapsed_seconds > 30:
                # Reset the failure count
                ssh_fail_count = 0
            else:
                # Otherwise, mark it as unsuccessful
                ssh_fail_count += 1

            # If it's failed too many times, try killing the port forward process and breaking out to retry it
            if ssh_fail_count >= 10:
                p.kill()
                break

            # For every unsuccessful connection in a row, sleep an additional second (linear back-off)
            # Don't sleep more than 10 seconds though
            if ssh_fail_count > 0:
                time.sleep(min(10, ssh_fail_count))

        port_forward_elapsed_seconds = time.time() - port_forward_start_time

        stderr = p.stderr.read()
        if p.returncode != 0 or stderr != b'':
            if p.stderr is None:
                p.stderr = b''
            log.error('Session manager failed with exit code {} and stderr: {}'.format(
                p.returncode, stderr.decode('utf-8')))
        else:
            log.warn('Session manager exited')

        # If it ran > 30 seconds, we'll consider that a successful session
        if port_forward_elapsed_seconds > 30:
            # Reset the failure count
            port_forward_fail_count = 0
        else:
            # Otherwise, mark it as unsuccessful
            port_forward_fail_count += 1

        # For every unsuccessful connection in a row, sleep an additional second (linear back-off)
        # Don't sleep more than 10 seconds though
        if port_forward_fail_count > 0:
            time.sleep(min(10, port_forward_fail_count))
