import boto3
import urllib3
import json
import subprocess
import logging
import time
import os
import shlex
import stat

log = logging.getLogger()

iot_cert_pem = os.environ['SECRET_IOT_CERT_PEM'].replace('\\n', '\n')
iot_key_pem = os.environ['SECRET_IOT_KEY_PEM'].replace('\\n', '\n')
thing_name = os.environ['SECRET_THING_NAME']
credentials_url = os.environ['SECRET_CREDENTIALS_URL']
region = os.environ['SECRET_REGION']
config_param = os.environ['SECRET_SSM_CONFIG_PARAM']

local_ssh_port = 2222
cert_file = 'iot.crt'
key_file = 'iot.key'
key_filename = 'ssh-key-file.pem'

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

    ssh_command = shlex.split("ssh -N -i '{}' -p {} -R {}:{}:{} -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=no {}@localhost".format(
        key_filename, local_ssh_port, config['remote_port_forward_local_port'], config['remote_port_forward_remote_host'], config['remote_port_forward_remote_port'], config['ssh_user']))

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

    # For tracking whether our processes are working properly
    port_forward_fail_count = 0

    while True:
        # Start the EC2 session to the RDS proxy
        response = ssm_client.start_session(
            Target=target,
            DocumentName=document,
            Parameters=parameters
        )

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
        print('Starting port forwarding session...')
        port_forward_start_time = time.time()
        p = subprocess.Popen(
            port_forward_command, stderr=subprocess.PIPE)

        ssh_fail_count = 0
        while p.returncode is None:
            print('Starting SSH with remote tunnel...')

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

        stdout = p.stdout.read()
        stderr = p.stderr.read()
        # Print the process output
        log.warn('Session manager exited with stdout: {}'.format(
            stdout.decode('utf-8')))
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
