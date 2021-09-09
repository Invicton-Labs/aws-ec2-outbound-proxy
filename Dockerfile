# syntax=docker/dockerfile:1
FROM ubuntu:20.04
RUN apt-get update
RUN apt-get install -y python3 python3-pip curl openssh-client
# Install AWS session-manager-plugin
RUN curl "https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb" -o "session-manager-plugin.deb"
RUN dpkg -i session-manager-plugin.deb
RUN pip install boto3
WORKDIR /app
COPY ./app .
USER root
CMD ["python3", "main.py"]