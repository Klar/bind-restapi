#!/bin/bash

# redhat
  # yum install -y python3-pip bind-utils

# archlinux / manjaro
  # pacman -S python-pip bind

cp ./bind-api.service /etc/systemd/system/
chmod 644 /etc/systemd/system/bind-api.service

cp ./bind-api.conf /etc/
chown root:root /etc/bind-api.conf
chmod 640 /etc/bind-api.conf

cp ./bind-restapi.py /usr/local/bin/
chown root:root /usr/local/bin/bind-restapi.py
chmod 640 /usr/local/bin/bind-restapi.py

pip3 install -r requirements.txt
systemctl enable bind-api.service
systemctl start bind-api.service
