#!/bin/bash

# redhat
  # yum install -y python3-pip bind-utils

# archlinux / manjaro
  # pacman -S python-pip bind

cp ./bind-api.service /etc/systemd/system/

cp ./bind-api.conf /etc/
echo "^ set / control permissions"
# ^ permission set correct! --> ???
  # chown root:root /etc/bind-api.conf
  # chmod 640 /etc/bind-api.conf

cp ./bind-restapi.py /usr/local/bin/

echo "^ set / control permissions"
# ^ permission set correct! --> ???
  # chown root:root /usr/local/bin/bind-restapi.py
  # chmod 700 /usr/local/bin/bind-restapi.py

pip3 install -r requirements.txt
systemctl enable bind-api.service
systemctl start bind-api.service
