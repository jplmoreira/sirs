#!/bin/bash

echo "Setup central server ..."

#TODO: firewalls ufw
#TODO: NAT

echo "Installing python"
apt-get update
sudo apt-get install python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools -y

pip3 install -r /vagrant/requirements.txt

echo "Installing Nginx"
apt-get install -y nginx
rm -f /etc/nginx/sites-enabled/*
cp /vagrant/setup/nginx_https.conf /etc/nginx/sites-available/nginx_https.conf
chmod 644 /etc/nginx/sites-available/nginx_https.conf
ln -s /etc/nginx/sites-available/nginx_https.conf /etc/nginx/sites-enabled/nginx_https.conf

cp /vagrant/setup/central.service /lib/systemd/system/central.service
systemctl daemon-reload
systemctl enable central.service
systemctl start central.service

systemctl enable nginx
systemctl restart nginx

echo "export SSL_HOST='192.168.30.2'" >> ~/.bashrc
echo "export SSL_PORT=8082" >>  ~/.bashrc
echo "export SSL_CERT='/vagrant/ssl/central.crt'" >>  ~/.bashrc
echo "export SSL_KEY='/vagrant/ssl/central.key'" >>  ~/.bashrc
echo "export SSL_CA_CERT='/vagrant/ssl/root_ca.crt'" >>  ~/.bashrc
echo "export PYTHONPATH=\"$PYTHONPATH:/vagrant\"" >>  ~/.bashrc


# python3 /vagrant/central/scan.py