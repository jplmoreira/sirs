#!/bin/bash

echo "Setup scan server ..."

echo "Installing python"
apt-get update
sudo apt-get install python3-pip python3-dev python3-setuptools -y

pip3 install -r /vagrant/requirements.txt

cp /vagrant/setup/scan.service /lib/systemd/system/scan.service
systemctl daemon-reload
systemctl enable scan.service
systemctl start scan.service

echo "192.168.30.2 a30-sirs.com" >> /etc/hosts

echo "export SSL_HOST='a30-sirs.com'" >> ~/.bashrc
echo "export SSL_PORT=8082" >> ~/.bashrc
echo "export SSL_CLIENT_CERT='/vagrant/ssl/scan-1.crt'" >> ~/.bashrc
echo "export SSL_CLIENT_KEY='/vagrant/ssl/scan-1.key'" >> ~/.bashrc
echo "export SSL_CA_CERT='/vagrant/ssl/root_ca.crt'" >> ~/.bashrc
echo "export CA_CERT='/vagrant/ssl/root_ca.crt'" >> ~/.bashrc
echo "export SCAN_HOST='192.168.40.2'" >> ~/.bashrc
echo "export SCAN_BROADCAST='192.168.40.255'" >> ~/.bashrc
echo "export SCAN_PORT=9999" >> ~/.bashrc
echo "export SCAN_LOCATION='gps for network sirs-scan-1-'" >> ~/.bashrc
echo "export PYTHONPATH=\"$PYTHONPATH:/vagrant\"" >> ~/.bashrc

