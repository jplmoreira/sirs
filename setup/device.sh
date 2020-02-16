#!/bin/bash

echo "Setup client server ..."

echo "Installing python"
apt-get update
sudo apt-get install python3-pip python3-dev python3-setuptools -y

echo "export CA_CERT='/vagrant/ssl/root_ca.crt'" >>  ~/.bashrc

pip3 install -r /vagrant/requirements.txt