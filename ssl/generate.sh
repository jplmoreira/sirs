#!/usr/bin/env bash

echo "generate root CA key"
openssl genrsa -out root_ca.key

echo "generate root CA certificate"
openssl req -new -key root_ca.key -out root_ca.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=A30 SIRS CA/OU=IT Department/CN=ca.a30-sirs.com"
openssl x509 -req -days 365 -in root_ca.csr -signkey root_ca.key -out root_ca.crt

echo "create database file (.srl)"
echo 01 > root_ca.srl

echo "generate central server key and certificate"
openssl genrsa -out central.key
openssl req -new -key central.key -out central.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=A30 SIRS/OU=IT Department/CN=central.a30-sirs.com"
openssl x509 -req -days 365 -in central.csr -CA root_ca.crt -CAkey root_ca.key -out central.crt

echo "generate https server key and certificate"
openssl genrsa -out https.key
openssl req -new -key https.key -out https.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=A30 SIRS/OU=IT Department/CN=https.a30-sirs.com"
openssl x509 -req -days 365 -in https.csr -CA root_ca.crt -CAkey root_ca.key -out https.crt

echo "generate scan-1 server key and certificate"
openssl genrsa -out scan-1.key
openssl req -new -key scan-1.key -out scan-1.csr -subj "/C=PT/ST=Lisbon/L=Lisbon/O=A30 SIRS/OU=IT Department/CN=scan-1.a30-sirs.com"
openssl x509 -req -days 365 -in scan-1.csr -CA root_ca.crt -CAkey root_ca.key -out scan-1.crt
