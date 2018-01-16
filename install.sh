#!/bin/bash
if [ "$(grep -c ACCOUNTNUMBERHERE policy-dev.json)" != "0" ]; then
    echo "set the account number in the policy-dev.json"
    exit
fi

yum -y install https://centos7.iuscommunity.org/ius-release.rpm
yum -y install python36u python36u-devel python36u-pip
wget 'https://bootstrap.pypa.io/get-pip.py'
pip3.6 install chalice

chalice webhook
cp app.py webhook
cp requirements.txt webhook
cp policy-dev.json webhook/.chalice
cd webhook && chalice deploy


