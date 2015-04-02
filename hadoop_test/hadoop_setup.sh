#!/bin/bash
#hduser setup


getent passwd hduser > /dev/null 

if [ $? -eq 0 ]; then
    echo "hduser exists"
else
	sudo addgroup hadoop
	sudo adduser --ingroup hadoop hduser
fi

sudo su - hduser
ssh-keygen -t rsa -P "" -f $HOME/.ssh/id_rsa
cat $HOME/.ssh/id_rsa.pub >> $HOME/.ssh/authorized_keys
ssh localhost
