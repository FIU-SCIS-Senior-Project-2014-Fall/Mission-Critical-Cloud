#!/bin/bash
#hduser setup

U="hduser"
G="hadoop"

getent passwd $U > /dev/null 

if [ $? -eq 0 ]; then
    echo "user $U exists"
else
	sudo addgroup $G
	sudo adduser --ingroup $G $U
fi


HM=$(awk -F: -v v="$U" '{ if ($1==v) print $6}' /etc/passwd)
echo "$U's home dir = $HM"

sudo su - hduser && ssh-keygen -t rsa -P "" -f $HM/.ssh/id_rsa && cat $HM/.ssh/id_rsa.pub >> $HM/.ssh/authorized_keys
ssh localhost
