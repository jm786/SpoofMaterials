#!/bin/bash

set -e
set -x

if [ $# -ne 2 ]
then
        echo "Wrong number of arguments supplied."
        echo "Usage: $0 <server_url> <deploy_key>."
        exit 1
fi

server_url=$1
deploy_key=$2

yum -y update

if [ -f /etc/redhat-release ]
then

    export PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:$PATH
    yum -y install wget curl epel-release python-setuptools python-pip

cat >> /etc/supervisord.conf <<EOF
[include]
files=/etc/supervisord.d/*.ini
EOF

cat > /etc/yum.repos.d/docker.repo <<EOF
[dockerrepo]
name=Docker Repository
baseurl=http://yum.dockerproject.org/repo/main/centos/6/
enabled=1
gpgcheck=0
EOF

    yum -y install docker-engine
    service docker start
    mkdir -p /var/dionaea /var/dionaea/wwwroot /var/dionaea/binaries /var/dionaea/log  /var/dionaea/bitstreams /var/dionaea/rtp /var/dionaea/bistreams
    mkdir -p /etc/dionaea/

    #fixme
    chmod -R a+wrx /var/dionaea
    docker pull threatstream/dionaea-mhn

    # Register the sensor with MHN server.
    wget $server_url/static/registration.txt -O registration.sh
    chmod 755 registration.sh
    # Note: this will export the HPF_* variables
    . ./registration.sh $server_url $deploy_key "dionaea"

    echo "Getting dionea from $server_url"
    curl $server_url/static/dionaea.conf | sed -e "s/HPF_HOST/$HPF_HOST/" | sed -e "s/HPF_PORT/$HPF_PORT/" | sed -e "s/HPF_IDENT/$HPF_IDENT/" | sed -e "s/HPF_SECRET/$HPF_SECRET/" > /etc/dionaea/dionaea.conf

cat > /etc/supervisord.d/dionaea.ini <<EOF
[program:dionaea]
command=docker run --cap-add=NET_BIND_SERVICE --rm=true -p 80:80 -p 21:21 -p 42:42 -p 8080:80 -p 135:135 -p 443:443 -p 445:445 -p 1433:1433 -p 3306:3306 -p 5061:5061 -p 5060:5060 -p 69:69/udp -p 5060:5060/udp -v /var/dionaea:/data/dionaea -v /etc/dionaea:/etc/dionaea threatstream/dionaea-mhn:latest supervisord
directory=/var/dionaea
stdout_logfile=/var/log/dionaea.out
stderr_logfile=/var/log/dionaea.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

    supervisorctl update
    exit 0
fi

cat > /etc/supervisord.d/dionaea.ini<<EOF
[program:dionaea]
command=dionaea -c /etc/dionaea/dionaea.conf -w /var/dionaea -u nobody -g nogroup
directory=/var/dionaea
stdout_logfile=/var/log/dionaea.out
stderr_logfile=/var/log/dionaea.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

supervisorctl update
