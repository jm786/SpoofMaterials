#!/bin/bash

yum -y update
pip install numpy hpfeeds

mkdir -p /opt/spoofspotter/bin

git clone https://github.com/jm786/SpoofMaterials.git /opt/spoofspotter/bin

server_url=$1
deploy_key=$2

# Register the sensor with MHN server.
wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "spoofspotter"

# Config for supervisor.
cat > /etc/supervisord.d/spoofspotter.ini <<EOF
[program:spoofspotter]
command=python SpoofSpotter.py -R 5 -g $HPF_HOST $HPF_IDENT $HPF_SECRET $HPF_PORT
directory=/opt/spoofspotter/bin
stdout_logfile=/var/log/spoofspotter.log
stderr_logfile=/var/log/spoofspotter.err
redirect_stderr=true
EOF

supervisorctl update