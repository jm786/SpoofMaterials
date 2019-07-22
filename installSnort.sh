#!/bin/bash
INTERFACE=eth0

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

yum update
yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm  || true

# if [ $? -eq 0 ]; then
#   echo "Installed EPEL"
# else 
#   echo "Failed to install EPEL"
# fi

yum install -y gcc flex bison zlib libpcap zlib-devel jansson-devel libpcap-devel pcre-devel libdnet-devel pcre libdnet tcpdump wget python-pip git

yum group install -y "Development Tools"

cd /tmp
rm -rf libev*
wget https://github.com/threatstream/hpfeeds/releases/download/libev-4.15/libev-4.15.tar.gz
tar zxvf libev-4.15.tar.gz 
cd libev-4.15
./configure && make && make install
ldconfig


pip install --upgrade distribute
pip install --upgrade pip
pip install virtualenv
pip install docopt pyparsing requests sqlalchemy watchdog hpfeeds==1.0


cd /tmp
rm -rf hpfeeds
git clone https://github.com/threatstream/hpfeeds.git
cd hpfeeds/appsupport/libhpfeeds
autoreconf --install
./configure && make && make install 


yum install -y libnghttp2



# Don't do this... yet
#sudo yum install -y https://www.snort.org/downloads/snort/daq-2.0.6-1.centos7.x86_64.rpm
#sudo yum install -y https://www.snort.org/downloads/snort/snort-2.9.12-1.centos7.x86_64.rpm
#sudo ldconfig
sudo groupadd snort || true
sudo useradd snort -r -s /sbin/nologin -c SNORT_IDS -g snort || true

cd /tmp
rm -rf hpfeeds
git clone https://github.com/threatstream/hpfeeds.git
cd hpfeeds/appsupport/libhpfeeds
autoreconf --install
./configure && make && make install

cd /tmp
wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -xzvf daq-2.0.6.tar.gz
cd daq-2.0.6
./configure
make 
make install

cd /tmp
rm -rf snort
git clone -b hpfeeds-support https://github.com/threatstream/snort.git
export CPPFLAGS=-I/include
export PATH=$PATH:/usr/local/bin
cd snort
./configure --prefix=/opt/snort && make && make install 

# Register the sensor with the MHN server.
wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
# Note: this will export the HPF_* variables
. ./registration.sh $server_url $deploy_key "snort"

mkdir -p /opt/snort/etc /opt/snort/rules /opt/snort/lib/snort_dynamicrules /opt/snort/lib/snort_dynamicpreprocessor /var/log/snort/



cd etc

cp snort.conf classification.config reference.config threshold.conf unicode.map /opt/snort/etc/
touch  /opt/snort/rules/white_list.rules
touch  /opt/snort/rules/black_list.rules

cd /opt/snort/etc/
sed -i 's#/usr/local/#/opt/snort/#' snort.conf 
sed -i -r 's,include \$RULE_PATH/(.*),# include $RULE_PATH/\1,' snort.conf
sed -i 's,# include $RULE_PATH/local.rules,include $RULE_PATH/local.rules,' snort.conf
sed -i "s/# hpfeeds/# hpfeeds\noutput log_hpfeeds: host $HPF_HOST, ident $HPF_IDENT, secret $HPF_SECRET, channel snort.alerts, port $HPF_PORT/" snort.conf 



IP=$(ip address show $INTERFACE | egrep 'inet ' | cut -f6 -d " " | cut -f1 -d "/")
sed -i 's/ipvar HOME_NET any/ipvar HOME_NET [216.73.240.0\/20,10.0.0.0\/8,172.16.0.0\/12,192.168.0.0\/16]/' snort.conf

# Installing snort rules.
# mhn.rules will be used as local.rules.
rm -f /etc/snort/rules/local.rules
ln -s /opt/mhn/rules/mhn.rules /opt/snort/rules/local.rules || true

sudo touch /var/log/snort.log || true
sudo mkdir /var/log/snort || true

chown -R snort:snort /opt/snort
chown -R snort:snort /var/log/snort.log
chown -R snort:snort /var/log/snort/

yum install -y supervisor

supervisord -c /etc/supervisord.conf

# Config for supervisor.
cat > /etc/supervisord.d/snort.ini <<EOF
[program:snort]
command=/opt/snort/bin/snort -c /opt/snort/etc/snort.conf -u snort -g snort -i $INTERFACE
directory=/opt/snort
stdout_logfile=/var/log/snort.log
stderr_logfile=/var/log/snort.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

cat > /etc/cron.daily/update_snort_rules.sh <<EOF
#!/bin/bash

mkdir -p /opt/mhn/rules
rm -f /opt/mhn/rules/mhn.rules.tmp

echo "[`date`] Updating snort signatures ..."
wget $server_url/static/mhn.rules -O /opt/mhn/rules/mhn.rules.tmp && \
	mv /opt/mhn/rules/mhn.rules.tmp /opt/mhn/rules/mhn.rules && \
	(supervisorctl update ; supervisorctl restart snort ) && \
	echo "[`date`] Successfully updated snort signatures" && \
	exit 0

echo "[`date`] Failed to update snort signatures"
exit 1
EOF

chmod 755 /etc/cron.daily/update_snort_rules.sh
/etc/cron.daily/update_snort_rules.sh

supervisorctl update