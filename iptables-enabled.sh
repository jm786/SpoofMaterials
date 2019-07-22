#!/bin/bash

MANIP="216.73.240.168"
MONIPS=("216.73.240.169"\
	#"216.73.240.170"\
	)

sudo iptables -P INPUT ACCEPT
sudo iptables -P OUTPUT ACCEPT
sudo iptables -F

sudo iptables -N LOGGING
sudo iptables -N DOCKER

sudo iptables -A INPUT -i lo -j ACCEPT
echo "Allowing management traffic (ssh) to $MANIP"
sudo iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A INPUT -s 172.16.6.0/24 -d $MANIP -p tcp --dport 22 -m state --state NEW -m tcp -j ACCEPT
sudo iptables -A INPUT -s 172.16.90.0/24 -d $MANIP -p tcp --dport 22 -m state --state NEW -m tcp -j ACCEPT
sudo iptables -A INPUT -s 10.190.119.0/24 -d $MANIP -p tcp --dport 22 -m state --state NEW -m tcp -j ACCEPT

echo "Allowing all traffic to $MANIP from Vulnerabilities Scanner"
sudo iptables -A INPUT -s 172.16.5.40 -d $MANIP -j ACCEPT
sudo iptables -A INPUT -s 172.16.5.41 -d $MANIP -j ACCEPT

for MONIP in ${MONIPS[@]}; do
    echo "Allowing all traffic to $MONIP & deny all traffic from Vulnerabilies Traffic"
    sudo iptables -A INPUT -s 172.16.5.40 -d $MONIP -j DROP
    sudo iptables -A INPUT -s 172.16.5.41 -d $MONIP -j DROP
    sudo iptables -A INPUT -d $MONIP -j ACCEPT
done

sudo iptables -A INPUT -j LOGGING
sudo iptables -A OUTPUT -o lo -j ACCEPT
sudo iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT

# Allows DNS
sudo iptables -A OUTPUT -s $MANIP -p udp -m state --state NEW -m udp --dport 53 -j ACCEPT

# Allows access to spacewalk server
sudo iptables -A OUTPUT -s $MANIP -d 216.73.240.184/32 -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 216.73.240.184/32 -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT

# Allows access to ldap for authentication
sudo iptables -A OUTPUT -s $MANIP -d 216.73.240.141/32 -p tcp -m state --state NEW -m tcp --dport 389 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 216.73.240.141/32 -p tcp -m state --state NEW -m tcp --dport 636 -j ACCEPT

# Allows access to NTP Servers
sudo iptables -A OUTPUT -s $MANIP -d 216.73.240.147/32 -p udp -m state --state NEW -m udp --dport 123 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 216.73.240.146/32 -p udp -m state --state NEW -m udp --dport 123 -j ACCEPT

# Allows access to logging servers
sudo iptables -A OUTPUT -s $MANIP -d 192.168.64.96/32 -p udp -m state --state NEW -m udp --dport 514 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 192.168.64.96/32 -p tcp -m state --state NEW -m tcp --dport 514 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 192.168.64.96/32 -p tcp -m state --state NEW -m tcp --dport 5044 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 192.168.64.87/32 -p udp -m state --state NEW -m udp --dport 514 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 192.168.64.87/32 -p tcp -m state --state NEW -m tcp --dport 514 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 192.168.64.87/32 -p tcp -m state --state NEW -m tcp --dport 5044 -j ACCEPT
sudo iptables -A OUTPUT -s $MANIP -d 216.73.246.111/32 -p udp -m state --state NEW -m udp --dport 514 -j ACCEPT

# Allows access to MHN Management Server
sudo iptables -A OUTPUT -s $MANIP -d 216.73.240.164/32 -p tcp -m state --state NEW -m tcp -m multiport --dports 80,443,10000 -j ACCEPT

# Allows access for SpoofSpotter
sudo iptables -A OUTPUT -s $MONIP -p udp -m state --state NEW -m udp -j ACCEPT

# Dump remaining traffic to logging chain
sudo iptables -A OUTPUT -j LOGGING

# Log the traffic
for MONIP in ${MONIPS[@]}; do
    echo "Allowing all traffic to $MONIP"
    sudo iptables -A LOGGING -s $MONIP -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: "
    sudo iptables -A LOGGING -d $MONIP -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: "
done

sudo iptables -A LOGGING -s $MANIP -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: "
sudo iptables -A LOGGING -d $MANIP -m limit --limit 2/min -j LOG --log-prefix "IPTables-Dropped: "

# Drop the traffic
sudo iptables -A LOGGING -j DROP

# Drop Nessus Scanner from Docker
sudo iptables -A FORWARD -o docker0 -s 172.16.5.40 -j DROP
sudo iptables -A FORWARD -o docker0 -s 172.16.5.41 -j DROP

#sudo iptables -P INPUT DROP
#sudo iptables -P OUTPUT DROP
