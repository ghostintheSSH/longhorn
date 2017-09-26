#!/bin/bash


#things to do
# call sysctl -p at end to reload settings for ipsec


#vars for some things

ipsec="# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0 
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0 
net.ipv6.conf.default.accept_redirects = 0

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1"

ipv6="#disable ipv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1"

nospoof="order bind,hosts
nospoof on"

cronkill="ALL"

iptables=("iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP" "iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP" "iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"" "iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP" "iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"" "iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP" "iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP" "iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP" "iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT" "iptables -A OUTPUT -p icmp -o eth0 -j ACCEPT" "iptables -A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT" "iptables -A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT" "iptables -A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT" "iptables -A INPUT -p icmp -i eth0 -j DROP")

#the above ip tables will kill ddos with threshhold set. force syn packet checks, drop all null, allow established outgoing, drop icmp

response=$(zenity --height=250 --list --checklist \
	--title='selection' --column=Boxes --column=Selections \
	TRUE "IPsec" TRUE "Disable IPv6" TRUE "Kill Cron" TRUE "Kill Spoofing" TRUE "IP Tables" --separator=':')

if [ -z "$response" ] ; then
	echo "No Selection"
	exit 1
fi

IFS=":" ; for word in $response ; do
	case $word in
		"IPsec") echo $ipsec >> testfile1.txt ;;
		"Disable IPv6") echo $ipv6 >> testfile1.txt ;;
		"Kill Cron") echo $cronkill >> /etc/cron.deny && chown root:root /etc/cron.deny ;;
		"Kill Spoofing") echo $nospoof >> /etc/host.conf ;;
		"IP Tables") for (( i =0; i < ${#iptables[@]} ; i++)); do eval "${iptables[$i]}"; done ;;
	esac

done
