#!/bin/bash


#things to do
# call sysctl -p at end to reload settings for ipsec

zenity --question --title="Project Longhorn" --text="The system will be updated.\n\nClick Yes to continue or No to move on."
   if [ "$?" -eq "0" ];then

x=$( stdbuf -oL /bin/bash \-c '(sudo apt-get update \-y && sudp apt-get upgrade \-y)' 2>&1 |
stdbuf -oL sed -n -e '/\[*$/ s/^/# /p' -e '/\*$/ s/^/# /p'|
zenity --progress --title="Updating package information..." --pulsate \
--width=600 --auto-close )

sudo dpkg --clear-avail 

else
	exit 0
fi

zenity --question --title="Project Longhorn" --text="Install dependancies.\n\nClick Yes to continue or No to move on."
	if [ "$?" -eq "0" ];then

x=$( stdbuf -oL /bin/bash \-c '(sudo apt-get install nmap \-y)' |
stdbuf -oL sed -n -e '/\[*$/ s/^/# /p' -e '/\*$/ s/^/# /p'|
zenity --progress --title="Installing dependancies and upgrading..." --pulsate \
--width=600 --auto-close )

else
	exit 0
fi


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

secssh="

#Blocks users from setting environment options
PermitUserEnvironment no

#Hides last user to login
PrintLastLog no

#Disables UseDNS
UseDNS no
			
#Sets idle timeout interval to 3 minutes
ClientAliveInterval 180
ClientAliveCountMax 0
			
#Sets max unauthenticated connections to SSH daemon to 2
MaxStartups 2"

discam="

#Disables webcam
blacklist uvcvideo"

Harden() {
	sudo dpkg-statoverride --update --add root sudo 4750 /bin/su
	sudo sed -i '30,401 s/^/#/' /etc/securetty
	sudo chown root:root /etc/securetty
	sudo chmod 0600 /etc/securetty
	sudo echo >> /etc/fstab "#secure shared memory
	tmpfs     /run/shm    tmpfs	defaults,noexec,nosuid	0	0"
	sudo mount -a
}

DisableTools() {
	sudo passwd -l root
	sudo sed -i.bak 's/^\(ENABLED=\).*/\10/' /etc/default/irqbalance
	sudo sed -i '11,14 s/^/#/' /etc/crontab
	sudo chmod 000 /usr/bin/byacc /usr/bin/yacc /usr/bin/bcc /usr/bin/kgcc /usr/bin/cc /usr/bin/gcc /usr/bin/*c++ /usr/bin/*g++
	sudo sed -i '12 s/^/#/' /etc/init/control-alt-delete.conf
	sudo echo >> /etc/udev/rules.d/85-no-automount.rules "SUBSYSTEM==\"usb\", ENV{UDISKS_AUTO}=\"0\""
	sudo service udev restart
	sudo echo 'manual' > /etc/init/atd.override
	sudo sed -i.bak 's/^\(ENABLED=\).*/\10/' /etc/default/apport
	sudo apt-get purge apport
	sudo touch avahi-daemon.override
	sudo echo -e "manual" > avahi-daemon.override
	sudo echo -e "manual" > /etc/init/cups.override
	sudo sed -i.bak 's/^\(report_crashes=\).*/\1false/' /etc/default/whoopsie
	sudo modprobe -r uvcvideo
	sudo echo >> /etc/modprobe.d/blacklist.conf
	amixer set Capture nocap
}

RmTools() {
	sudo apt-get purge at
	sudo apt-get purge zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist
	sudo apt-get purge nfs-kernel-server nfs-common portmap rpcbind autofs
	sudo apt-get -y remove avahi-daemon avahi-utils
	sudo apt-get -y remove cups
	sudo apt-get purge dovecot-* --auto-remove snmp
	sudo apt-get purge telnetd inetutils-telnetd telnetd-ssl whoopsie
}

MoveDir() {
	sudo dd if=/dev/zero of=/usr/tmpDSK bs=1024 count=1024000
	sudo cp -Rpfv /tmp /tmpbackup
	sudo mount -t tmpfs -o loop,noexec,nosuid,rw /usr/tmpDSK /tmp
	sudo chmod 1777 /tmp
	sudo cp -Rpf /tmpbackup/* /tmp/
	sudo rm -rf /tmpbackup/*
	sudo /usr/tmpDSK /tmp tmpfs loop,nosuid,noexec,rw 0 0
	sudo mount -o remount /tmp
	sudo mv /var/tmp /var/tmpold
	sudo ln -s /tmp /var/tmp
	sudo cp -prfv /var/tmpold/* /tmp/
}

Ports() {
	nmap -sV -p "*" localhost -oA ports
	cat ports.nmap | grep open | cut -d"/" -f1 >> openports.txt
	while read line; do
		sudo iptables -A OUTPUT -p tcp -m tcp --dport $line -j ACCEPT
		sudo iptables -A INPUT -p tcp -m tcp --dport $line -j DROP
	done < openports.txt
	shred -zvfu *ports.* > /dev/null 2>&1
}

IPtable() {
	sudo iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
	sudo iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP
	sudo iptables -A INPUT   -m recent --name portscan --remove
	sudo iptables -A FORWARD -m recent --name portscan --remove
	sudo iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan: "
	sudo iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
	sudo iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan: "
	sudo iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP
	sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
	sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
	sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	sudo iptables -A OUTPUT -p icmp -o eth0 -j ACCEPT
	sudo iptables -A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT
	sudo iptables -A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT
	sudo iptables -A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT
	sudo iptables -A INPUT -p icmp -i eth0 -j DROP
}

SecureSH() {
	sudo echo >> /etc/hosts.deny "sshd : ALL"

	sudo iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --set
	sudo iptables -I INPUT -p tcp --dport 22 -i eth0 -m state --state NEW -m recent --update --seconds 30 --hitcount 3 -j DROP
	sudo iptables -I INPUT -p tcp --dport ssh -i eth0 -m state --state NEW -m recent  --set
	sudo iptables -I INPUT -p tcp --dport ssh -i eth0 -m state --state NEW -m recent  --update --seconds 30 --hitcount 3 -j DROP

	sudo sed -i.bak 's/^\(PermitRootLogin \).*/\1no/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(PermitEmptyPasswords \).*/\1no/' /etc/ssh/sshd_config
	sudo sed -i '/#PasswordAuthentication/c\PasswordAuthentication' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(PasswordAuthentication \).*/\1no/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(Protocol \).*/\12/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(IgnoreRhosts \).*/\1yes/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(RhostsAuthentication \).*/\1no/' /etc/ssh/sshd_config
	sudo sed -i '/RhostsAuthentication/a RhostsRSAAuthentication no' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(RSAAuthentication \).*/\yes/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(HostbasedAuthentication \).*/\1no/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(LoginGraceTime \).*/\160/' /etc/ssh/sshd_config
	sudo sed -i '/X11Forwarding/a AllowTcpForwarding no' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(X11Forwarding \).*/\1no/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(LogLevel \).*/\1VERBOSE/' /etc/ssh/sshd_config
	sudo sed -i.bak 's/^\(StrictModes \).*/\1yes/' /etc/ssh/sshd_config
}

#the above ip tables will kill ddos with threshhold set. force syn packet checks, drop all null, allow established outgoing, drop icmp

response=$(zenity --height=600 --width=800 --list --checklist \
	--title='Project Longhorn' --column=Boxes --column=Selections --column=Description \
	TRUE "IPsec" "Protects against SYN floods, DDoS, broadcasting, direct ICMP pinging, & redirects" \
	TRUE "Disable IPv6" "Disables IPv6" \
	TRUE "Kill Cron" "Kills CRON for all users" \
	TRUE "Kill Spoofing" "Prevents IP spoofing" \
	TRUE "General Hardening" "Limits su to sudo group users, secures TTY, & secures shared memory" \
	TRUE "Kill Tools" "Disables unused tools & vulnerable features" \
	TRUE "Purge Tools" "Purges unused tools" \
	TRUE "Secure /tmp & /var" "Creates partitions for & moves /tmp & /var" \
	TRUE "Filter Ports" "Scans & modifies open ports to filtered" \
	TRUE "IP Tables" "IP Table Additions: anti-portscan, logging, DDoS threshholds, IP ban for scanners/abusers" \
	TRUE "Secure SSH" "Limits SSH connection attempts, anti-portscan, IP ban for scanners/abusers, hardens SSH" \
	--separator=':')

if [ -z "$response" ] ; then
	echo "No Selection"
	exit 1
fi

IFS=":" ; for word in $response ; do
	case $word in
		"IPsec") echo >> /etc/sysctl.conf $ipsec ;;
		"Disable IPv6") echo >> /etc/sysctl.conf $ipv6 ;;
		"Kill Cron") echo >> /etc/cron.deny && chown root:root /etc/cron.deny $cronkill ;;
		"Kill Spoofing") sudo sed -i '2,3 s/^/#/' /etc/host.conf && sudo echo >> /etc/host.conf $nospoof ;;
		"General Hardening") Harden ;;
		"Kill Tools") DisableTools && sudo echo >> /etc/modprobe.d/blacklist.conf $discam ;;
		"Purge Tools") RmTools ;;
		"Secure /tmp & /var") MoveDir ;;
		"Filter Ports") Ports ;;
		"IP Tables") IPtable ;;
		"Secure SSH") SecureSH && sudo echo >> /etc/ssh/sshd_config $secssh ;;
	esac

done
