#!/bin/bash


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

sharedmem="#secure shared memory
tmpfs     /run/shm    tmpfs	defaults,noexec,nosuid	0	0"

discam="

#Disables webcam
blacklist uvcvideo"

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

#the above ip tables will kill ddos with threshhold set. force syn packet checks, drop all null, allow established outgoing, drop icmp

Z_Main() {
	response=$(zenity --height=600 --width=800 --list --checklist \
		--title='Project Longhorn' --column=Boxes --column=Selections --column=Description \
		TRUE "General Hardening" "Limits su to sudo group users, secures TTY, & secures shared memory" \
		TRUE "Kill Tools" "Disables unused tools & vulnerable features" \
		TRUE "Purge Tools" "Purges unused tools" \
		TRUE "Kill Cron" "Kills CRON for all users" \
		TRUE "Secure /tmp & /var" "Creates partitions for & moves /tmp & /var" \
		TRUE "IPsec" "Protects against SYN floods, DDoS, broadcasting, direct ICMP pinging, & redirects" \
		TRUE "Disable IPv6" "Disables IPv6" \
		TRUE "Kill Spoofing" "Prevents IP spoofing" \
		TRUE "Filter Ports" "Scans & modifies open ports to filtered" \
		TRUE "IP Tables" "IP Table Additions: anti-portscan, logging, DDoS threshholds, IP ban for scanners/abusers" \
		TRUE "Secure SSH" "Limits SSH connection attempts, anti-portscan, IP ban for scanners/abusers, hardens SSH" \
		--separator=':' 2> /dev/null)

	if [ -z "$response" ] ; then
		echo "No Selection"
		exit 1
	fi

	IFS=":" ; for word in $response ; do
		case $word in
			"General Hardening") Z_Harden ;;
			"Kill Tools") Z_KillTools ;;
			"Purge Tools") Z_RmTools ;;
			"Kill Cron") sudo bash -c "echo >> /etc/cron.deny \"ALL\"" && chown root:root /etc/cron.deny ;;
			"Secure /tmp & /var") Z_TmpVar ;;
			"IPsec") sudo bash -c "echo >> /etc/sysctl.conf $ipsec" ;;
			"Disable IPv6") sudo bash -c "echo >> /etc/sysctl.conf $ipv6" ;;
			"Kill Spoofing") sudo sed -i '2,3 s/^/#/' /etc/host.conf && sudo bash -c "echo >> /etc/host.conf $nospoof" ;;
			"Filter Ports") Z_Ports ;;
			"IP Tables") Z_IP ;;
			"Secure SSH") Z_SSH && sudo bash -c "echo >> /etc/ssh/sshd_config $secssh" ;;
		esac
	done
}

Z_Harden() {
	response=$(sudo zenity --height=600 --width=800 --list --checklist \
		--title='Project Longhorn - General Hardening' --column=Boxes --column=Selections --column=Description \
		TRUE "Secure su" "Limits su to sudo group users" \
		TRUE "Secure TTY" "Disables all secondary TTY terminals, changes root owner of securetty with perms update" \
		TRUE "Secure shared memory" "Moves shared memory to own partition & remounts" \
		TRUE "Secure root user" "Locks root user" \
		--separator=':' 2> /dev/null)

	IFS=":" ; for word in $response ; do
		case $word in
			"Secure su") sudo dpkg-statoverride --update --add root sudo 4750 /bin/su ;;
			"Secure TTY") sudo sed -i '30,401 s/^/#/' /etc/securetty && sudo chown root:root /etc/securetty && sudo chmod 0600 /etc/securetty ;;
			"Secure shared memory") sudo bash -c "echo >> /etc/fstab $sharedmem" && sudo mount -a ;;
			"Secure root user") sudo passwd -l root ;;
		esac
	done
}

Z_KillTools() {
	response=$(sudo zenity --height=600 --width=800 --list --checklist \
		--title='Project Longhorn - Kill Tools' --column=Boxes --column=Selections --column=Description \
		TRUE "Disable IRQ balance" "Disables IRQ balance" \
		TRUE "Disable anacron" "Disables anacron" \
		TRUE "Disable compilers" "Changes compilers permissions to unreadable, unwriteable, & unexecutable" \
		TRUE "Disable control+alt+delete" "Disables safe reboot shortcut keys" \
		TRUE "Disable autofs" "Disables autofs" \
		TRUE "Disable atd" "Disables atd by changing service start to manual" \
		TRUE "Disable apport" "Disables apport" \
		TRUE "Disable avahi" "Disables avahi by changing service start to manual" \
		TRUE "Disable CUPS" "Disables CUPS by changing service start to manual" \
		TRUE "Disable whoopsie" "Disables whoopsie crash reporting" \
		TRUE "Disable webcam" "Disables webcam & blacklists for next boot" \
		TRUE "Mute mic" "Mic cannot be disabled without disabling soundcard, but can be muted" \
		TRUE "Disable Bluetooth" "Disables Bluetooth & disables autostart for future sessions" \
		TRUE "Disable Wi-Fi" "Disables Wi-Fi by changing service start to manual & restarts network manager" \
		--separator=':' 2> /dev/null)

	IFS=":" ; for word in $response ; do
		case $word in
			"Disable IRQ balance") sudo sed -i.bak 's/^\(ENABLED=\).*/\10/' /etc/default/irqbalance ;;
			"Disable anacron") sudo sed -i '11,14 s/^/#/' /etc/crontab ;;
			"Disable compilers") sudo chmod 000 /usr/bin/byacc /usr/bin/yacc /usr/bin/bcc /usr/bin/kgcc /usr/bin/cc /usr/bin/gcc /usr/bin/*c++ /usr/bin/*g++ ;;
			"Disable control+alt+delete") sudo sed -i '12 s/^/#/' /etc/init/control-alt-delete.conf ;;
			"Disable autofs") sudo bash -c "echo >> /etc/udev/rules.d/85-no-automount.rules \"SUBSYSTEM==\\"usb\\", ENV{UDISKS_AUTO}=\\"0\\"\"" \
				&& sudo service udev restart ;;
			"Disable atd") sudo bash -c "echo 'manual' > /etc/init/atd.override" ;;
			"Disable apport") sudo sed -i.bak 's/^\(ENABLED=\).*/\10/' /etc/default/apport ;;
			"Disable avahi") sudo touch avahi-daemon.override && sudo bash -c "echo -e \"manual\" > avahi-daemon.override" ;;
			"Disable CUPS") sudo bash -c "echo -e \"manual\" > /etc/init/cups.override" ;;
			"Disable whoopsie") sudo sed -i.bak 's/^\(report_crashes=\).*/\1false/' /etc/default/whoopsie ;;
			"Disable webcam") sudo modprobe -r uvcvideo && sudo bash -c "echo >> /etc/modprobe.d/blacklist.conf $discam" ;;
			"Disable Bluetooth") sudo bash -c "echo >> /etc/rc.local \"rfkill block bluetooth\"" && sudo sed -i.bak 's/^\(InitiallyPowered =\).*/\1false/' \
				/etc/bluetooth/main.conf ;;
			"Disable Wi-Fi") sudo bash -c "echo >> /etc/network/interfaces \"iface wlan0 inet manual\"" && sudo service network-manager restart ;;
			"Mute mic") amixer set Capture nocap ;;
		esac
	done
}

Z_RmTools() {
	response=$(sudo zenity --height=600 --width=800 --list --checklist \
		--title='Project Longhorn - Purge Tools' --column=Boxes --column=Selections --column=Description \
		TRUE "Purge at" "Uninstalls at & removes configuration files" \
		TRUE "Purge apport" "Uninstalls apport & removes configuration files" \
		TRUE "Purge zeitgeist" "Uninstalls zeitgeist & removes configuration files" \
		TRUE "Purge nfs" "Uninstalls nfs & removes configuration files" \
		TRUE "Purge avahi" "Uninstalls avahi & removes configuration files" \
		TRUE "Purge CUPS" "Uninstalls CUPS & removes configuration files" \
		TRUE "Purge dovecot" "Uninstalls dovecot & removes configuration files" \
		TRUE "Purge SNMP" "Uninstalls SNMP & removes configuration files" \
		TRUE "Purge telnet" "Uninstalls telnet & removes configuration files" \
		TRUE "Purge whoopsie" "Uninstalls whoopsie & removes configuration files" \
		--separator=':' 2> /dev/null)

	IFS=":" ; for word in $response ; do
		case $word in
			"Purge at") sudo apt-get purge at ;;
			"Purge apport") sudo apt-get purge apport ;;
			"Purge zeitgeist") sudo apt-get purge zeitgeist-core zeitgeist-datahub python-zeitgeist rhythmbox-plugin-zeitgeist zeitgeist ;;
			"Purge nfs") sudo apt-get purge nfs-kernel-server nfs-common portmap rpcbind autofs ;;
			"Purge avahi") sudo apt-get purge avahi-daemon avahi-utils ;;
			"Purge CUPS") sudo apt-get purge cups ;;
			"Purge dovecot") sudo apt-get purge dovecot-* ;;
			"Purge SNMP") sudo apt-get purge --auto-remove snmp ;;
			"Purge telnet") sudo apt-get purge telnetd inetutils-telnetd telnetd-ssl ;;
			"Purge whoopsie") sudo apt-get purge whoopsie ;;
		esac
	done
}

MoveDir() {
	#NEEDS ZENITY WITH WARNING WINDOW & ASKING IF SURE THEY WANT TO CONTINUE WITH THIS FUNCTION
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

Z_Ports() {
	#NEEDS ZENITY WITH PROGRESS BAR
	nmap -sV -p "*" localhost -oA ports
	cat ports.nmap | grep open | cut -d"/" -f1 >> openports.txt
	while read line; do
		sudo iptables -A OUTPUT -p tcp -m tcp --dport $line -j ACCEPT
		sudo iptables -A INPUT -p tcp -m tcp --dport $line -j DROP
	done < openports.txt
	shred -zvfu *ports.* > /dev/null 2>&1
}

Z_IP() {
	response=$(sudo zenity --height=600 --width=800 --list --checklist \
		--title='Project Longhorn - IP Tables' --column=Boxes --column=Selections --column=Description \
		TRUE "Block portscanner" "Blocks portscanner for 24 hours" \
		TRUE "Lift lock" "Lifts lock on portscanner after 24 hours is complete" \
		TRUE "Log portscans" "Logs portscan attempt and portscanner" \
		TRUE "Check SYN" "Force checks SYN packets" \
		TRUE "Block NULL" "Blocks all NULL packets" \
		TRUE "Keep Connections" "Maintains established connections from dropping" \
		TRUE "Block pings" "Blocks all incoming pings" \
		--separator=':' 2> /dev/null)

	IFS=":" ; for word in $response ; do
		case $word in
			"Block portscanner") sudo iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP \
				&& sudo iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP ;;
			"Lift lock") sudo iptables -A INPUT   -m recent --name portscan --remove && sudo iptables -A FORWARD -m recent --name portscan --remove ;;
			"Log portscans") sudo iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan: " \
				&& sudo iptables -A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP \
				&& sudo iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan: " \
				&& sudo iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP ;;
			"Check SYN") sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP ;;
			"Block NULL") sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP ;;
			"Keep Connections") sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT ;;
			"Block pings") sudo iptables -A OUTPUT -p icmp -o eth0 -j ACCEPT && sudo iptables -A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT \
				&& sudo iptables -A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT \
				&& sudo iptables -A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT && sudo iptables -A INPUT -p icmp -i eth0 -j DROP ;;
		esac
	done
}

Z_SSH() {
	sudo bash -c "echo >> /etc/hosts.deny \"sshd : ALL\""

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

Z_Main
