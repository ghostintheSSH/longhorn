#this will run, and it wont be pretty, IGNORE IP talbes, they are built for Godaddy VPS which is where i am testing- they are limiting on what you can do 

#!/bin/bash


#jesus this is going to be ugly until i get all i want in here and start spring cleaning
#vars for now FTW until i start asking user for var inputs 
sshport = 22

#update and remove baddies and install some  goodies
sudo apt-get update
sudo apt-get upgrade

#purge some baddies
sudo apt-get purge rpcbind samba fetchmail postfix smnp* quota
sudo apt-get -y install nmap nano


#install ufw NOTE will not work on godaddy VPS
sudo apt-get -y install ufw

#enable ufw enable ssh
sudo ufw enable && sudo ufw allow ssh





#things to add to ssh config
#will need to echo this, possibly make a copy of current config and add this to that, then out to a new config all together
#sed works for replacing lines however some might not have added configs
sed -i 'Ns/.*/Port $sshport/' /etc/ssh/sshd_config
sed -i '$ PermitRootLogin no' /etc/ssh/sshd_config
sed -i '$ PermitEmptyPasswords no' /etc/ssh/sshd_config
sed -i '$ PermitUserEnvironment no' /etc/ssh/sshd_config
sed -i '$ PrintLastLog no' /etc/ssh/sshd_config
sed -i '$ PasswordAuthentication no' /etc/ssh/sshd_config
sed -i '$ UseDNS no' /etc/ssh/sshd_config
sed -i '$ ClientAliveInterval 300' /etc/ssh/sshd_config
sed -i '$ ClientAliveCountMax 0' /etc/ssh/sshd_config
sed -i '$ IgnoreRhosts yes' /etc/ssh/sshd_config
sed -i '$ RhostsAuthentication no' /etc/ssh/sshd_config
sed -i '$ RhostsRSAAuthentication no' /etc/ssh/sshd_config
sed -i '$ RSAAuthentication yes' /etc/ssh/sshd_config
sed -i '$ LoginGraceTime 150' /etc/ssh/sshd_config
sed -i '$ AllowTcpForwarding no' /etc/ssh/sshd_config
sed -i '$ X11Forwarding no' /etc/ssh/sshd_config
sed -i '$ LogLevel VERBOSE' /etc/ssh/sshd_config
sed -i '$ StrictModes yes' /etc/ssh/sshd_config

#PermitRootLogin no
#PermitEmptyPasswords no
#PermitUserEnvironment no
#PrintLastLog no
#PasswordAuthentication no
#UseDNS no
#ClientAliveInterval 300
#ClientAliveCountMax 0
#IgnoreRhosts yes
#RhostsAuthentication no
#RhostsRSAAuthentication no
#RSAAuthentication yes
#LoginGraceTime 150
#AllowTcpForwarding no
#X11Forwarding no
#LogLevel VERBOSE
#StrictModes yes




#add ssh new port to IPtables
#not needed now as i have a full iptables output later
#sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT
#sudo iptables-save > /root/my.active.firewall.rules


#secure shared mem
#sudo vi /etc/fstab
sudo sed -i '$tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0' /etc/fstab

#add user to admin, limit su to admin
sudo groupadd admin
sudo usermod -a -G admin $user
sudo dpkg-statoverride --update --add root admin 4750 /bin/su

--------------------------


# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
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
net.ipv4.tcp_syncookies = 1
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
net.ipv4.icmp_echo_ignore_all = 1
------------------------------

#bind arden
#sudo vi /etc/bind/named.conf.options
#Add the following to the Options section :

recursion no;
version "Not Disclosed";

#Restart BIND DNS server. Open a Terminal and enter the following :
#sudo /etc/init.d/bind9 restart

--------------------------------

#ip spoofing
#/etc/host.conf
order bind,hosts
nospoof on

--------------------------------


#fail2ban
# has moduals that will then keep track of traffic for services you set, such as ssh 
#and apache. this will look at brute force attempts and auto block abusers at thresholds 
#you set
sudo apt-get -y install fail2ban



#IP tables for go daddy VPS, limit apache ddos protection 

iptables -F
#iptables -A INPUT -p tcp -m tcp --dport 3343 -j ACCEPT
iptables -A INPUT -i eth0:0 -p tcp --dport 3343 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o eth0:0 -p tcp --sport 3343 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0:0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0:0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o eth0:0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i eth0:0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -p udp -o eth0:0 --dport 53 -j ACCEPT
iptables -A INPUT -p udp -i eth0:0 --sport 53 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# psad is a intrusion detection system built for linux distros 
sudo apt-get -y install psad
