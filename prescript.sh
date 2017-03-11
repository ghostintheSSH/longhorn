#this will run, and it wont be pretty, IGNORE IP talbes, they are built for Godaddy VPS - they are limiting on what you can do 


#update and remove baddies and install some  goodies
sudo apt-get update && sudo apt-get upgrade && sudo apt-get purge rpcbind samba apache2 fetchmail postfix smnp* quota && sudo apt-get -y install nmap nano


#install ufw
sudo apt-get -y install ufw

#enable ufw enable ssh
sudo ufw enable && sudo ufw allow ssh





#things to add to ssh config
#will need to echo this, possibly make a copy of current config and add this to that, then out to a new config all together
CHANGE PORT

PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
PrintLastLog no
PasswordAuthentication no
UseDNS no
ClientAliveInterval 300
ClientAliveCountMax 0
IgnoreRhosts yes
RhostsAuthentication no
RhostsRSAAuthentication no
RSAAuthentication yes
LoginGraceTime 150
AllowTcpForwarding no
X11Forwarding no
LogLevel VERBOSE
StrictModes yes




add ssh new port to IPtables
sudo iptables -A INPUT -p tcp -m tcp --dport 3343 -j ACCEPT
iptables-save > /root/my.active.firewall.rules


#secure mem
sudo vi /etc/fstab
tmpfs     /dev/shm     tmpfs     defaults,noexec,nosuid     0     0

#add user to admin, limit su to admin
sudo groupadd admin
sudo usermod -a -G admin $user
sudo dpkg-statoverride --update --add root admin 4750 /bin/su

--------------------------


## IP Spoofing protection
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
