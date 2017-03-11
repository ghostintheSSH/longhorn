#iptables i would like to have

*filter

#FIXED FOR CZ CONTAINER
#  Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT


#  Accepts all established inbound connections
#-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT


#  Allows all outbound traffic
#  You can modify this to only allow certain traffic
-A OUTPUT -p tcp --dport 22 -j ACCEPT
#-A INPUT -p tcp -m state --state NEW --dport 3343 -j ACCEPT


# Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
#-A INPUT -p tcp --dport 80 -j ACCEPT
#-A INPUT -p tcp --dport 443 -j ACCEPT


#  Allows SSH connections
#
# THE -dport NUMBER IS THE SAME ONE YOU SET UP IN THE SSHD_CONFIG FILE
#
-A INPUT -p tcp -m state --state NEW --dport 3343 -j ACCEPT

#limit SSH to 5 hits in 60 seconds
#-I INPUT -p tcp --dport 22 -i eth0:0 -m state --state NEW -m recent --set
#-I INPUT -p tcp --dport 22 -i eth0:0 -m state --state NEW -m recent --update --seconds 60 --hitcount 5 -j DROP

#rate limit SSH
#-I INPUT -p tcp --dport 22 -i eth0: -m state --state NEW -m recent  --set
#-I INPUT -p tcp --dport 22 -i eth0: -m state --state NEW -m recent  --update --seconds 15 --hitcount 3 -j DROP

#block port scans
-A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j DROP
-A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j DROP

#add scanners to list and log
-A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
-A INPUT   -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

-A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
-A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j DROP

#force SYN chk
#-A INPUT -p tcp ! --syn -m state --state NEW -j DROP

#drop ping 

-A OUTPUT -p icmp -o eth0 -j ACCEPT
-A INPUT -p icmp --icmp-type echo-reply -s 0/0 -i eth0 -j ACCEPT
-A INPUT -p icmp --icmp-type destination-unreachable -s 0/0 -i eth0 -j ACCEPT
-A INPUT -p icmp --icmp-type time-exceeded -s 0/0 -i eth0 -j ACCEPT
-A INPUT -p icmp -i eth0 -j DROP


# Allow ping
#-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT


# log iptables denied calls
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7


# Reject all other inbound - default deny unless explicitly allowed policy
-A INPUT -j REJECT
-A FORWARD -j REJECT

COMMIT






#---------------------
#potential ssh port knocking, this is public so i will not have my real ssh ports here
#gnr reference for the win


-N stage1
-A stage1 -m recent --remove --name knock
-A stage1 -p tcp --dport 3456 -m recent --set --name knockknock

-N stage2
-A stage2 -m recent --remove --name knockkock
-A stage2 -p tcp --dport 2345 -m recent --set --name heavensdoor

-N door
-A door -m recent --rcheck --seconds 5 --name knockknock -j stage2
-A door -m recent --rcheck --seconds 5 --name knock -j stage1
-A door -p tcp --dport 1234 -m recent --set --name knock

-A INPUT -m --state ESTABLISHED,RELATED -j ACCEPT
-A INPUT -p tcp --dport 22 -m recent --rcheck --seconds 5 --name heavensdoor -j ACCEPT
-A INPUT -p tcp --syn -j doo
