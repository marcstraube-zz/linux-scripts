#!/bin/bash +x

# Define variables
SYSCTL=/usr/bin/sysctl
IPTABLES=/usr/bin/iptables
IPTABLES_SAVE=/usr/bin/iptables-save
IPTABLES_RULE_FILE=/etc/iptables/iptables.rules
IP_ADDR=192.168.1.70
BROADCAST=192.168.1.255
DNS_SERVERS="192.168.1.2"
SSH=22      # SSH port to connect
SSHD=22     # SSHd server port
NTP_SERVERS="0.de.pool.ntp.org 1.de.pool.ntp.org 2.de.pool.ntp.org 3.de.pool.ntp.org 0.europe.pool.ntp.org 1.europe.pool.ntp.org 2.europe.pool.ntp.org 3.europe.pool.ntp.org"
DICT_SERVERS="dict.org"


#
# Kernel Parameter Configuration
#

# Enable dynamic address hacking.
# May be useful if you have a dynamic IP address (pppoe, dhcp)
#$SYSCTL net.ipv4.ip_dynaddr="1"

# Enable TCP SYN flood protection.
# The TCP SYN cookies activation allows you system to accept an
# unlimited number of TCP connections while still trying to give
# reasonable service during a DoS attack.
$SYSCTL net.ipv4.tcp_syncookies="1"

# Enable protection against TCP time-wait assassination hazards.
# Drop RST packets for sockets in the time-wait state
# (not widely supported outside of linux, but conforms to RFC)
$SYSCTL net.ipv4.tcp_rfc1337="1"

# Enable kernel reverse path filtering.
# This will source validation of the packets recieved from all
# the interfaces on the machine. Protects from attackes that are
# using ip spoofing methods.
$SYSCTL net.ipv4.conf.all.rp_filter="1"

# Refuse source routed packets.
# Turned on as a default but generally considered as a security risk.
# This option turns it off.
$SYSCTL net.ipv4.conf.all.accept_source_route="0"

# Enable or disable ICMP redirects.
# ICMP redirects are generalle considered as a security risk.
# This option turns it off.
$SYSCTL net.ipv4.conf.all.accept_redirects="0"
$SYSCTL net.ipv4.conf.default.accept_redirects="0"

# Enable secure redirects.
# This option only accepts redirects from gateways in the default
# gateway list.
$SYSCTL net.ipv4.conf.all.secure_redirects="1"

# Log packets from impossible addresses.
$SYSCTL net.ipv4.conf.all.log_martians="1"

# TCP timestamps
# + Protect agains wrapping sequence numbers (at gigabit speeds)
# + Round trip time calculation implemented in TCP
# - Causes extra overhead and allows updatime detection by scanners like nmap
# Enable at gigabit speeds.
#$SYSCTL net.ipv4.tcp_timestamps="1"
$SYSCTL net.ipv4.tcp_timestamps="0"

# Disable sending of redirects (this is needed for a router)
$SYSCTL net.ipv4.conf.all.send_redirects="0"



#
# IPTABLES configuration
#

# Delete all existing chains and rules
$IPTABLES -F
$IPTABLES -X


# Set DROP as default policy
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT DROP


# Create chains
$IPTABLES -N COMMON
$IPTABLES -N STATE_TRACK
$IPTABLES -N BLACKLIST
$IPTABLES -N PORTSCAN
$IPTABLES -N SPOOFING
$IPTABLES -N ICMP_IN
$IPTABLES -N UDP_IN
$IPTABLES -N TCP_IN
$IPTABLES -N ICMP_OUT
$IPTABLES -N UDP_OUT
$IPTABLES -N TCP_OUT



#
# INPUT chain rules
#

# Accept all incoming traffic from loopback device
$IPTABLES -A INPUT -i lo -j ACCEPT

# Drop packets with incoming fragments due this attack result into linux server panic such as data loss
$IPTABLES -A INPUT -f -j DROP

# Send all traffic to COMMON chain
$IPTABLES -A INPUT -j COMMON

# Send all traffic to PORTSCAN chain
$IPTABLES -A INPUT -j PORTSCAN

# Send all traffic to SPOOFING chain
$IPTABLES -A INPUT -j SPOOFING

# Send all ICMP traffic to ICMP_IN chain
$IPTABLES -A INPUT -p icmp -j ICMP_IN

# Send all UDP traffic to UDP_IN chain
$IPTABLES -A INPUT -p udp -j UDP_IN

# Send all TCP traffic to TCP_IN chain
$IPTABLES -A INPUT -p tcp -j TCP_IN

# All other packets will be logged and rejected
$IPTABLES -A INPUT -m limit --limit 2/min -j LOG --log-prefix "iptables INPUT rejected: " --log-level 7
$IPTABLES -A INPUT -j REJECT --reject-with icmp-proto-unreachable



#
# OUTPUT chain rules
#

# Accept all outgoing traffic from loopback device
$IPTABLES -A OUTPUT -o lo -j ACCEPT

# Send all traffic to COMMON chain
$IPTABLES -A OUTPUT -j COMMON

# Send all ICMP traffic to ICMP_OUT chain
$IPTABLES -A OUTPUT -p icmp -j ICMP_OUT

# Send all UDP traffic to UPD_OUT chain
$IPTABLES -A OUTPUT -p udp -j UDP_OUT 

# Send all TCP traffic to TCP_OUT chain
$IPTABLES -A OUTPUT -p tcp -j TCP_OUT

# All other packets will be logged and rejected
$IPTABLES -A OUTPUT -m limit --limit 2/min -j LOG --log-prefix "iptables OUTPUT rejected: " --log-level 7



#
# COMMON chain rules
#

# Send all traffic to STATE_TRACK chain
$IPTABLES -A COMMON -j STATE_TRACK

# Send all traffic to BLACKLIST chain
$IPTABLES -A COMMON -j BLACKLIST

# Return to parent chain
$IPTABLES -A COMMON -j RETURN


#
# STATE_TRACK chain rules
#

# Allow all established and related traffic
$IPTABLES -A STATE_TRACK -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Drop all invalid packets
$IPTABLES -A STATE_TRACK -m conntrack --ctstate INVALID -j DROP

# All packets with state NEW returns to parent chain
$IPTABLES -A STATE_TRACK -j RETURN



#
# BLACKLIST chain rules
#

# For example, blacklist an IP address
# $IPTABLES -A BLACKLIST -d 202.0.113.45 -j DROP

# Return to parent chain
$IPTABLES -A BLACKLIST -j RETURN



#
# PORTSCAN chain rules
#

# Drop common portscan attacks
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ACK,URG URG -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$IPTABLES -A PORTSCAN -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Return to parent chain
$IPTABLES -A PORTSCAN -j RETURN 



#
# SPOOFING chain rules
#

# Drop packets claiming to be the loopback interface (protects against source quench)
$IPTABLES -A SPOOFING ! -i lo -d 127.0.0.0/8 -j DROP

# Drop spoofed packets pretending to be from your IP address
$IPTABLES -A SPOOFING ! -i lo -s $IP_ADDR -j DROP

# Drop "Class D" multicast addresses. Multicast is illegal as a source address.
$IPTABLES -A SPOOFING -s 224.0.0.0/4 -j DROP

# Refuse "Class E" reserved IP addresses
$IPTABLES -A SPOOFING -s 240.0.0.0/5 -j DROP

# Drop broadcast address packets
$IPTABLES -A SPOOFING ! -i lo -d $BROADCAST -j DROP

# Return to parent chain
$IPTABLES -A SPOOFING -j RETURN



#
# ICMP_IN chain rules
#

# Allow ICMP echo requests (ping) and limit to 1 per second.
$IPTABLES -A ICMP_IN -p icmp --icmp-type 8 -m limit --limit 1/s --limit-burst 10 -j ACCEPT

# Log and reject other ICMP packets with ICMP protocol unreachable (Linux default behaviour)
$IPTABLES -A ICMP_IN -p icmp -m limit --limit 2/min -j LOG --log-prefix "iptables ICMP_IN rejected: " --log-level 7
$IPTABLES -A ICMP_IN -j REJECT --reject-with icmp-proto-unreachable



#
# UDP_IN chain rules
#

# Log and reject other UDP packets with ICMP port unreachable (RFC compliant default behaviour for Linux)
$IPTABLES -A UDP_IN -m limit --limit 2/min -j LOG --log-prefix "iptables UDP_IN rejected: " --log-level 7
$IPTABLES -A UDP_IN -j REJECT --reject-with icmp-port-unreachable



#
# TCP_IN chain rules
#

# Since new TCP connections must be started with a SYN package, drop all other
$IPTABLES -A TCP_IN -p tcp ! --syn -j DROP

# Allow incoming SSH with only 4 connection tries per 60 seconds to prevend dictionary attacks (can slow down SCP)
$IPTABLES -A TCP_IN -p tcp --dport $SSHD -m recent --set --name ssh --rsource
$IPTABLES -A TCP_IN -p tcp --dport $SSHD -m recent ! --rcheck --seconds 60 --hitcount 4 --name ssh --rsource -j ACCEPT

# Allow incoming HTTP and HTTPS and prevend from DoS attack (for small web servers)
$IPTABLES -A TCP_IN -p tcp -m multiport --dports 80,443 -m limit --limit 512/min --limit-burst 512 -j ACCEPT

# Allow incoming SMTP, SMTPS, Submission, POP3, POP3S, IMAP, IMAPS and SIEVE
$IPTABLES -A TCP_IN -p tcp -m multiport --dports 25,465,587,110,995,143,993,4190 -j ACCEPT

# Log all other incoming traffic and reject it with TCP-RST package (Linux default behaviour) 
$IPTABLES -A TCP_IN -p tcp -m limit --limit 2/min -j LOG --log-prefix "iptables TCP_IN rejected: " --log-level 7
$IPTABLES -A TCP_IN -p tcp -j REJECT --reject-with tcp-rst



#
# ICMP_OUT chain rules
#

# Allow outgoing ICMP echo request (ping)
$IPTABLES -A ICMP_OUT -p icmp --icmp-type 8 -j ACCEPT

# Log and drop all other packets
$IPTABLES -A ICMP_OUT -m limit --limit 2/min -j LOG --log-prefix "iptables ICMP_OUT dropped: " --log-level 7
$IPTABLES -A ICMP_OUT -j DROP



#
# UDP_OUT chain rules
#

# Allow outgoing DNS
for DNS in $DNS_SERVERS; do
    $IPTABLES -A UDP_OUT -p udp -d $DNS --sport 1024:65535 --dport 53 -j ACCEPT
done

# Allow outgoing NTP
for NTP in $NTP_SERVERS; do
    $IPTABLES -A UDP_OUT -p udp -d $NTP --dport 123 -j ACCEPT
done

# Allow outgoing traceroute
$IPTABLES -A UDP_OUT -p udp --sport 32769:65535 --dport 33434:33523 -j ACCEPT

# Log and drop all other packets
$IPTABLES -A UDP_OUT -m limit --limit 2/min -j LOG --log-prefix "iptables UDP_OUT dropped: " --log-level 7
$IPTABLES -A UDP_OUT -j DROP



#
# TCP_OUT chain rules
#

# Allow outgoing HTTP and HTTPS
$IPTABLES -A TCP_OUT -p tcp -m multiport --dports 80,443 -j ACCEPT

# Allow outgoing SMTP, SMTPS, Submission, POP3, POP3S, IMAP, IMAPS and SIEVE
$IPTABLES -A TCP_OUT -p tcp -m multiport --dports 25,465,587,110,995,143,993,4190 -j ACCEPT

# Allow outgoing SSH
$IPTABLES -A TCP_OUT -p tcp --dport $SSH -j ACCEPT

# Allow outgoing FTP
$IPTABLES -A TCP_OUT -p tcp --sport 1024:65535 -m multiport --dports 20,21 -j ACCEPT

# Allow outgoing rsync (needed for ABS)
$IPTABLES -A TCP_OUT -p tcp --dport 837 -j ACCEPT

# Allow outgoing Git
$IPTABLES -A TCP_OUT -p tcp --dport 9418 -j ACCEPT

# Allow outgoing XMPP
$IPTABLES -A TCP_OUT -p tcp --dport 5222 -j ACCEPT

# Allow outgoing HKP Key Exchange Protocol
$IPTABLES -A TCP_OUT -p tcp --dport 11371 -j ACCEPT

# Allow outgoing telnet
$IPTABLES -A TCP_OUT -p tcp --dport 23 -j ACCEPT

# Allow outgoing DICT
for DICT in $DICT_SERVERS; do
    $IPTABLES -A TCP_OUT -p tcp -d $DICT --dport 2628 -j ACCEPT
done

# Log and drop all other packets
$IPTABLES -A TCP_OUT -m limit --limit 2/min -j LOG --log-prefix "iptables TCP_OUT dropped: " --log-level 7
$IPTABLES -A TCP_OUT -j DROP


# Save the current ruleset
$IPTABLES_SAVE >> $IPTABLES_RULE_FILE
