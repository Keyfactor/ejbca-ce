#!/bin/sh

######## IPtables Firewall script for EJBCA. ######
######## Made by Thomas Karlsson 2002 #############
######## This script has taken some functions from another script made by Henrik Andreasson
# What this script does:
# It blocks ALL incoming ports except for WEBServer, SSLWebserver and SSH from ONE ip.
# It blocks ALL outgoing ports except for SMTP(25) and DNS requests to your own trusted dns servers.
######## How to install ###########################
# 1. Preferly copy this script to /etc/init.d
# 2. Make a softlink from your runleveldirectory to this script
#	cp this.script.sh /etc/init.d
#	cd /etc/rc2.d (or the preferred runlevel (in redhat its rc3.d)
#	ln -s ../init.d/this.script.sh .
# 3. Now the script will automatically be run everytime the server is rebooted
# 4. Edit the script so it matches your environment. The variables speaks for them selves
# 5. If you do not plan to reboot now, please just run this once.

######## Userchangable variables ##################
######## Add trusted sites here ###################

USE_EXTERNAL_LDAPSERVER="yes"
USE_LOCAL_LDAPSERVER="no"
TRUSTEDSSH="10.1.1.110";
EJBCAWEBSERVERPORT="8080";
EJBCASSLWEBSERVERPORT1="8442";
EJBCASSLWEBSERVERPORT2="8443";
LDAPPORT="389";
LDAPSSLPORT="636";

######## config ###############
#point to iptables binary
IPTABLES=/sbin/iptables
ROUTE=/sbin/route
IFCONFIG=/sbin/ifconfig

######## End Userchangable variables ####

logger $0 "Securing EJBCA with iptables firewall"
echo "Securing EJBCA with iptables firewall"

###################
# peers definitions  
WORLD=0.0.0.0/0
BROADCAST="255.255.255.255"

###### end config ###########


###### get ip addresses from ifconfig ####
# inside of fw (3c59x)
INET_IFACE="eth0"
INET_IP=`$IFCONFIG $INET_IFACE | awk '/inet addr/ { gsub(".*:", "", $2) ; print $2 }'`
INETNET=`$ROUTE |grep $INET_IFACE |grep -v UG |cut -f1 -d\ `

#loopback if
LO_IFACE="lo"
LO_IP=`$IFCONFIG $LO_IFACE | awk '/inet addr/ { gsub(".*:", "", $2) ; print $2 }'`
LO_NET=`$ROUTE |grep $LO_IFACE |grep -v UG |cut -f1 -d\ `

###############################

echo "INET IF: $INET_IFACE"
echo "INET IP: $INET_IP"

#####################################
echo -n "Removing old firewall rules... "
$IPTABLES -P INPUT ACCEPT
$IPTABLES -P OUTPUT ACCEPT
$IPTABLES -P FORWARD ACCEPT
$IPTABLES -F	# Flush all rules
$IPTABLES -X	# Delete all usermade chains

echo "done"

################ DEFAULT POLICES ###############################
echo -n "Setting default polices to DROP... "

$IPTABLES -P INPUT      DROP 
$IPTABLES -P FORWARD    DROP
$IPTABLES -P OUTPUT     DROP 
echo "done"

############ LOOPBACK access rules ###########################
echo -n "Setting LOOPBACK access rules... "

# local loop back interface allow all
$IPTABLES -A INPUT -i $LO_IFACE -s $LO_IP -j ACCEPT
$IPTABLES -A INPUT -i $LO_IFACE -s $INET_IP -j ACCEPT
echo "done"

############ INPUT access rules ###########################
echo -n "Setting INPUT access rules... "

$IPTABLES -A INPUT -m state --state INVALID -j DROP	# Drop evil invalid packets from the start
$IPTABLES -A INPUT -i $INET_IFACE -d $INET_IP -m state --state ESTABLISHED,RELATED	-j ACCEPT # Use the statefulfiltering capability
$IPTABLES -A INPUT -p tcp -i $INET_IFACE -s $WORLD -d $INET_IP --dport $EJBCAWEBSERVERPORT -m state --state NEW -j ACCEPT # Open webserverport
$IPTABLES -A INPUT -p tcp -i $INET_IFACE -s $WORLD -d $INET_IP --dport $EJBCASSLWEBSERVERPORT1 -m state --state NEW -j ACCEPT # Open sslwebserverport
$IPTABLES -A INPUT -p tcp -i $INET_IFACE -s $WORLD -d $INET_IP --dport $EJBCASSLWEBSERVERPORT2 -m state --state NEW -j ACCEPT # Open sslwebserverport
$IPTABLES -A INPUT -p tcp -i $INET_IFACE -s $TRUSTEDSSH -d $INET_IP --dport 22 -m state --state NEW	-j ACCEPT # Open SSH for one ip
if [ "$USE_LOCAL_LDAPSERVER" = yes ]
        then
		$IPTABLES -A INPUT -p tcp -i $INET_IFACE -d $INET_IP --dport $LDAPPORT -m state --state NEW -j ACCEPT
		$IPTABLES -A INPUT -p tcp -i $INET_IFACE -d $INET_IP --dport $LDAPSSLPORT -m state --state NEW -j ACCEPT
fi
$IPTABLES -A INPUT -j LOG --log-level info --log-prefix="FW-DROP: "	# Log every DROP
$IPTABLES -A INPUT -j DROP	# Drop them

echo "done"
############ OUTPUT access rules ##########################
echo -n "Setting OUTPUT access rules... "
 
$IPTABLES -A OUTPUT -o $INET_IFACE -m state --state ESTABLISHED	-j ACCEPT # Use the statefulfiltering capability
### Add dns servers, this loop grabs all dns server you have in your /etc/resolv.conf and allows dns traffic to them
for dnsserv in `cat /etc/resolv.conf | awk '/nameserver/ { print $2 }'` ; do $IPTABLES -A OUTPUT -p udp -o $INET_IFACE -d $dnsserv --dport 53 -m state --state NEW       -j ACCEPT ; done
### END adding local dns servers
if [ "$USE_EXTERNAL_LDAPSERVER" = yes ]
        then
		$IPTABLES -A OUTPUT -p tcp -o $INET_IFACE --dport $LDAPPORT -m state --state NEW -j ACCEPT
		$IPTABLES -A OUTPUT -p tcp -o $INET_IFACE --dport $LDAPSSLPORT -m state --state NEW -j ACCEPT

fi
$IPTABLES -A OUTPUT -j LOG --log-level info --log-prefix="FW OUT: "
$IPTABLES -A OUTPUT -j DROP

echo "done"
