#!/bin/bash

DIR=/usr/local/tmp/

# this script is used by EJBCA_3_1_3 to create OpenVPN windows
# installer programs using the nsis package for linux.
# Contributed by Jon Bendtsen.

# EJBCA expects this program to be at
# /usr/local/ejbca/openvpn/mk_openvpn_windows_installer.sh
# EJBCA leaves a PKCS12 file in /usr/local/tmp, and expects
# the openvpn windows installer program at the same location
# with a particular name
# /usr/local/tmp/openvpn-gui-install-$USERNAME.exe


# The user name, IssuerDN and SubjectDN are written from EJBCA
# to stdout which is connected to the stdin of this script.
read username
read IssuerDN
read SubjectDN


# This script can use the username, IssuerDN and/or SubjectDN
# to give the user a particular OpenVPN configuration file.
#
# username is unique - username is NOT the Common Name
# IssuerDN is the Distinguised Name of the CA's cert
# SubjectDN is the Distinguised Name of this user's cert
#
# username might look like "jens" 
# IssuerDN might look like "CN=ManagementCA,O=Example,C=Com"
# SubjectDN might look like "CN=Jens Hansen,O=Example,OU=Sales,C=Com"
# you could use the O or OU from a DN to specify the needed
# openvpn configuration
#
# But _YOU_ are expected to make the needed changes to this script
# if you dont, you will just get the default called client.conf 
# from /usr/local/ejbca/openvpn/default-client.ovpn
# if the file does not exist, the openvpn-gui-install-$USERNAME.exe
# will not be made
cfg=default-client.ovpn
org=work
zipfile=openvpn_install_source-2.0.5-gui-1.0.3.zip
#openvpn_install_source-2.0.5-gui-1.0.3.zip
#openvpn_install_source-2.1beta7-gui-1.0.3.zip


move_files() {
	# this function moves the configuration and certificate
	# to the right place in the tree in $DIR/$username
	#
	# this function also changes the configuration file
	# to use this users certificate, and to the name of
	# the organisation which is usually extracted from
	# the SubjectDN, if no organisation is extracted
	# the default named work is used.
	# 
	# before that the tree under $DIR/$username is
	# extracted from a zipfile. The zipfile is either the
	# default openvpn_install_source-2.0.5-gui-1.0.3.zip
	# or extracted from the username, IssuerDN and/or SubjectDN
	# this lets you run with different OpenVPN versions.
	olddir=$PWD
	cd $DIR/$username
	unzip -q /usr/local/ejbca/openvpn/$zipfile

	# now we move the certificate to the right location
	# EJBCA saves the certificate as $username.p12
	mv ../$username.p12 openvpn/config/

	# now we take the configuration file, and make it use
	# the certificate of this particular user
	cat /usr/local/ejbca/openvpn/$cfg | sed -e "s/_-USER-_/$username/g"\
		> openvpn/config/$org.ovpn

	cd $olddir
}

run_nsis() {
	# now that the PKCS12 certificate and the configuration file
	# is in place, we call the nsis program to actually make the
	# /usr/local/tmp/openvpn-gui-install-$USERNAME.exe

	olddir=$PWD
	cd $DIR/$username

	# first we make changes to the nsis configuration file to
	# include the configuration and certificate during install
	# and when the program is removed
	cat openvpn-gui.nsi | sed -e "s/_-USER-_/$username/g" | \
	    sed -e "s/_-ORGANISATION-_/$org/g" > $username.nsi

	# now we run makensis to create the openvpn windows installer
	makensis $username.nsi >> /dev/null

	# move the openvpn windows installer to /usr/local/tmp
	mv *.exe /usr/local/tmp/openvpn-gui-install-$username.exe
	
	cd $olddir
}


# so we have a place to store our files while we make the nsis
# openvpn windows installer program
mkdir -p $DIR/$username

# First we run a check for the setup for this IssuerDN
# Second we run a check for the setup for this SubjectDN without this user's CN
# Third we run a check for the setup for this username

case "$IssuerDN" in
	CN=ManagementCA,O=Example,C=com)
		cfg=employee-client.conf
		org=work
		zipfile=openvpn_install_source-2.1beta7-gui-1.0.3.zip
		;;
	"CN=PartnerCA1,O=Partners of Example,C=Example")
		cfg=partner-vpn-client.conf
		org=example
		zipfile=openvpn_install_source-2.1beta7-gui-1.0.3.zip
		;;
#	*)
#		# * means the default
#		cfg="default-client.conf"
#		;;
esac

# since the SubjectDN includes the users Common Name you will most
# likely have to extract the O (Organisation) and/or OU (Organisational
# Unit) from the SubjectDN
newSubjectDN=$(echo "$SubjectDN" | cut -d"," -f2-)

case "$newSubjectDN" in
	O=Example,OU=Sales,C=Com)
		cfg="Example.Sales.com-client.conf"
		org=ExampleSales
		;;
#	*)
#		# * means the default
#		cfg="default-client.conf"
#		;;
esac

# uncomment if you need to check for special users
# you can also let the OpenVPN server give some users a special
# configuration for some things, but stuff like the address
# of the openvpn server can not be set from the server, only
# in the configuration file on the client.
#case "$username" in
#	john)
#		cfg=john-special-openvpn.conf
#		;;
#
#	*)
#		# * means the default
#		cfg="default-client.conf"
#		;;
#esac

move_files
run_nsis

# cleanup time
rm -rf /usr/local/tmp/$username
rm -rf /usr/local/tmp/$username.p12
rmdir $DIR/$username
