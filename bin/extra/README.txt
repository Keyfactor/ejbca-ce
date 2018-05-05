This directory contains extra scripts that are useful for some special functions.

CMP Monitoring
--------------
check_cmpv2 is a Python script for Nagios monitoring of the CMP server. 
It was contributed by Fabien Hochstrasser and is provided "as is".

For monitoring it sends a real CMP message, certConf, which does not perform any actual operation on the server
and parses the response to see that the CMP server is actually up and responding to requests.

Code signing:
------------
sign-verify.sh - used to sign a file. Creates a signature file, that can later be verified using the same program. 
 Uses a private key to sign and a public key to verify.
 It is actually recommended, for security reasons, that the signing and verification is done on another machine
 than the file being signed. This protects againsy someone gaining privileges and using a key stored on disk to 
 sign a bad version of the file.
 
 Create a new user 'Batch' in EJBCA, check 'Batch' processing and choose P12 keystore.
 When the p12 has been created you can convert it to openssl format with the following commands.
 (in these commands the created user was called signer, so the p12 file is called signer.p12)

 Openssl command to convert a p12 file to cert and key files in pem
 First cert:
 openssl pkcs12 -in signer.p12 -nodes -nokeys -clcerts -out signer.pem
 Then public key
 openssl x509 -in signer.pem -pubkey -noout > signer.pub
 Then private key:
 openssl pkcs12 -in signer.p12 -nodes -nocerts -out signer.priv
 
 Now you can call the script to sign with:
 sign-verify.sh sign signer.priv <path to file to sign> <path to signature>"
 and verify with:
 sign-verify.sh verify signer.pub <path to file to sign> <path to signature>"
 
 cronverify.sh - a small script that you can call from cron to log (to syslog) when a signed file has been modified, 
  or remove the modified file. Configure paths and options in the file.
  Drop a file containing the following into /etc/cron.d to have verification every minute.
  -----
  SHELL=/bin/sh
  PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

  * * * * *   root        /usr/local/ejbca/bin/extra/cronverify.sh  >/dev/null
  -----

  
csv_to_endentity.sh
-------------------

This is a small utility script that can be used for creating end entities in
EJBCA using a CSV file. Help about script can be obtained by running it without
parameters, or with -h.

Information taken from CSV includes end entity name, CN, and IP address. The IP
address is put into ipaddress subjectAltName. A couple of changes that should be
made prior to running the script should usually include:

- Changing the default values that are passed to bin/ejbca.sh ra addendentity command
  (look for the "Set-up default values for adding the end entity." line).
- If the CSV contains different information that outlined above, the script will
  required some tweaking of CSV line validation, fields read from CSV, and
  arguments passed to bin/ejbca.sh commmand.
