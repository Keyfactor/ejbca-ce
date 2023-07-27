This directory contains extra scripts that are useful for some special functions.

Helper scripts are located in GitHub: https://github.com/primekeydevs/ejbcatools

Code signing:
------------
sign-verify.sh - used to sign a file. Creates a signature file, that can later be verified using the same program. 
 Uses a private key to sign and a public key to verify.
 It is actually recommended, for security reasons, that the signing and verification is done on another machine
 than the file being signed. This protects against someone gaining privileges and using a key stored on disk to 
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
