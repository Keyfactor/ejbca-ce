package se.anatom.ejbca.admin;

import java.io.*;
import java.util.*;
import java.lang.Integer;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.*;
import java.security.Provider;
import java.security.Security;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;
import javax.ejb.CreateException;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;

import se.anatom.ejbca.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSession;
import se.anatom.ejbca.ca.store.IPublisherSessionHome;
import se.anatom.ejbca.ca.store.IPublisherSession;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSession;

import org.apache.log4j.*;

public class ca {

    private static Category cat = Category.getInstance( ca.class.getName() );
    
    /** Pointer to main certificate store */
    private static ICertificateStoreSession certificateStore = null;
    /** A vector of publishers where certs and CRLs are stored */
    private static Vector publishers = null;
    /** Private key alias in PKCS12 keystores */
    private static String privKeyAlias = "privateKey";
    private static char[] privateKeyPass = null;
    
    public static void main(String [] args){
        if (args.length < 1) {
            System.out.println("Usage: CA info | makeroot | getrootcert | makereq | recrep | processreq | init | createcrl | getcrl | rolloverroot | rolloversub | listexpired");
            return;
        }
        try {
            org.apache.log4j.PropertyConfigurator.configure();
            // Install BouncyCastle provider
            Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
            int result = Security.addProvider(BCJce);

            if (args[0].equals("makeroot")) {
                // Generates keys and creates a keystore (PKCS12) to be used by the CA
                if (args.length < 6) {
                    System.out.println("Usage: CA makeroot <DN> <keysize> <validity-days> <filename> <storepassword>");
                    return;
                }
                String dn = args[1];
                int keysize = Integer.parseInt(args[2]);
                int validity = Integer.parseInt(args[3]);
                String filename = args[4];
                String storepwd = args[5];

                System.out.println("Generating rootCA keystore:");
                System.out.println("DN: "+dn);
                System.out.println("Keysize: "+keysize);
                System.out.println("Validity (days): "+validity);
                System.out.println("Storing in: "+filename);
                System.out.println("Protected with storepassword: "+storepwd);

                // Generate keys
                System.out.println("Generating keys, please wait...");
                KeyPair rsaKeys = KeyTools.genKeys(keysize);
                X509Certificate rootcert = CertTools.genSelfCert(dn, validity, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);
                KeyStore ks = KeyTools.createP12(privKeyAlias, rsaKeys.getPrivate(), rootcert, (X509Certificate)null);

                FileOutputStream os = new FileOutputStream(filename);
                System.out.println("Storing keystore '"+filename+"'.");
                ks.store(os, storepwd.toCharArray());
                System.out.println("Keystore "+filename+" generated succefully.");
            } else if (args[0].equals("getrootcert")) {
                // Export root CA certificate
                if (args.length < 2) {
                    System.out.println("Save root CA certificate to file.");
                    System.out.println("Usage: CA rootcert <filename>");
                    return;
                }
                String filename = args[1];
                Certificate[] chain = getCertChain();
                X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
                FileOutputStream fos = new FileOutputStream(filename);
                fos.write(rootcert.getEncoded());
                fos.close();
                System.out.println("Wrote Root CA certificate to '"+filename+"'");
            } else if (args[0].equals("listexpired")) {
                // List certificates that will expire within the given number of days
                if (args.length < 2) {
                    System.out.println("List certificates that will expire within the given number of days.");
                    System.out.println("Usage: CA listexpired <days>");
                    return;
                }
                long days = Long.parseLong(args[1]);
                Date findDate = new Date();
                long millis = (days * 24 * 60 * 60 * 1000);
                findDate.setTime(findDate.getTime() + (long)millis);
                System.out.println("Looking for certificates that expire before "+findDate+".");
                Certificate[] certs = getExpiredCerts(findDate);
                for (int i=0;i<certs.length;i++) {
                    X509Certificate xcert = (X509Certificate)certs[i];
                    Date retDate = xcert.getNotAfter();
                    String subjectDN= xcert.getSubjectDN().toString();
                    String serNo = xcert.getSerialNumber().toString();
                    System.out.println("Certificate with subjectDN '"+subjectDN+"' and serialNumber '"+serNo+"' expires at "+retDate+".");
                }
            } else if (args[0].equals("info")) {
                Certificate[] chain = getCertChain();
                if (chain.length < 2)
                    System.out.println("This is a Root CA.");
                else
                    System.out.println("This is a subordinate CA.");
                X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
                System.out.println("Root CA DN: "+rootcert.getSubjectDN().toString());
                System.out.println("Certificate valid from: "+rootcert.getNotBefore().toString());
                System.out.println("Certificate valid to: "+rootcert.getNotAfter().toString());
                System.out.println("Root CA keysize: "+((RSAPublicKey)rootcert.getPublicKey()).getModulus().bitLength());
                if (chain.length > 1) {
                    X509Certificate cacert = (X509Certificate)chain[chain.length-2];
                    System.out.println("CA DN: "+cacert.getSubjectDN().toString());
                    System.out.println("Certificate valid from: "+cacert.getNotBefore().toString());
                    System.out.println("Certificate valid to: "+cacert.getNotAfter().toString());
                    System.out.println("CA keysize: "+((RSAPublicKey)cacert.getPublicKey()).getModulus().bitLength());
                }
            } else if (args[0].equals("makereq")) {
                // Generates keys and creates a keystore (PKCS12) to be used by the CA
                if (args.length < 7) {
                    System.out.println("Usage: CA makereq <DN> <keysize> <rootca-certificate> <request-file> <keystore-file> <storepassword>");
                    System.out.println("Generates a certification request for a subCA for sending to a RootCA.");
                    return;
                }
                String dn = args[1];
                int keysize = Integer.parseInt(args[2]);
                String rootfile = args[3];
                String reqfile = args[4];
                String ksfile = args[5];
                String storepwd = args[6];

                System.out.println("Generating cert request (and keystore):");
                System.out.println("DN: "+dn);
                System.out.println("Keysize: "+keysize);
                System.out.println("RootCA cert file: "+rootfile);
                System.out.println("Storing CertificationRequest in: "+reqfile);
                System.out.println("Storing KeyStore in: "+ksfile);
                System.out.println("Protected with storepassword: "+storepwd);

                // Read in RootCA certificate
                X509Certificate rootcert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer(rootfile));

                // Generate keys
                System.out.println("Generating keys, please wait...");
                KeyPair rsaKeys = KeyTools.genKeys(keysize);
                // Create selfsigned cert...
                X509Certificate selfcert = CertTools.genSelfCert(dn, 365, rsaKeys.getPrivate(), rsaKeys.getPublic(), true);

                // Create certificate request
                makeCertRequest(dn, rsaKeys, reqfile);

                // Create keyStore
                KeyStore ks = KeyTools.createP12("privateKey", rsaKeys.getPrivate(), selfcert, rootcert);

                FileOutputStream os = new FileOutputStream(ksfile);
                ks.store(os, storepwd.toCharArray());
                System.out.println("Keystore '"+ksfile+"' generated succefully.");
            } else if (args[0].equals("recrep")) {
                // Receive certificate reply as result of certificate request
                if (args.length < 4) {
                    System.out.println("Usage: CA recrep <certificate-file> <keystore-file> <storepassword>");
                    System.out.println("Used to receive certificates which has been produced as result of sending a certificate request to a RootCA.");
                    return;
                }
                String certfile = args[1];
                String ksfile = args[2];
                String storepwd= args[3];

                System.out.println("Receiving cert reply:");
                System.out.println("Cert reply file: "+certfile);
                System.out.println("Storing KeyStore in: "+ksfile);
                System.out.println("Protected with storepassword: "+storepwd);

                X509Certificate cert = CertTools.getCertfromByteArray(FileTools.readFiletoBuffer(certfile));
                X509Certificate rootcert = null;
                KeyStore store = KeyStore.getInstance("PKCS12", "BC");
                FileInputStream fis = new FileInputStream(ksfile);
                store.load(fis, storepwd.toCharArray());
                Certificate[] certchain = store.getCertificateChain("privateKey");
                System.out.println("Loaded certificate chain with length "+ certchain.length+" with alias 'privateKey'.");
                if (certchain.length > 1) {
                    // We have whole chain at once
                    if (!CertTools.isSelfSigned((X509Certificate)certchain[1])) {
                        System.out.println("Last certificate in chain with alias 'privateKey' in keystore '"+ksfile +"' is not root certificate (selfsigned)");
                        return;
                    }
                    if (certchain.length > 2) {
                        System.out.println("Certificate chain length is larger than 2, only 2 is supported.");
                        return;

                    }
                    rootcert = (X509Certificate)certchain[1];
                } else {
                    String ialias = CertTools.getPartFromDN(cert.getIssuerDN().toString(), "CN");
                    Certificate[] chain1 = store.getCertificateChain(ialias);
                    System.out.println("Loaded certificate chain with length "+ chain1.length+" with alias '"+ialias+"'.");
                    if (chain1.length == 0) {
                        System.out.println("No CA-certificate found!");
                        return;
                    }
                    if (!CertTools.isSelfSigned((X509Certificate)chain1[0])) {
                        System.out.println("Certificate in chain with alias '"+ialias+"' in keystore '"+ksfile +"' is not root certificate (selfsigned)");
                        return;
                    }
                    rootcert = (X509Certificate)chain1[0];
                }
                PrivateKey privKey = (PrivateKey)store.getKey("privateKey", null);
                // check if the private and public keys match
                Signature sign = Signature.getInstance("SHA1WithRSA");
                sign.initSign(privKey);
                sign.update("foooooooooooooooo".getBytes());
                byte[] signature = sign.sign();
                sign.initVerify(cert.getPublicKey());
                sign.update("foooooooooooooooo".getBytes());
                if (sign.verify(signature) == false) {
                    System.out.println("Public key in received certificate does not match private key.");
                    return;
                }

                // Create new keyStore
                KeyStore ks = KeyTools.createP12("privateKey", privKey, cert, rootcert);
                FileOutputStream os = new FileOutputStream(ksfile);
                ks.store(os, storepwd.toCharArray());
                System.out.println("Keystore '"+ksfile+"' generated succefully.");
            } else if (args[0].equals("processreq")) {
                // Receive certification request and create certificate to send back
                if (args.length < 5) {
                    System.out.println("Usage: CA processreq <username> <password> <request-file> <outfile>");
                    System.out.println("Used to receive certificate requests from subCAs and generate certificates to be sent back.");
                    return;
                }
                String username = args[1];
                String password = args[2];
                String reqfile = args[3];
                String outfile = args[4];

                System.out.println("Processing cert request:");
                System.out.println("Username: "+username);
                System.out.println("Password: "+password);
                System.out.println("Request file: "+reqfile);
                byte[] b64Encoded = FileTools.readFiletoBuffer(reqfile);
                byte[] buffer;
                try {
                    String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
                    String endKey = "-----END CERTIFICATE REQUEST-----";
                    buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
                } catch (IOException e) {
                    String beginKey = "-----BEGIN NEW CERTIFICATE REQUEST-----";
                    String endKey = "-----END NEW CERTIFICATE REQUEST-----";
                    buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);
                }

                Context ctx = getInitialContext();
                ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
                ISignSession ss = home.create();
                X509Certificate cert = (X509Certificate) ss.createCertificate(username, password, buffer);
                FileOutputStream fos = new FileOutputStream(outfile);
                fos.write("-----BEGIN CERTIFICATE-----\n".getBytes());
                fos.write(Base64.encode(cert.getEncoded()));
                fos.write("\n-----END CERTIFICATE-----\n".getBytes());
                fos.close();
                System.out.println("Wrote certificate to file " + outfile);
            } else if (args[0].equals("createcrl")) {
                // No arguments to creatcrl
                createCRL();
            } else if (args[0].equals("getcrl")) {
                if (args.length < 2) {
                    System.out.println("Usage: CA getcrl <outfile>");
                    return;
                }
                String outfile = args[1];
                Context context = getInitialContext();
                ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
                ICertificateStoreSession store = storehome.create();
                byte[] crl = store.getLastCRL();
                FileOutputStream fos = new FileOutputStream(outfile);
                fos.write(crl);
                fos.close();
                System.out.println("Wrote latest CR to " + outfile+ ".");
            } else if (args[0].equals("init")) {
                // No arguments to init
                System.out.println("Initializing CA");
                // First get and publish CA certificates
                Context context = getInitialContext();
                ISignSessionHome signhome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("RSASignSession"), ISignSessionHome.class);
                ISignSession sign = signhome.create();
                Certificate[] certs = sign.getCertificateChain();
                initCertificateStore();
                for (int j=0;j<certs.length;j++) {
                    X509Certificate cert = (X509Certificate)certs[j];
                    String cafingerprint = null;
                    int type = SecConst.USER_CA;
                    if ( (!CertTools.isSelfSigned(cert)) && ((j+1) < certs.length) )
                        cafingerprint = CertTools.getFingerprintAsString((X509Certificate)certs[j+1]);
                    else {
                        cafingerprint = CertTools.getFingerprintAsString(cert);
                        type = SecConst.USER_ROOTCA;
                    }
                    try {
                        // We will get an exception if the entity already exist
                        certificateStore.storeCertificate(cert, cafingerprint, CertificateData.CERT_ACTIVE, type);
                    } catch (java.rmi.ServerException e) {
                        System.out.println("Certificate for subject '"+cert.getSubjectDN()+"' already exist in the certificate store.");
                    }
                    // Call authentication session and tell that we are finished with this user
                    for (int i=0;i<publishers.size();i++) {
                        ((IPublisherSession)(publishers.get(i))).storeCertificate(cert, cafingerprint, CertificateData.CERT_ACTIVE, type);
                    }
                    System.out.println("-Stored CA certificates in certificate store(s).");
                }
                // Second create (and publish) CRL
                createCRL();
                System.out.println("-Created and published initial CRL.");
                System.out.println("CA initialized");
            } else if (args[0].equals("rolloverroot")) {
                // Creates a new root certificate with new validity, using the same key
                if (args.length < 4) {
                    System.out.println("Usage: CA rolloverroot <validity-days> <keystore filename> <storepassword>");
                    System.out.println("Rolloverroot is used to generate a new RootCA certificate using an existing keypair. This updates the current RootCA keystore.");
                    return;
                }
                int validity = Integer.parseInt(args[1]);
                String filename = args[2];
                String storepwd = args[3];
                // Get old root certificate
                Certificate[] chain = getCertChain();
                if (chain.length > 2) {
                    System.out.println("Certificate chain too long, this P12 was not generated with EJBCA?");
                    return;
                }
                X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
                if (!CertTools.isSelfSigned(rootcert)) {
                    System.out.println("Root certificate is not self signed???");
                    return;
                }
                X509Certificate cacert = null;
                if (chain.length > 1)
                    cacert = (X509Certificate)chain[chain.length-2];
                // Get private key
                KeyStore keyStore=KeyStore.getInstance("PKCS12", "BC");
                InputStream is = new FileInputStream(filename);
                keyStore.load(is, storepwd.toCharArray());
                PrivateKey privateKey = (PrivateKey)keyStore.getKey(privKeyAlias, privateKeyPass);
                if (privateKey == null) {
                    System.out.println("No private key with alias '"+privKeyAlias+"' in keystore, this keystore was not generated with EJBCA?");
                    return;
                }                
                // Generate the new root certificate
                X509Certificate newrootcert = CertTools.genSelfCert(rootcert.getSubjectDN().toString(), validity, privateKey, rootcert.getPublicKey(), true);
                // verify that the old and new keyidentifieras are the same
                String oldKeyId = Hex.encode(CertTools.getAuthorityKeyId(rootcert));
                String newKeyId = Hex.encode(CertTools.getAuthorityKeyId(newrootcert));
                System.out.println("Old key id: "+oldKeyId);
                System.out.println("New key id: "+newKeyId);
                if (oldKeyId.compareTo(newKeyId) != 0) {
                    System.out.println("Old key identifier and new key identifieras does not match, have the key pair changed?");
                    System.out.println("Unable to rollover Root CA.");
                    return;
                }
                // Create the new PKCS12 file
                KeyStore ks = KeyTools.createP12(privKeyAlias, privateKey, newrootcert, cacert);
                FileOutputStream os = new FileOutputStream(filename);
                ks.store(os, storepwd.toCharArray());
                System.out.println("Keystore "+filename+" generated succefully.");
                System.out.println("Please restart application server and run 'ca init'.");
            } else if (args[0].equals("rolloversub")) {
                // Creates a new root certificate with new validity, using the same key
                if (args.length < 4) {
                    System.out.println("Usage: CA rolloversub <validity-days> <keystore filename> <storepassword> <certrequest filename>");
                    System.out.println("Rolloversub is used to generate a new subCA certificate using an existing keypair. This updates the current subCA keystore.");
                    return;
                }
                int validity = Integer.parseInt(args[1]);
                String ksfilename = args[2];
                String storepwd = args[3];
                String reqfile = args[4];
                // Load keystore
                KeyStore keyStore=KeyStore.getInstance("PKCS12", "BC");
                InputStream is = new FileInputStream(ksfilename);
                keyStore.load(is, storepwd.toCharArray());
                // Get old certificate chain
                Certificate[] chain = KeyTools.getCertChain(keyStore,privKeyAlias);
                if (chain.length > 2) {
                    System.out.println("Certificate chain too long, this keystore was not generated with EJBCA?");
                    return;
                }
                X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
                if (!CertTools.isSelfSigned(rootcert)) {
                    System.out.println("Root certificate is not self signed???");
                    return;
                }
                X509Certificate cacert = null;
                if (chain.length > 1)
                    cacert = (X509Certificate)chain[0];
                if (cacert == null) {
                    System.out.println("No subCA certificate found in keystore, this is not a subCA or keystore was not generated with EJBCA?");
                    return;
                }                 
                System.out.println("Generating new certificate request for CA with DN='"+cacert.getSubjectDN().toString()+"'.");
                // Get private key
                PrivateKey privateKey = (PrivateKey)keyStore.getKey(privKeyAlias, privateKeyPass);
                if (privateKey == null) {
                    System.out.println("No private key with alias '"+privKeyAlias+"' in keystore, this keystore was not generated with EJBCA?");
                    return;
                }                
                // Make a KeyPair
                KeyPair keyPair = new KeyPair(cacert.getPublicKey(), privateKey);
                // verify that the old and new keyidentifieras are the same
                X509Certificate newselfcert = CertTools.genSelfCert(cacert.getSubjectDN().toString(), validity, privateKey, cacert.getPublicKey(), true);
                String oldKeyId = Hex.encode(CertTools.getSubjectKeyId(cacert));
                String newKeyId = Hex.encode(CertTools.getSubjectKeyId(newselfcert));
                System.out.println("Old key id: "+oldKeyId);
                System.out.println("New key id: "+newKeyId);
                if (oldKeyId.compareTo(newKeyId) != 0) {
                    System.out.println("Old key identifier and new key identifieras does not match, have the key pair changed?");
                    System.out.println("Unable to rollover subCA.");
                    return;
                }
                // Generate the new certificate request
                makeCertRequest(cacert.getSubjectDN().toString(), keyPair, reqfile);
                
                System.out.println("Submit certificare request to RootCA and when receiving reply run 'ca recrep'.");
            } else {
                System.out.println("Usage: CA info | makeroot | getrootcert | makereq | recrep | processreq | init | createcrl | getcrl | rolloverroot | rolloversub | listexpire");
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());
            //e.printStackTrace();
        }
    }
 
    static private void makeCertRequest(String dn, KeyPair rsaKeys, String reqfile) throws NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {
        cat.debug(">makeCertRequest: dn='"+dn+"', reqfile='"+reqfile+"'.");
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(
        "SHA1WithRSA", CertTools.stringToBcX509Name(dn), rsaKeys.getPublic(), null, rsaKeys.getPrivate());
        /* We don't use these uneccesary attributes
        DERConstructedSequence kName = new DERConstructedSequence();
        DERConstructedSet  kSeq = new DERConstructedSet();
        kName.addObject(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
        kSeq.addObject(new DERIA5String("foo@bar.se"));
        kName.addObject(kSeq);
        req.setAttributes(kName);
         */
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DERInputStream dIn = new DERInputStream(bIn);
        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest((DERConstructedSequence)dIn.readObject());
        boolean verify = req2.verify();
        System.out.println("Verify returned " + verify);
        if (verify == false) {
            System.out.println("Aborting!");
            return;
        }
        FileOutputStream os1 = new FileOutputStream(reqfile);
        os1.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
        os1.write(Base64.encode(bOut.toByteArray()));
        os1.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
        os1.close();
        System.out.println("CertificationRequest '"+reqfile+"' generated succefully.");
        cat.debug("<makeCertRequest: dn='"+dn+"', reqfile='"+reqfile+"'.");
    } // makeCertRequest
    
    static private void createCRL() throws NamingException, CreateException, RemoteException {
        Context context = getInitialContext();
        IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( context.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
        home.create().run();
        ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
        ICertificateStoreSession storeremote = storehome.create();
        int number = storeremote.getLastCRLNumber();
        System.out.println("CRL with number " + number+ " generated.");
    }

    static private Certificate[] getCertChain() {
        try {
            Context ctx = getInitialContext();
            ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
            ISignSession ss = home.create();
            Certificate[] chain = ss.getCertificateChain();
            return chain;
        } catch (Exception e) {
            cat.error(e);
        }
        return null;
    } // getCertChain
    
    static private Certificate[] getExpiredCerts(Date findDate) {
        try {
            Context ctx = getInitialContext();
            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class );;
            ICertificateStoreSession store = storehome.create();
            cat.debug("Looking for cert with expireDate="+findDate);
            Certificate[] certs = store.findCertificatesByExpireTime(findDate);
            cat.debug("Found "+certs.length+" certs.");
            return certs;
        } catch (Exception e) {
            cat.error(e);
        }
        return null;
    } // getExpiredCerts
    
    static private Context getInitialContext() throws NamingException{
        cat.debug(">getInitialContext");
        Context ctx = new javax.naming.InitialContext();
        cat.debug("<getInitialContext");
        return ctx;
    } //getInitialContext

    /**
     * Creates the CertificateStore and Publishers so they are available.
     */
    static private void initCertificateStore() throws RemoteException {
        cat.debug(">initCertificateStore()");
        Context context = null;
        try {
            context = getInitialContext();
            // First init main certificate store
            if (certificateStore == null) {
                ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
                certificateStore = storehome.create();
            }
        } catch (NamingException e) {
            // We could not find this publisher
            cat.error("Failed to find cert store.");
            e.printStackTrace();
        } catch (CreateException ce) {
            // We could not find this publisher
            cat.error("Failed to create cert store.");
            ce.printStackTrace();
        }
        // Init the publisher session beans
        if (publishers == null) {
            int i = 1;
            publishers = new Vector(0);
            try {
                while (true) {
                    String jndiName = "PublisherSession" + i;
                    IPublisherSessionHome pubhome = (IPublisherSessionHome)javax.rmi.PortableRemoteObject.narrow(context.lookup(jndiName), IPublisherSessionHome.class);
                    IPublisherSession pub = pubhome.create();
                    publishers.add(pub);
                    cat.debug("Added publisher class '"+pub.getClass().getName()+"'");
                    i++;
                }
                
            } catch (NamingException e) {
                // We could not find this publisherm this is not an error
                cat.debug("Failed to find publisher at index '"+i+"', no more publishers.");
            } catch (CreateException ce) {
                // We could not find this publisher
                cat.error("Failed to create configured publisher.");
                ce.printStackTrace();
            }
        }
        cat.debug("<initCertificateStore()");
    } // initCertificateStore
    
} //ca
