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
import java.security.SignatureException;
import java.security.InvalidKeyException;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;

import se.anatom.ejbca.*;
import se.anatom.ejbca.util.*;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSession;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSession;

public class ca {

    public static void main(String [] args){
        if (args.length < 1) {
            System.out.println("Usage: CA makeroot | rootcert | makereq | recrep | processreq | createcrl | getcrl");
            return;
        }
        try {
            org.apache.log4j.BasicConfigurator.configure();
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
                KeyStore ks = KeyTools.createP12("privateKey", rsaKeys.getPrivate(), rootcert, null);

                FileOutputStream os = new FileOutputStream(filename);
                ks.store(os, storepwd.toCharArray());
                System.out.println("Keystore "+filename+" generated succefully.");
            } else if (args[0].equals("rootcert")) {
                // Export root CA certificate
                if (args.length < 2) {
                    System.out.println("Save root CA certificate to file.");
                    System.out.println("Usage: CA rootcert <filename>");
                    return;
                }
                String filename = args[1];
                Context ctx = getInitialContext();
                ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
                ISignSession ss = home.create();
                Certificate[] chain = ss.getCertificateChain();
                X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
                FileOutputStream fos = new FileOutputStream(filename);
                fos.write(rootcert.getEncoded());
                fos.close();
                System.out.println("Wrote Root CA certificate to '"+filename+"'");
            } else if (args[0].equals("makereq")) {
                // Generates keys and creates a keystore (PKCS12) to be used by the CA
                if (args.length < 7) {
                    System.out.println("Usage: CA makereq <DN> <keysize> <rootca-cert> <reqfile> <ksfile> <storepassword>");
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
                ByteArrayOutputStream bOut = new ByteArrayOutputStream ();
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

                // Create keyStore
                KeyStore ks = KeyTools.createP12("privateKey", rsaKeys.getPrivate(), selfcert, rootcert);

                FileOutputStream os = new FileOutputStream(ksfile);
                ks.store(os, storepwd.toCharArray());
                System.out.println("Keystore '"+ksfile+"' generated succefully.");
            } else if (args[0].equals("recrep")) {
                // Receive certificate reply as result of certificate request
                if (args.length < 4) {
                    System.out.println("Usage: CA recrep <cert-file> <ksfile> <storepassword>");
                    return;
                }
                String certfile = args[1];
                String ksfile = args[2];
                String storepwd= args[3];

                System.out.println("Receiving cert reploy:");
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
                    String ialias = CertTools.getCNFromDN(cert.getIssuerDN().toString());
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
                sign.initVerify(cert);
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
                    System.out.println("Usage: CA processreq <username> <password> <req-file> <outfile>");
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
                String beginKey = "-----BEGIN CERTIFICATE REQUEST-----";
                String endKey = "-----END CERTIFICATE REQUEST-----";
                byte[] buffer = FileTools.getBytesFromPEM(b64Encoded, beginKey, endKey);

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
                Context context = getInitialContext();
                IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( context.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
                home.create().run();
                ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
                ICertificateStoreSession storeremote = storehome.create();
                int number = storeremote.getLastCRLNumber();
                System.out.println("CRL with number " + number+ " generated.");
            } else if (args[0].equals("getcrl")) {
                if (args.length < 2) {
                    System.out.println("Usage: CA getcrl <outfile>");
                    return;
                }
                String outfile = args[1];
                Context context = getInitialContext();
                ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
                ICertificateStoreSession storeremote = storehome.create();
                byte[] crl = storeremote.getLastCRL();
                FileOutputStream fos = new FileOutputStream(outfile);
                fos.write(crl);
                fos.close();
                System.out.println("Wrote latest CR to " + outfile+ ".");
            } else {
                System.out.println("Usage: CA makeroot | rootcert | makereq | recrep | processreq | createcrl | getcrl");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
 

    static public Context getInitialContext() throws NamingException{
        System.out.println(">GetInitialContext");
        Context ctx = new javax.naming.InitialContext();
        System.out.println("<GetInitialContext");
    return ctx;
    }

} //ca
