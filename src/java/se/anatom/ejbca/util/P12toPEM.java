package se.anatom.ejbca.util;

import java.io.*;
import java.util.Enumeration;
import java.security.Security;
import java.security.cert.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;

import org.bouncycastle.jce.provider.*;

import org.apache.log4j.*;

/**
 * P12toPEM is used to export PEM files from a single p12 file.
 * The class exports the user certificate, user private key in seperated files and the chain of sub ca and ca certifikate in a third file.
 * The PEM files will have the names <i>common name</i>.pem, <i>common name</i>Key.pem and <i>common name</i>CA.pem derived from the DN in user certificate.
 *
 * @version $Id: P12toPEM.java,v 1.3 2002-05-10 08:29:04 anatom Exp $
 */

public class P12toPEM {

    private static Category cat = Category.getInstance(P12toPEM.class.getName());

    String exportpath = "./pem/";
    String p12File;
    String password;
    boolean overwrite = false;

    byte beginCertificate[] = "-----BEGIN CERTIFICATE-----".getBytes();
    byte endCertificate[] = "-----END CERTIFICATE-----".getBytes();
    byte beginPrivateKey[] = "-----BEGIN RSA PRIVATE KEY-----".getBytes();
    byte endPrivateKey[] = "-----END RSA PRIVATE KEY-----".getBytes();
    byte NL[] = "\n".getBytes();

    public static void main(String args[]) {

        org.apache.log4j.PropertyConfigurator.configure("log4j.properties");
        // Bouncy Castle security provider
        Security.addProvider(new BouncyCastleProvider());

        P12toPEM p12 = null;
        String pathAllP12 = null;
        try {
            if(args.length > 2) {
                boolean overwrite = false;
                if(args[2].equalsIgnoreCase("true")) overwrite = true;
                p12 = new P12toPEM(args[0], args[1], overwrite);
            } else if (args.length > 1) {
                p12 = new P12toPEM(args[0], args[1]);
            } else {
                System.out.println("Usage: P12toPEM <p12file> <p12password> [overwrite (true/false)(default false)]");
                System.exit(0);
            }
            p12.createPEM();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Basic construtor for the P12toPEM class, set variables for the class.
     *
     * @param String p12File The (path +) name of the input p12 file.
     * @param String password The password for the p12 file.
     */
    public P12toPEM(String p12File, String password) {
        this.p12File = p12File;
        this.password = password;
    }

    /** Sets the directory where PEM-files wil be stores
     * @param path path where PEM-files will be stores
     */
    public void setExportPath(String path) {
        exportpath = path;
    }

    /**
     * Constructor for the P12toPEM class.
     *
     * @param String p12File The (path +) name of the input p12 file.
     * @param String password The password for the p12 file.
     * @param boolean overwrite If existing files should be overwritten.
     */
    public P12toPEM(String p12File, String password, boolean overwrite) {
        this.p12File = p12File;
        this.password = password;
        this.overwrite = overwrite;
    }

    public void createPEM() throws KeyStoreException,
        FileNotFoundException, IOException, NoSuchProviderException,
        NoSuchAlgorithmException, CertificateEncodingException, CertificateException,
        UnrecoverableKeyException {
        KeyStore ks = ks = KeyStore.getInstance("PKCS12", "BC");
        InputStream in = new FileInputStream(p12File);
        ks.load(in, password.toCharArray());
        in.close();

        // Fid the key private key entry in the keystore
        Enumeration e = ks.aliases();
        Object o = null;
        PrivateKey serverPrivKey = null;
        while (e.hasMoreElements()) {
            o = e.nextElement();
            if(o instanceof String) {
                if ( (ks.isKeyEntry((String) o)) && ((serverPrivKey = (PrivateKey)ks.getKey((String) o, password.toCharArray())) != null) ) {
                    cat.debug("Aliases " + o + " is KeyEntry.");
                    break;
                }
            }
        }

        cat.debug("Private key encode: " + serverPrivKey == null ? null : serverPrivKey.getFormat());
        byte privKeyEncoded[] = "".getBytes();
        if (serverPrivKey != null)
            privKeyEncoded = serverPrivKey.getEncoded();

        //Certificate chain[] = ks.getCertificateChain((String) o);
        Certificate chain[] = KeyTools.getCertChain(ks, (String) o);
        cat.debug("Loaded certificate chain with length "+chain.length+" from keystore.");
        X509Certificate userX509Certificate = (X509Certificate) chain[0];

        byte output[] = userX509Certificate.getEncoded();
        String sn = userX509Certificate.getSubjectDN().toString();
        String userFile = CertTools.getPartFromDN(sn, "CN");
        String filetype = ".pem";

        File path = new File(exportpath);
        path.mkdir();
        File tmpFile = new File(path, userFile + filetype);
        if(!overwrite)
            if(tmpFile.exists()) {
                cat.error("File '"+tmpFile+"' already exists, don't overwrite.");
                return;
            }
        OutputStream out = new FileOutputStream(tmpFile);
        out.write(beginCertificate);
        out.write(NL);
        byte userCertB64[] = Base64.encode(output);
        out.write(userCertB64);
        out.write(NL);
        out.write(endCertificate);
        out.close();

        tmpFile = new File(path, userFile + "-Key" + filetype);
        if(!overwrite)
            if(tmpFile.exists()) {
                cat.error("File '"+tmpFile+"' already exists, don't overwrite.");
                return;
            }
        out = new FileOutputStream(tmpFile);
        out.write(beginPrivateKey);
        out.write(NL);
        byte privKey[] = Base64.encode(privKeyEncoded);
        out.write(privKey);
        out.write(NL);
        out.write(endPrivateKey);
        out.close();

        tmpFile = new File(path, userFile + "-CA" + filetype);
        if(!overwrite)
            if(tmpFile.exists()) {
                cat.error("File '"+tmpFile+"' already exists, don't overwrite.");
                return;
            }
        if (CertTools.isSelfSigned(userX509Certificate)) {
            cat.info("User certificate is selfsigned, this is a RootCA, no CA certificates written.");
        } else {
            out = new FileOutputStream(tmpFile);
            for(int num = 1;num < chain.length;num++) {
                X509Certificate tmpX509Cert = (X509Certificate) chain[num];
                byte tmpOutput[] = tmpX509Cert.getEncoded();
                out.write(beginCertificate);
                out.write(NL);
                byte tmpCACertB64[] = Base64.encode(tmpOutput);
                out.write(tmpCACertB64);
                out.write(NL);
                out.write(endCertificate);
                out.write(NL);
            }
            out.close();
        }
    } // createPEM

} // P12toPEM
