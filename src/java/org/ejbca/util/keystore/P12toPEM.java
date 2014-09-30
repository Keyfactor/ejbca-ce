/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.util.keystore;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.log4j.Logger;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * P12toPEM is used to export PEM files from a single p12 file. The class exports the user
 * certificate, user private key in seperated files and the chain of sub ca and ca certifikate in
 * a third file. The PEM files will have the names <i>common name</i>.pem, <i>common
 * name</i>Key.pem and <i>common name</i>CA.pem derived from the DN in user certificate.
 *
 * @version $Id$
 */
public class P12toPEM {
    private static Logger log = Logger.getLogger(P12toPEM.class);
    String exportpath = "./p12/pem/";
    String p12File;
    String password;
    KeyStore ks = null;
    
    boolean overwrite = false;
    byte[] beginCertificate = "-----BEGIN CERTIFICATE-----".getBytes();
    byte[] endCertificate = "-----END CERTIFICATE-----".getBytes();
    byte[] beginPrivateKey = "-----BEGIN PRIVATE KEY-----".getBytes();
    byte[] endPrivateKey = "-----END PRIVATE KEY-----".getBytes();
    byte[] NL = "\n".getBytes();

    /**
     * DOCUMENT ME!
     *
     * @param args DOCUMENT ME!
     */
    public static void main(String[] args) {
        // Bouncy Castle security provider
    	CryptoProviderTools.installBCProvider();

        P12toPEM p12 = null;

        try {
            if (args.length > 2) {
                boolean overwrite = false;

                if (args[2].equalsIgnoreCase("true")) {
                    overwrite = true;
                }

                p12 = new P12toPEM(args[0], args[1], overwrite);
            } else if (args.length > 1) {
                p12 = new P12toPEM(args[0], args[1]);
            } else {
                System.out.println(
                    "Usage: P12toPEM <p12file> <p12password> [overwrite (true/false)(default false)]");
                System.exit(0); // NOPMD this is a cli command
            }

            p12.createPEM();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Basic construtor for the P12toPEM class, set variables for the class.
     *
     * @param p12File p12File The (path +) name of the input p12 file.
     * @param password password The password for the p12 file.
     * 
     */
    public P12toPEM(String p12File, String password) {
        this.p12File = p12File;
        this.password = password;
    }

	/**
	 * Basic constructor using a in memory KeyStore instead for a file.
	 *
	 * @param keystore the KeyStore to use.
	 * @param password password The password for the p12 file.
	 * @param overwrite overwrite If existing files should be overwritten.    
	 */
	public P12toPEM(KeyStore keystore, String password, boolean overwrite) {		
		this.password = password;
		this.ks = keystore;
		this.overwrite = overwrite;
	}


    /**
     * Sets the directory where PEM-files wil be stores
     *
     * @param path path where PEM-files will be stores
     */
    public void setExportPath(String path) {
        exportpath = path;
    }

    /**
     * Constructor for the P12toPEM class.
     *
     * @param p12File p12File The (path +) name of the input p12 file.
     * @param password password The password for the p12 file.
     * @param overwrite overwrite If existing files should be overwritten.
     */
    public P12toPEM(String p12File, String password, boolean overwrite) {
        this.p12File = p12File;
        this.password = password;
        this.overwrite = overwrite;
    }

    /**
     * DOCUMENT ME!
     *
     * @throws KeyStoreException DOCUMENT ME!
     * @throws FileNotFoundException DOCUMENT ME!
     * @throws IOException DOCUMENT ME!
     * @throws NoSuchProviderException DOCUMENT ME!
     * @throws NoSuchAlgorithmException DOCUMENT ME!
     * @throws CertificateEncodingException DOCUMENT ME!
     * @throws CertificateException DOCUMENT ME!
     * @throws UnrecoverableKeyException DOCUMENT ME!
     */
    public void createPEM()
        throws KeyStoreException, FileNotFoundException, IOException, NoSuchProviderException, 
            NoSuchAlgorithmException, CertificateEncodingException, CertificateException, 
            UnrecoverableKeyException {
         
         if(this.ks == null){    	
            ks = KeyStore.getInstance("PKCS12", "BC");
            InputStream in = new FileInputStream(p12File);
            ks.load(in, password.toCharArray());
            in.close();
        }
        // Fid the key private key entry in the keystore
        Enumeration<String> e = ks.aliases();
        Object o = null;
        PrivateKey serverPrivKey = null;

        while (e.hasMoreElements()) {
            o = e.nextElement();

            if (o instanceof String) {
                if ((ks.isKeyEntry((String) o)) &&
                        ((serverPrivKey = (PrivateKey) ks.getKey((String) o, password.toCharArray())) != null)) {
                    log.debug("Aliases " + o + " is KeyEntry.");

                    break;
                }
            }
        }

        log.debug((("Private key encode: " + serverPrivKey) == null) ? null
                                                                     : serverPrivKey.getFormat());

        byte[] privKeyEncoded = "".getBytes();

        if (serverPrivKey != null) {
            privKeyEncoded = serverPrivKey.getEncoded();
        }

        //Certificate chain[] = ks.getCertificateChain((String) o);
        Certificate[] chain = KeyTools.getCertChain(ks, (String) o);
        log.debug("Loaded certificate chain with length " + chain.length + " from keystore.");

        X509Certificate userX509Certificate = (X509Certificate) chain[0];

        byte[] output = userX509Certificate.getEncoded();
        String sn = CertTools.getSubjectDN(userX509Certificate);
        String userFile = CertTools.getPartFromDN(sn, "CN");
        String filetype = ".pem";

        File path = new File(exportpath);
        path.mkdir();

        File tmpFile = new File(path, userFile + filetype);

        if (!overwrite) {
            if (tmpFile.exists()) {
                log.error("File '" + tmpFile + "' already exists, don't overwrite.");

                return;
            }
        }

        OutputStream out = new FileOutputStream(tmpFile);
        out.write(beginCertificate);
        out.write(NL);

        byte[] userCertB64 = Base64.encode(output);
        out.write(userCertB64);
        out.write(NL);
        out.write(endCertificate);
        out.close();

        tmpFile = new File(path, userFile + "-Key" + filetype);

        if (!overwrite) {
            if (tmpFile.exists()) {
                log.error("File '" + tmpFile + "' already exists, don't overwrite.");

                return;
            }
        }

        out = new FileOutputStream(tmpFile);
        out.write(beginPrivateKey);
        out.write(NL);

        byte[] privKey = Base64.encode(privKeyEncoded);
        out.write(privKey);
        out.write(NL);
        out.write(endPrivateKey);
        out.close();

        tmpFile = new File(path, userFile + "-CA" + filetype);

        if (!overwrite) {
            if (tmpFile.exists()) {
                log.error("File '" + tmpFile + "' already exists, don't overwrite.");

                return;
            }
        }

        if (CertTools.isSelfSigned(userX509Certificate)) {
            log.info(
                "User certificate is selfsigned, this is a RootCA, no CA certificates written.");
        } else {
            out = new FileOutputStream(tmpFile);

            for (int num = 1; num < chain.length; num++) {
                X509Certificate tmpX509Cert = (X509Certificate) chain[num];
                byte[] tmpOutput = tmpX509Cert.getEncoded();
                out.write(beginCertificate);
                out.write(NL);

                byte[] tmpCACertB64 = Base64.encode(tmpOutput);
                out.write(tmpCACertB64);
                out.write(NL);
                out.write(endCertificate);
                out.write(NL);
            }

            out.close();
        }
    }

    // createPEM
}


// P12toPEM
