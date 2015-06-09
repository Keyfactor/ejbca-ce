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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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
                    "Usage: P12toPEM <p12file> <p12password>");
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
	 */
	public P12toPEM(KeyStore keystore, String password) {		
		this.password = password;
		this.ks = keystore;
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
    }

    /**
     * Converts a P12 into a PEM
     *
     * @return the created PEM file, null if file wasn't found and no other exception was thrown. 
     *
     * @throws FileNotFoundException if the P12 file supplied to this class in its constructor was not found.
     * @throws CertificateException if the p12 couldn't be loaded
     * @throws NoSuchAlgorithmException if the algorithm used to build the P12 couldn't be found
     * @throws KeyStoreException if the keystore has not been initialised. 
     * @throws UnrecoverableKeyException if the password was incorrect 
     */
    public File createPEM() throws FileNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {
         if(this.ks == null){    	
            try {
                ks = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
            } catch (KeyStoreException e1) {
                // TODO Auto-generated catch block
                e1.printStackTrace();
            } catch (NoSuchProviderException e) {
              throw new IllegalStateException("BouncyCastle provider not found.", e);
            }
            InputStream in = new FileInputStream(p12File);
            try {
                try {
                    ks.load(in, password.toCharArray());
                } finally {
                    in.close();
                }
            } catch(IOException e) {
                throw new IllegalStateException("Unexpected IOException was thrown", e);
            }
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
                    if (log.isDebugEnabled()) {
                        log.debug("Aliases " + o + " is KeyEntry.");
                    }
                    break;
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug((("Private key encode: " + serverPrivKey) == null) ? null : serverPrivKey.getFormat());
        }
        byte[] privKeyEncoded = "".getBytes();
        if (serverPrivKey != null) {
            privKeyEncoded = serverPrivKey.getEncoded();
        }
        Certificate[] chain = KeyTools.getCertChain(ks, (String) o);
        if (log.isDebugEnabled()) {
            log.debug("Loaded certificate chain with length " + chain.length + " from keystore.");
        }
        X509Certificate userX509Certificate = (X509Certificate) chain[0];

        byte[] output = userX509Certificate.getEncoded();
        String sn = CertTools.getSubjectDN(userX509Certificate);
        String userFile = CertTools.getPartFromDN(sn, "CN");
        String filetype = ".pem";

        File path = new File(exportpath);
        path.mkdir();

        File tmpFile = new File(path, userFile + filetype);

        OutputStream out = new FileOutputStream(tmpFile);
        try {
            try {
                out.write(beginCertificate);
                out.write(NL);
                byte[] userCertB64 = Base64.encode(output);
                out.write(userCertB64);
                out.write(NL);
                out.write(endCertificate);
            } finally {
                out.close();
            }
        } catch (IOException e1) {
            throw new IllegalStateException("Unexpected IOException was thrown", e1);
        }
     
        tmpFile = new File(path, userFile + "-Key" + filetype);

        out = new FileOutputStream(tmpFile);
        try {
            try {
                out.write(beginPrivateKey);
                out.write(NL);
                byte[] privKey = Base64.encode(privKeyEncoded);
                out.write(privKey);
                out.write(NL);
                out.write(endPrivateKey);
            } finally {
                out.close();
            }
        } catch (IOException e1) {
            throw new IllegalStateException("Unexpected IOException was thrown", e1);
        }
        

        tmpFile = new File(path, userFile + "-CA" + filetype);

        if (CertTools.isSelfSigned(userX509Certificate)) {
            log.info(
                "User certificate is selfsigned, this is a RootCA, no CA certificates written.");
        } else {
            out = new FileOutputStream(tmpFile);
            try {
                for (int num = 1; num < chain.length; num++) {
                    X509Certificate tmpX509Cert = (X509Certificate) chain[num];
                    byte[] tmpOutput = tmpX509Cert.getEncoded();
                    try {
                        out.write(beginCertificate);
                        out.write(NL);

                        byte[] tmpCACertB64 = Base64.encode(tmpOutput);

                        out.write(tmpCACertB64);
                        out.write(NL);
                        out.write(endCertificate);
                        out.write(NL);
                    } catch (IOException e1) {
                        throw new IllegalStateException("Unexpected IOException was thrown", e1);
                    }
                }

            } finally {
                try {
                    out.close();
                } catch (IOException e1) {
                    throw new IllegalStateException("Unexpected IOException was thrown", e1);
                }
            }
        }
        return tmpFile;
    }
}
