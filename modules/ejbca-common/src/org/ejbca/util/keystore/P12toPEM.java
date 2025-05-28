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
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import org.apache.log4j.Logger;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.keys.KeyTools;

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
    public static File createPEM(final KeyStore keystore, final String password, final String exportPath) throws FileNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {

        // Find the private key key entry in the keystore
        Enumeration<String> e = keystore.aliases();
        Object o = null;
        PrivateKey serverPrivKey = null;
        while (e.hasMoreElements()) {
            o = e.nextElement();
            if (o instanceof String) {
                if ((keystore.isKeyEntry((String) o)) &&
                        ((serverPrivKey = (PrivateKey) keystore.getKey((String) o, password.toCharArray())) != null)) {
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
        Certificate[] chain = KeyTools.getCertChain(keystore, (String) o);
        if (log.isDebugEnabled()) {
            log.debug("Loaded certificate chain with length " + chain.length + " from keystore.");
        }
        X509Certificate userX509Certificate = (X509Certificate) chain[0];

        byte[] output = userX509Certificate.getEncoded();
        String sn = CertTools.getSubjectDN(userX509Certificate);
        String userFile = DnComponents.getPartFromDN(sn, "CN");
        String filetype = ".pem";

        File path = new File(exportPath);
        path.mkdir();

        File tmpFile = new File(path, userFile + filetype);

        try (OutputStream out = new FileOutputStream(tmpFile)) {
            out.write(CertTools.BEGIN_CERTIFICATE_WITH_NL.getBytes());
            byte[] userCertB64 = Base64.encode(output);
            out.write(userCertB64);
            out.write(CertTools.END_CERTIFICATE_WITH_NL.getBytes());
        } catch (IOException e1) {
            throw new IllegalStateException("Unexpected IOException was thrown", e1);
        }
            
        tmpFile = new File(path, userFile + "-Key" + filetype);

        try (FileOutputStream keyOutputStream = new FileOutputStream(tmpFile)) {
            keyOutputStream.write(CertTools.BEGIN_PRIVATE_KEY.getBytes());
            keyOutputStream.write("\n".getBytes());
            byte[] privKey = Base64.encode(privKeyEncoded);
            keyOutputStream.write(privKey);
            keyOutputStream.write("\n".getBytes());
            keyOutputStream.write(CertTools.END_PRIVATE_KEY.getBytes());

        } catch (IOException e1) {
            throw new IllegalStateException("Unexpected IOException was thrown", e1);
        }
        

        tmpFile = new File(path, userFile + "-CA" + filetype);

        if (CertTools.isSelfSigned(userX509Certificate)) {
            log.info(
                "User certificate is selfsigned, this is a RootCA, no CA certificates written.");
        } else {
            try (FileOutputStream chainOutputStream = new FileOutputStream(tmpFile)) {

                for (int num = 1; num < chain.length; num++) {
                    X509Certificate tmpX509Cert = (X509Certificate) chain[num];
                    byte[] tmpOutput = tmpX509Cert.getEncoded();
                    chainOutputStream.write(CertTools.BEGIN_CERTIFICATE_WITH_NL.getBytes());
                    byte[] tmpCACertB64 = Base64.encode(tmpOutput);
                    chainOutputStream.write(tmpCACertB64);
                    chainOutputStream.write(CertTools.END_CERTIFICATE_WITH_NL.getBytes());
                }
            } catch (IOException e1) {
                throw new IllegalStateException("Unexpected IOException was thrown", e1);
            }
        }
        return tmpFile;
    }
}
