/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.util;

import java.io.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.*;
import java.security.interfaces.*;
import java.security.spec.*;
import java.util.*;

import org.apache.log4j.Logger;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.interfaces.*;


/**
 * Tools to handle common key and keystore operations.
 *
 * @version $Id: KeyTools.java,v 1.29 2004-11-08 20:10:13 sbailliez Exp $
 */
public class KeyTools {
    private static Logger log = Logger.getLogger(KeyTools.class);

    /**
     * Prevent from creating new KeyTools object
     */
    private KeyTools() {
    }

    /**
     * Generates a keypair
     *
     * @param keysize size of keys to generate, typical value is 1024 for RSA keys
     *
     * @return KeyPair the generated keypair
     */
    public static KeyPair genKeys(int keysize)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        log.debug(">genKeys()");

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(keysize);

        KeyPair rsaKeys = keygen.generateKeyPair();

        log.debug("Generated " + rsaKeys.getPublic().getAlgorithm() + " keys with length " +
            ((RSAPrivateKey) rsaKeys.getPrivate()).getPrivateExponent().bitLength());

        log.debug("<genKeys()");

        return rsaKeys;
    } // genKeys

    /**
     * Creates PKCS12-file that can be imported in IE or Netscape. The alias for the private key is
     * set to 'privateKey' and the private key password is null.
     *
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cacert CA-certificate or null if only one cert in chain, in that case use 'cert'.
     *
     * @return KeyStore containing PKCS12-keystore
     *
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, X509Certificate cacert) 
    throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate[] chain;

        if (cacert == null) {
            chain = null;
        } else {
            chain = new Certificate[1];
            chain[0] = cacert;
        }

        return createP12(alias, privKey, cert, chain);
    } // createP12

    /**
     * Creates PKCS12-file that can be imported in IE or Netscape.
     * The alias for the private key is set to 'privateKey' and the private key password is null.
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cacert Collection of X509Certificate, or null if only one cert in chain, in that case use 'cert'.
     * @param username user's username
     * @param password user's password
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, Collection cacerts)
    throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate[] chain;
        if (cacerts == null)
            chain = null;
        else {
            chain = new Certificate[cacerts.size()];
            chain = (Certificate[])cacerts.toArray(chain);
        }
        return createP12(alias, privKey, cert, chain);
    } // createP12

    /**
     * Creates PKCS12-file that can be imported in IE or Netscape. The alias for the private key is
     * set to 'privateKey' and the private key password is null.
     *
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cachain CA-certificate chain or null if only one cert in chain, in that case use 'cert'.
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, Certificate[] cachain) 
    throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        log.debug(">createP12: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) +", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        // Certificate chain
        if (cert == null) {
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        }
        int len = 1;
        if (cachain != null) {
            len += cachain.length;
        }
        Certificate[] chain = new Certificate[len];
        // To not get a ClassCastException we need to genereate a real new certificate with BC
        CertificateFactory cf = CertTools.getCertificateFactory();
        chain[0] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                    cert.getEncoded()));

        if (cachain != null) {
            for (int i = 0; i < cachain.length; i++) {
                X509Certificate tmpcert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                            cachain[i].getEncoded()));
                chain[i + 1] = tmpcert;
            }
        }
        if (chain.length > 1) {
            for (int i = 1; i < chain.length; i++) {
                X509Certificate cacert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                            chain[i].getEncoded()));
                // Set attributes on CA-cert
                PKCS12BagAttributeCarrier caBagAttr = (PKCS12BagAttributeCarrier) chain[i];
                // We constuct a friendly name for the CA, and try with some parts from the DN if they exist.
                String cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "CN");
                // On the ones below we +i to make it unique, O might not be otherwise
                if (cafriendly == null) {
                    cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "O")+i;
                }
                if (cafriendly == null) {
                    cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "OU"+i);
                }
                if (cafriendly == null) {
                    cafriendly = "CA_unknown"+i;
                }
                caBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString(cafriendly));
            }
        }

        // Set attributes on user-cert
        PKCS12BagAttributeCarrier certBagAttr = (PKCS12BagAttributeCarrier) chain[0];
        certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        // in this case we just set the local key id to that of the public key
        certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));
        // "Clean" private key, i.e. remove any old attributes
        KeyFactory keyfact = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
        PrivateKey pk = keyfact.generatePrivate(new PKCS8EncodedKeySpec(privKey.getEncoded()));
        // Set attributes for private key
        PKCS12BagAttributeCarrier keyBagAttr = (PKCS12BagAttributeCarrier) pk;
        // in this case we just set the local key id to that of the public key
        keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));
        // store the key and the certificate chain
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        store.load(null, null);
        store.setKeyEntry(alias, pk, null, chain);
        log.debug("<createP12: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        return store;
    } // createP12

    /**
     * Creates JKS-file that can be used with JDK. The alias for the private key is set to
     * 'privateKey' and the private key password is null.
     *
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param password user's password
     * @param cert user certificate
     * @param cachain CA-certificate chain or null if only one cert in chain, in that case use
     *        'cert'.
     *
     * @return KeyStore containing JKS-keystore
     *
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createJKS(String alias, PrivateKey privKey, String password,
        X509Certificate cert, Certificate[] cachain) throws Exception {
        log.debug(">createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) +
            ", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        String caAlias = "cacert";

        // Certificate chain
        if (cert == null) {
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        }
        int len = 1;
        if (cachain != null) {
            len += cachain.length;
        }
        Certificate[] chain = new Certificate[len];
        chain[0] = cert;
        if (cachain != null) {
            for (int i = 0; i < cachain.length; i++) {
                chain[i + 1] = cachain[i];
            }
        }

        // store the key and the certificate chain
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);

        // First load the key entry
        X509Certificate[] usercert = new X509Certificate[1];
        usercert[0] = cert;
        store.setKeyEntry(alias, privKey, password.toCharArray(), usercert);

        // Add the root cert as trusted
        if (cachain != null) {
            if (!CertTools.isSelfSigned((X509Certificate) cachain[cachain.length - 1])) {
                throw new IllegalArgumentException("Root cert is not self-signed.");
            }
            store.setCertificateEntry(caAlias, cachain[cachain.length - 1]);
        }

        // Set the complete chain
        log.debug("Storing cert chain of length " + chain.length);
        store.setKeyEntry(alias, privKey, password.toCharArray(), chain);
        log.debug("<createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) +
            ", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        return store;
    } // createJKS

    /**
     * Retrieves the certificate chain from a keystore.
     *
     * @param keyStore the keystore, which has been loaded and opened.
     * @param privateKeyAlias the alias of the privatekey for which the certchain belongs.
     *
     * @return array of Certificate, length of array is 0 if no certificates are found.
     */
    public static Certificate[] getCertChain(KeyStore keyStore, String privateKeyAlias)
        throws KeyStoreException {
        log.debug(">getCertChain: alias='" + privateKeyAlias + "'");

        Certificate[] certchain = keyStore.getCertificateChain(privateKeyAlias);
        log.debug("Certchain retrieved from alias '" + privateKeyAlias + "' has length " +
            certchain.length);

        if (certchain.length < 1) {
            log.error("Cannot load certificate chain with alias '" + privateKeyAlias +
                "' from keystore.");
            log.debug("<getCertChain: alias='" + privateKeyAlias + "', retlength=" +
                certchain.length);

            return certchain;
        } else if (certchain.length > 0) {
            if (CertTools.isSelfSigned((X509Certificate) certchain[certchain.length - 1])) {
                log.debug("Issuer='" +
                    CertTools.getIssuerDN((X509Certificate) certchain[certchain.length - 1]) +
                    "'.");
                log.debug("Subject='" +
                    CertTools.getSubjectDN((X509Certificate) certchain[certchain.length - 1]) +
                    "'.");
                log.debug("<getCertChain: alias='" + privateKeyAlias + "', retlength=" +
                    certchain.length);

                return certchain;
            }
        }

        // If we came here, we have a cert which is not root cert in 'cert'
        ArrayList array = new ArrayList();

        for (int i = 0; i < certchain.length; i++) {
            array.add(certchain[i]);
        }

        boolean stop = false;

        while (!stop) {
            X509Certificate cert = (X509Certificate) array.get(array.size() - 1);
            String ialias = CertTools.getPartFromDN(CertTools.getIssuerDN(cert), "CN");
            Certificate[] chain1 = keyStore.getCertificateChain(ialias);

            if (chain1 == null) {
                stop = true;
            } else {
                log.debug("Loaded certificate chain with length " + chain1.length +
                    " with alias '" + ialias + "'.");

                if (chain1.length == 0) {
                    log.error("No RootCA certificate found!");
                    stop = true;
                }

                for (int j = 0; j < chain1.length; j++) {
                    array.add(chain1[j]);

                    // If one cert is slefsigned, we have found a root certificate, we don't need to go on anymore
                    if (CertTools.isSelfSigned((X509Certificate) chain1[j])) {
                        stop = true;
                    }
                }
            }
        }

        Certificate[] ret = new Certificate[array.size()];

        for (int i = 0; i < ret.length; i++) {
            ret[i] = (X509Certificate) array.get(i);
            log.debug("Issuer='" + CertTools.getIssuerDN((X509Certificate) ret[i]) + "'.");
            log.debug("Subject='" + CertTools.getSubjectDN((X509Certificate) ret[i]) + "'.");
        }

        log.debug("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + ret.length);

        return ret;
    } // getCertChain

    /**
     * create the subject key identifier.
     *
     * @param pubKey the public key
     *
     * @return SubjectKeyIdentifer asn.1 structure
     */
    public static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey) {
        try {
            ByteArrayInputStream bIn = new ByteArrayInputStream(pubKey.getEncoded());
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo((ASN1Sequence) new DERInputStream(
                        bIn).readObject());

            return new SubjectKeyIdentifier(info);
        } catch (Exception e) {
            throw new RuntimeException("error creating key");
        }
    } // createSubjectKeyId
    
} // KeyTools
