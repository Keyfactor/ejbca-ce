
package se.anatom.ejbca.util;

import java.io.*;

import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyStoreException;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.jce.interfaces.*;

import org.apache.log4j.*;


/**
 * Tools to handle common key and keystore operations.
 *
 * @version $Id: KeyTools.java,v 1.13 2003-01-22 09:06:13 scop Exp $
 */
public class KeyTools {

    private static Category cat = Category.getInstance(KeyTools.class.getName());

    /** Prevent from creating new KeyTools object*/
    private KeyTools() {
    }

    /**
     * Generates a keypair
     *
     * @return KeyPair the generated keypair
     */
    static public KeyPair genKeys(int keysize) throws NoSuchAlgorithmException, NoSuchProviderException {

        cat.debug(">genKeys()");
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA", "BC");
        keygen.initialize(keysize);
        KeyPair rsaKeys = keygen.generateKeyPair();

        cat.debug("Generated " + rsaKeys.getPublic().getAlgorithm() + " keys with length " + ((RSAPrivateKey)rsaKeys.getPrivate()).getPrivateExponent().bitLength());

        cat.debug("<genKeys()");
        return rsaKeys;
    } // genKeys

    /**
     * Creates PKCS12-file that can be imported in IE or Netscape.
     * The alias for the private key is set to 'privateKey' and the private key password is null.
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cacert CA-certificate or null if only one cert in chain, in that case use 'cert'.
     * @param username user's username
     * @param password user's password
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    static public KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, X509Certificate cacert)
    throws Exception {
        Certificate[] chain;
        if (cacert == null)
            chain = null;
        else {
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
     * @param cachain CA-certificate chain or null if only one cert in chain, in that case use 'cert'.
     * @param username user's username
     * @param password user's password
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    static public KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, Certificate[] cachain)
    throws Exception {
        cat.debug(">createP12: alias=" + alias + ", privKey, cert=" + cert.getSubjectDN() + ", cachain.length=" + (cachain == null ? 0 : cachain.length) );

        // Certificate chain, only max two levels deep unforturnately, this is a TODO:
        if (cert == null)
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        int len = 1;
        if (cachain != null)
            len += cachain.length;
        Certificate[] chain = new Certificate[len];
        // To not get a ClassCastException we need to genereate a real new certificate with BC
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        chain[0] = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
        if (cachain != null)
            for (int i=0;i<cachain.length;i++) {
                 X509Certificate tmpcert = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cachain[i].getEncoded()));
                 chain[i+1] = tmpcert;
            }


        if (chain.length > 1) {
            for (int i=1;i<chain.length;i++) {
                X509Certificate cacert  = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(chain[i].getEncoded()));
                // Set attributes on CA-cert
                PKCS12BagAttributeCarrier   caBagAttr = (PKCS12BagAttributeCarrier)chain[i];
                String cafriendly = CertTools.getPartFromDN(cacert.getSubjectDN().toString(), "CN");
                caBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(cafriendly));
            }
        }
        // Set attributes on user-cert
        PKCS12BagAttributeCarrier   certBagAttr = (PKCS12BagAttributeCarrier)chain[0];
        certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        // in this case we just set the local key id to that of the public key
        certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));

        // "Clean" private key, i.e. remove any old attributes
        KeyFactory keyfact = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
        PrivateKey pk = keyfact.generatePrivate(new PKCS8EncodedKeySpec(privKey.getEncoded()));
        // Set attributes for private key
        PKCS12BagAttributeCarrier keyBagAttr = (PKCS12BagAttributeCarrier)pk;
        // in this case we just set the local key id to that of the public key
        keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));

        // store the key and the certificate chain
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        store.load(null, null);
        store.setKeyEntry(alias, pk, null, chain);
        cat.debug(">createP12: alias=" + alias + ", privKey, cert=" + cert.getSubjectDN() + ", cachain.length=" + (cachain == null ? 0 : cachain.length));

        return store;
    } // createP12

    /**
     * Creates JKS-file that can be used with JDK.
     * The alias for the private key is set to 'privateKey' and the private key password is null.
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cachain CA-certificate chain or null if only one cert in chain, in that case use 'cert'.
     * @param username user's username
     * @param password user's password
     * @return KeyStore containing JKS-keystore
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    static public KeyStore createJKS(String alias, PrivateKey privKey, String password, X509Certificate cert, Certificate[] cachain)
    throws Exception {
        cat.debug(">createJKS: alias=" + alias + ", privKey, cert=" + cert.getSubjectDN() + ", cachain.length=" + (cachain == null ? 0 : cachain.length) );

        String caAlias="cacert";
        // Certificate chain, only max two levels deep unforturnately, this is a TODO:
        if (cert == null)
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        int len = 1;
        if (cachain != null)
            len += cachain.length;
        Certificate[] chain = new Certificate[len];
        chain[0] = cert;
        if (cachain != null) {
            for (int i=0;i<cachain.length;i++) {
                chain[i+1] = cachain[i];
            }
        }
        // store the key and the certificate chain
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);
        if (cachain != null) {
            store.setCertificateEntry(caAlias, cachain[cachain.length-1]);
        }
        store.setKeyEntry(alias, privKey, password.toCharArray(), chain);
        cat.debug(">createJKS: alias=" + alias + ", privKey, cert=" + cert.getSubjectDN() + ", cachain.length=" + (cachain == null ? 0 : cachain.length));

        return store;
    } // createJKS

    /** Retrieves the certificate chain from a keystore.
     * @param ks the keystore, which has been loaded and opened.
     * @param privKeyAlias the alias of the privatekey for which the certchain belongs.
     * @return array of Certificate, length of array is 0 if no certificates are found.
     */
    public static Certificate[] getCertChain(KeyStore keyStore, String privateKeyAlias) throws KeyStoreException {
        cat.debug(">getCertChain: alias='"+privateKeyAlias+"'");
        Certificate[] certchain = keyStore.getCertificateChain(privateKeyAlias);
        cat.debug("Certchain retrieved from alias '"+privateKeyAlias+"' has length "+certchain.length);
        if (certchain.length < 1) {
            cat.error("Cannot load certificate chain with alias '"+privateKeyAlias+"' from keystore.");
            cat.debug("<getCertChain: alias='"+privateKeyAlias+"', retlength="+certchain.length);
            return certchain;
        } else if (certchain.length > 0) {
            if (CertTools.isSelfSigned((X509Certificate)certchain[certchain.length-1])) {
                cat.debug("Issuer='"+((X509Certificate)certchain[certchain.length-1]).getIssuerDN()+"'.");
                cat.debug("Subject='"+((X509Certificate)certchain[certchain.length-1]).getSubjectDN()+"'.");
                cat.debug("<getCertChain: alias='"+privateKeyAlias+"', retlength="+certchain.length);
                return certchain;
            }
        }

        // If we came here, we have a cert which is not root cert in 'cert'
        ArrayList array = new ArrayList();
        for (int i=0;i<certchain.length;i++) {
            array.add(certchain[i]);
        }

        boolean stop = false;
        while (!stop) {
            X509Certificate cert = (X509Certificate)array.get(array.size()-1);
            String ialias = CertTools.getPartFromDN(cert.getIssuerDN().toString(), "CN");
            Certificate[] chain1 = keyStore.getCertificateChain(ialias);
            if (chain1 == null) {
                stop = true;
            } else {
                cat.debug("Loaded certificate chain with length "+ chain1.length+" with alias '"+ialias+"'.");
                if (chain1.length == 0) {
                    cat.error("No RootCA certificate found!");
                    stop = true;
                }
                for (int j=0;j<chain1.length;j++) {
                    array.add(chain1[j]);
                    // If one cert is slefsigned, we have found a root certificate, we don't need to go on anymore
                    if (CertTools.isSelfSigned((X509Certificate)chain1[j]))
                        stop = true;
                }
            }
        }
        Certificate[] ret = new Certificate[array.size()];
        for (int i=0;i<ret.length;i++) {
            ret[i] = (X509Certificate)array.get(i);
            cat.debug("Issuer='"+((X509Certificate)ret[i]).getIssuerDN()+"'.");
            cat.debug("Subject='"+((X509Certificate)ret[i]).getSubjectDN()+"'.");
        }
        cat.debug("<getCertChain: alias='"+privateKeyAlias+"', retlength="+ret.length);
        return ret;
    } // getCertChain

    /** create the subject key identifier.
     * @param pubKey the public key
     * @return SubjectKeyIdentifer asn.1 structure
     */
    public static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey)
    {
        try
        {
            ByteArrayInputStream  bIn = new ByteArrayInputStream(
                                                    pubKey.getEncoded());
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
                (ASN1Sequence)new DERInputStream(bIn).readObject());

            return new SubjectKeyIdentifier(info);
        }
        catch (Exception e)
        {
            throw new RuntimeException("error creating key");
        }
    }

} // KeyTools
