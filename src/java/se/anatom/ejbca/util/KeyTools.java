
package se.anatom.ejbca.util;

import java.io.*;

import java.security.cert.*;
import java.security.spec.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.jce.interfaces.*;
import org.bouncycastle.jce.provider.*;

import org.apache.log4j.*;

import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.Hex;

/**
 * Tools to handle common key and keystore operations.
 *
 * @version $Id: KeyTools.java,v 1.2 2001-11-24 14:53:59 anatom Exp $
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

        cat.debug("Generated " + rsaKeys.getPublic().getAlgorithm() + " keys with length " + ((RSAPublicKey)rsaKeys.getPublic()).getPublicExponent().bitLength());

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
     * @return byte[] containing PKCS12-file in binary format
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    static public KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, X509Certificate cacert)
    throws Exception {
        cat.debug(">createP12: privKey, cert=" + cert.getSubjectDN() + ", cacert=" + (cacert == null ? "null" : cacert.getSubjectDN().toString()) );

        // Certificate chain, only max two levels deep unforturnately, this is a TODO:
        Certificate[] chain = null;
        if ( (cert != null) && (cacert != null) )
             chain = new Certificate[2];
        else if (cert != null)
            chain = new Certificate[1];
        else throw new IllegalArgumentException("Parameter cert cannot be null.");

        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");

        if (cacert != null) {
            chain[1] = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cacert.getEncoded()));
            // Set attributes on CA-cert
            PKCS12BagAttributeCarrier   caBagAttr = (PKCS12BagAttributeCarrier)chain[1];
            String cafriendly = CertTools.getCNFromDN(cacert.getSubjectDN().toString());
            caBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(cafriendly));
        }
        chain[0] = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));
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
        cat.debug(">createP12: privKey, cert=" + cert.getSubjectDN() + ", cacert=" + (cacert == null ? "null" : cacert.getSubjectDN().toString()));

        return store;
    } // createP12

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
                (DERConstructedSequence)new DERInputStream(bIn).readObject());

            return new SubjectKeyIdentifier(info);
        }
        catch (Exception e)
        {
            throw new RuntimeException("error creating key");
        }
    }

} // KeyTools
