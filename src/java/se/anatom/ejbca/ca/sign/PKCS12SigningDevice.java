package se.anatom.ejbca.ca.sign;

import org.apache.log4j.Logger;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;

import java.io.FileInputStream;
import java.io.InputStream;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.util.Properties;


/**
 * Implements a singleton signing device using PKCS12 keystore.
 *
 * @version $Id: PKCS12SigningDevice.java,v 1.9 2003-06-26 11:43:23 anatom Exp $
 */
public class PKCS12SigningDevice implements ISigningDevice {
    /** Log4j instance for Base */
    private static Logger log = Logger.getLogger(PKCS12SigningDevice.class);
    private PrivateKey privateKey;
    private X509Certificate rootCert;
    private X509Certificate caCert;

    /** A handle to the unique Singleton instance. */
    private static PKCS12SigningDevice instance = null;

    /**
     * Reads a PKCS12 keystore and initializes all internal data arguments: -keyStorePass -keyStore
     * (filename) -privateKeyAlias -privateKeyPass
     *
     * @param p properties with arguments
     */
    protected PKCS12SigningDevice(Properties p) throws Exception {
        log.debug(">PKCS12SigningDevice()");

        // Get env variables and read in nessecary data
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        String keyStoreFile = p.getProperty("keyStore");

        if (keyStoreFile == null) {
            throw new IllegalArgumentException("Missing keyStore property.");
        }

        log.debug("keystore:" + keyStoreFile);

        InputStream is = new FileInputStream(keyStoreFile);
        String keyStorePass = p.getProperty("keyStorePass");

        if (keyStorePass == null) {
            throw new IllegalArgumentException("Missing keyStorePass property.");
        }

        //char[] keyStorePass = getPassword("java:comp/env/keyStorePass");
        log.debug("keystorepass: " + keyStorePass);
        keyStore.load(is, keyStorePass.toCharArray());

        String privateKeyAlias = p.getProperty("privateKeyAlias");

        if (privateKeyAlias == null) {
            throw new IllegalArgumentException("Missing privateKeyAlias property.");
        }

        log.debug("privateKeyAlias: " + privateKeyAlias);

        String privateKeyPass = p.getProperty("privateKeyPass");
        char[] pkPass;

        if ((privateKeyPass).equals("null")) {
            pkPass = null;
        } else {
            pkPass = privateKeyPass.toCharArray();
        }

        log.debug("privateKeyPass: " + privateKeyPass);
        privateKey = (PrivateKey) keyStore.getKey(privateKeyAlias, pkPass);

        if (privateKey == null) {
            log.error("Cannot load key with alias '" + privateKeyAlias + "' from keystore '" +
                keyStoreFile + "'");
            throw new Exception("Cannot load key with alias '" + privateKeyAlias +
                "' from keystore '" + keyStoreFile + "'");
        }

        Certificate[] certchain = KeyTools.getCertChain(keyStore, privateKeyAlias);

        if (certchain.length < 1) {
            log.error("Cannot load certificate chain with alias '" + privateKeyAlias +
                "' from keystore '" + keyStoreFile + "'");
            throw new Exception("Cannot load certificate chain with alias '" + privateKeyAlias +
                "' from keystore '" + keyStoreFile + "'");
        }

        // We only support a ca hierarchy with depth 2.
        caCert = (X509Certificate) certchain[0];
        log.debug("cacertIssuer: " + CertTools.getIssuerDN(caCert));
        log.debug("cacertSubject: " + CertTools.getSubjectDN(caCert));

        // root cert is last cert in chain
        rootCert = (X509Certificate) certchain[certchain.length - 1];
        log.debug("rootcertIssuer: " + CertTools.getIssuerDN(rootCert));
        log.debug("rootcertSubject: " + CertTools.getSubjectDN(rootCert));

        // is root cert selfsigned?
        if (!CertTools.isSelfSigned(rootCert)) {
            throw new Exception("Root certificate is not self signed!");
        }

        log.debug("<PKCS12SigningDevice()");
    }

    /**
     * Creates (if needed) the signing device and returns the object.
     *
     * @param prop Arguments needed fo?r the eventual creation of the object
     *
     * @return An instance of the Signing device.
     */
    public static synchronized ISigningDevice instance(Properties prop)
        throws Exception {
        if (instance == null) {
            instance = new PKCS12SigningDevice(prop);
        }

        return instance;
    }

    /**
     * Returns an array with the certificate chain, the root certificate is last in the chain.
     *
     * @return an array of Certificate
     */
    public Certificate[] getCertificateChain() {
        log.debug(">getCertificateChain()");

        // TODO: should support more than 2 levels of CAs
        Certificate[] chain;

        if (CertTools.isSelfSigned(caCert)) {
            chain = new Certificate[1];
        } else {
            chain = new Certificate[2];
            chain[1] = rootCert;
        }

        chain[0] = caCert;
        log.debug("<getCertificateChain()");

        return chain;
    }

    /**
     * Returns the private key (if possible) used for signature creation.
     *
     * @return PrivateKey object
     */
    public PrivateKey getPrivateSignKey() {
        return privateKey;
    }

    /**
     * Returns the public key (if possible) used for signature verification.
     *
     * @return PublicKey object
     */
    public PublicKey getPublicSignKey() {
        return caCert.getPublicKey();
    }

    /**
     * Returns the private key (if possible) used for decryption.
     *
     * @return PrivateKey object
     */
    public PrivateKey getPrivateDecKey() {
        return privateKey;
    }

    /**
     * Returns the public key (if possible) used for encryption.
     *
     * @return PublicKey object
     */
    public PublicKey getPublicEncKey() {
        return caCert.getPublicKey();
    }

    /**
     * Weuse the BouncyCastle provider to sign stuff
     *
     * @return String "BC"
     */
    public String getProvider() {
        return "BC";
    }
}
