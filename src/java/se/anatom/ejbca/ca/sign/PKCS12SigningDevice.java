package se.anatom.ejbca.ca.sign;



import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyStore;
import java.util.Properties;
import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.log4j.*;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;


/** Implements a signing device using PKCS12 keystore, implementes the Singleton pattern.
 *
 * @version $Id: PKCS12SigningDevice.java,v 1.6 2002-10-16 13:50:10 anatom Exp $
 */

public class PKCS12SigningDevice implements ISigningDevice{

    /** Log4j instance for Base */
    private static Category cat = Category.getInstance( PKCS12SigningDevice.class.getName() );

    private PrivateKey privateKey;
    private X509Certificate rootCert;
    private X509Certificate caCert;


   /**
    * A handle to the unique Singleton instance.
    */
    static private PKCS12SigningDevice instance = null;


   /** Reads a PKCS12 keystore and initializes all internal data
    */

    protected PKCS12SigningDevice(Properties p) throws Exception {
        cat.debug(">PKCS12SigningDevice()");
        // Get env variables and read in nessecary data
        KeyStore keyStore=KeyStore.getInstance("PKCS12", "BC");
        String keyStoreFile = p.getProperty("keyStore");
        if (keyStoreFile == null)
            throw new IllegalArgumentException("Missing keyStore property.");
        cat.debug("keystore:" + keyStoreFile);
        InputStream is = new FileInputStream(keyStoreFile);
        String keyStorePass = p.getProperty("keyStorePass");
        if (keyStorePass == null)
            throw new IllegalArgumentException("Missing keyStorePass property.");
        //char[] keyStorePass = getPassword("java:comp/env/keyStorePass");
        cat.debug("keystorepass: " + keyStorePass);
        keyStore.load(is, keyStorePass.toCharArray());
        String privateKeyAlias= p.getProperty("privateKeyAlias");
        if (privateKeyAlias == null)
            throw new IllegalArgumentException("Missing privateKeyAlias property.");
        cat.debug("privateKeyAlias: " + privateKeyAlias);
        String privateKeyPass = p.getProperty("privateKeyPass");
        char[] pkPass;
        if ((privateKeyPass).equals("null"))
            pkPass = null;
        else
            pkPass = privateKeyPass.toCharArray();
        cat.debug("privateKeyPass: " + privateKeyPass);
        privateKey = (PrivateKey)keyStore.getKey(privateKeyAlias, pkPass);
        if (privateKey == null) {
            cat.error("Cannot load key with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
            throw new Exception("Cannot load key with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
        }
        Certificate[] certchain = KeyTools.getCertChain(keyStore, privateKeyAlias);
        if (certchain.length < 1) {
            cat.error("Cannot load certificate chain with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
            throw new Exception("Cannot load certificate chain with alias '"+privateKeyAlias+"' from keystore '"+keyStoreFile+"'");
        }
        // We only support a ca hierarchy with depth 2.
        caCert = (X509Certificate)certchain[0];
        cat.debug("cacertIssuer: " + caCert.getIssuerDN().toString());
        cat.debug("cacertSubject: " + caCert.getSubjectDN().toString());

        // root cert is last cert in chain
        rootCert = (X509Certificate)certchain[certchain.length-1];
        cat.debug("rootcertIssuer: " + rootCert.getIssuerDN().toString());
        cat.debug("rootcertSubject: " + rootCert.getSubjectDN().toString());
        // is root cert selfsigned?
        if (!CertTools.isSelfSigned(rootCert))
            throw new Exception("Root certificate is not self signed!");
        cat.debug("<PKCS12SigningDevice()");
    }

   /** Creates (if needed) the signing device and returns the object.
    * @param prop Arguments needed fo?r the eventual creation of the object
    * @return An instance of the Signing device.
    */
    static public synchronized ISigningDevice instance(Properties prop) throws Exception {
       if(instance == null) {
         instance = new PKCS12SigningDevice(prop);
       }
       return instance;
    }

   /** Returns an array with the certificate chain, the root certificate is last in the chain.
    *
    * @return an array of Certificate
    */
    public Certificate[] getCertificateChain() {
        cat.debug(">getCertificateChain()");
        // TODO: should support more than 2 levels of CAs
        Certificate[] chain;
        if (CertTools.isSelfSigned(caCert)) {
            chain = new Certificate[1];
        } else {
            chain = new Certificate[2];
            chain[1] = rootCert;
        }
        chain[0] = caCert;
        cat.debug("<getCertificateChain()");
        return chain;
    }

   /** Returns the private key (if possible) used for signature creation.
    *
    * @return PrivateKey object
    */
    public PrivateKey getPrivateSignKey() {
        return privateKey;
    }
   /** Returns the public key (if possible) used for signature verification.
    *
    * @return PublicKey object
    */
    public PublicKey getPublicSignKey() {
        return caCert.getPublicKey();
    }

   /** Returns the private key (if possible) used for decryption.
    *
    * @return PrivateKey object
    */
    public PrivateKey getPrivateDecKey() {
        return privateKey;
    }
   /** Returns the public key (if possible) used for encryption.
    *
    * @return PublicKey object
    */
    public PublicKey getPublicEncKey() {
        return caCert.getPublicKey();
    }

    /** Weuse the BouncyCastle provider to sign stuff
     * @return String "BC"
     */
    public String getProvider() {
        return "BC";
    }


}

