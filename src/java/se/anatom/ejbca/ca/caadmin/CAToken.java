package se.anatom.ejbca.ca.caadmin;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import se.anatom.ejbca.util.UpgradeableDataHashMap;

/** Handles maintenance of the device producing signatures and handling the private key.
 * 
 * @version $Id: CAToken.java,v 1.2 2004-01-25 09:37:11 herrvendil Exp $
 */
public abstract class CAToken extends UpgradeableDataHashMap implements java.io.Serializable{
    
    public static final String CATOKENTYPE = "catokentype";
    
    protected static final String SIGNATUREALGORITHM = "signaturealgorithm";
   /**
    *  Returns information about this CAToken.
    */
    public abstract CATokenInfo getCATokenInfo();  
    
   /**
    * Updates the CAToken data saved in database.
    */
    public abstract void updateCATokenInfo(CATokenInfo catokeninfo);
      
    
   /** Returns the private key (if possible) used for signature creation.
    *
    * @return PrivateKey object
    */
    public abstract PrivateKey getPrivateSignKey();

   /** Returns the public key (if possible) used for signature verification.
    *
    * @return PublicKey object
    */
    public abstract PublicKey getPublicSignKey();

   /** Returns the private key (if possible) used for decryption.
    *
    * @return PrivateKey object
    */
    public abstract PrivateKey getPrivateDecKey();

   /** Returns the public key (if possible) used for encryption.
    *
    * @return PublicKey object
    */
    public abstract PublicKey getPublicEncKey();

    /** Returns a certificate with the public key (if possible) used for encryption.
     *
     * @return Certificate object
     */
    public abstract Certificate getEncCert();
    
    
    
    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public abstract String getProvider();

    
}
