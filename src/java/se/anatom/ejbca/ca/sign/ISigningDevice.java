package se.anatom.ejbca.ca.sign;

import java.security.cert.Certificate;
import java.security.PrivateKey;
import java.util.Properties;

/** Handles maintenance of the device producing signatures and handling the private key.
 * Classes implementing this interface should be Singletons, since they will be created
 * using the getINstance() method.
 *
 * @version $Id: ISigningDevice.java,v 1.1 2002-06-07 12:21:34 anatom Exp $
 */
public interface ISigningDevice {

   /** Returns an array with the certificate chain, the root certificate is last in the chain.
    *
    * @return an array of Certificate
    */
    public Certificate[] getCertificateChain();

   /** Returns the private key (if possible) used for signature creation.
    *
    * @return PrivateKey object
    */
    public PrivateKey getPrivateSignKey();
}
