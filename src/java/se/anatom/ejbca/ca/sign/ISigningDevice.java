package se.anatom.ejbca.ca.sign;

import java.security.cert.Certificate;
import java.security.PrivateKey;

/** Handles maintenance of the device producing signatures and handling the private key.
 * Classes implementing this interface should be Singletons, since they will be created
 * using the getInstance() method.
 *
 *
 * @version $Id: ISigningDevice.java,v 1.3 2002-08-20 12:17:11 anatom Exp $
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

    /** Returns the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
    public String getProvider();
}
