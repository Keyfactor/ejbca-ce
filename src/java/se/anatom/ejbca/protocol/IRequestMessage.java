package se.anatom.ejbca.protocol;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/** Base interface for request messages sent to the CA.
* Implementors of this interface must also implement Serializable if they are to be sent to any EJB bussiness methods.
*
* @version  $Id: IRequestMessage.java,v 1.2 2003-01-29 16:15:59 anatom Exp $
*/
public interface  IRequestMessage {

    /** Get the public key from a certification request.
     * @return The public key from a certification request.
     * @throws InvalidKeyException If the key is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the key uses an unhandled algorithm.
     */
    public PublicKey getRequestPublicKey() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;
    /** Verifies signatures, popo etc on the request message.
     * If verification fails the request should be considered invalid.
     * @return True if verification was succesful, false if it failed.
     * @throws InvalidKeyException If the key used for verification is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled algorithm.
     */
    public boolean verify() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;
    /** indicates if this message needs recipients public and private key to verify, decrypt etc.
     * If this returns true, setKeyInfo() should be called.
     * @return True if public and private key is needed.
     */
    public boolean requireKeyInfo();
    /** Sets the public and private key needed to decrypt/verify the message. Must be set if requireKeyInfo() returns true.
     * @see #requireKeyInfo()
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     */
    public void setKeyInfo(X509Certificate cert, PrivateKey key);
}
