package se.anatom.ejbca.protocol;

import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;

import org.apache.log4j.*;

/** Base interface for request messages sent to the CA. 
* Implementors of this interface must also implement Serializable if they are to be sent to any EJB bussiness methods.
*  
* @version  $Id$
*/
public interface  RequestMessage {

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
}
