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
 
package se.anatom.ejbca.protocol;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;


/**
 * Base interface for request messages sent to the CA. Implementors of this interface must also
 * implement Serializable if they are to be sent to any EJB bussiness methods.
 *
 * @version $Id: IRequestMessage.java,v 1.12 2004-04-16 07:38:55 anatom Exp $
 */
public interface IRequestMessage {
    /**
     * Get the username used to request a certificate from EJBCA.
     *
     * @return The username from the certification request.
     */
    public String getUsername();

    /**
     * Get the password used to request a certificate from EJBCA.
     *
     * @return The password from the certification request.
     */
    public String getPassword();

    /**
     * Gets the issuer DN if contained in the request (the CA the request is targeted at).
     *
     * @return issuerDN of receiving CA or null.
     */
    public String getIssuerDN();
    
    /**
     * Get the public key from a certification request.
     *
     * @return The public key from a certification request.
     *
     * @throws InvalidKeyException If the key is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the key uses an unhandled algorithm.
     */
    public PublicKey getRequestPublicKey()
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * Verifies signatures, popo etc on the request message. If verification fails the request
     * should be considered invalid.
     *
     * @return True if verification was successful, false if it failed.
     *
     * @throws InvalidKeyException If the key used for verification is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled
     *         algorithm.
     */
    public boolean verify()
        throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * indicates if this message needs recipients public and private key to verify, decrypt etc. If
     * this returns true, setKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireKeyInfo();

    /**
     * Sets the public and private key needed to decrypt/verify the message. Must be set if
     * requireKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     *
     * @see #requireKeyInfo()
     */
    public void setKeyInfo(X509Certificate cert, PrivateKey key);

    /**
     * Returns an error number after an error has occured processing the request
     *
     * @return class specific error number
     */
    public int getErrorNo();

    /**
     * Returns an error message after an error has occured processing the request
     *
     * @return class specific error message
     */
    public String getErrorText();

    /**
     * Returns a senderNonce if present in the request
     *
     * @return senderNonce as a string of base64 encoded bytes
     */
    public String getSenderNonce();

    /**
     * Returns a transaction identifier if present in the request
     *
     * @return transaction id
     */
    public String getTransactionId();

    /**
     * Returns requesters key info, key id or similar
     *
     * @return request key info
     */
    public byte[] getRequestKeyInfo();
}
