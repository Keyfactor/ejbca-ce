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

import java.io.IOException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Base interface for response messages sent from the CA. Implementors of this interface must also
 * implement Serializable if they are to be sent to any EJB bussiness methods. 
 * Example: <code>
 * ResponseMessage resp = new ResponseMessage(); 
 * resp.setCertificate(cert); resp.setStatus(OK); 
 * if (resp.requireSignKeyInfo()) { 
 *     resp.setSignKeyInfo(signcert,signkey) 
 * }; 
 * if (resp.requireEncKeyInfo()) { 
 *     resp.setEncKeyInfo(enccert,enckey) 
 * }; 
 * resp.create(); 
 * byte[] responseMessage = resp.getResponseMessage(); 
 * </code>
 *
 * @version $Id: IResponseMessage.java,v 1.12 2004-04-16 07:38:55 anatom Exp $
 */
public interface IResponseMessage {

    /**
     * Sets the complete certificate in the response message.
     *
     * @param cert certificate in the response message.
     */
    public void setCertificate(Certificate cert);

    /**
     * Gets the response message in the default encoding format.
     *
     * @return the response message in the default encoding format.
     */
    public byte[] getResponseMessage() throws IOException, CertificateEncodingException;

    /**
     * Sets the status of the response message.
     *
     * @param status status of the response.
     */
    public void setStatus(ResponseStatus status);

    /**
     * Gets the status of the response message.
     *
     * @return status status of the response.
     */
    public ResponseStatus getStatus();

    /**
     * Sets info about reason for failure.
     *
     * @param failInfo reason for failure.
     */
    public void setFailInfo(FailInfo failInfo);

    /**
     * Gets info about reason for failure.
     *
     * @return failInfo reason for failure.
     */
    public FailInfo getFailInfo();

    /**
     * Create encrypts and creates signatures as needed to produce a complete response message.  If
     * needed setSignKeyInfo and setEncKeyInfo must be called before this method. After this is
     * called the response message can be retrieved with getResponseMessage();
     *
     * @return True if signature/encryption was successful, false if it failed, request should not
     *         be sent back i failed.
     *
     * @throws IOException If input/output or encoding failed.
     * @throws InvalidKeyException If the key used for signing/encryption is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled
     *         algorithm.
     *
     * @see #setSignKeyInfo
     * @see #setEncKeyInfo
     */
    public boolean create()
        throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * indicates if this message needs recipients public and private key to sign. If this returns
     * true, setSignKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireSignKeyInfo();

    /**
     * indicates if this message needs recipients public and private key to encrypt. If this
     * returns true, setEncKeyInfo() should be called.
     *
     * @return True if public and private key is needed.
     */
    public boolean requireEncKeyInfo();

    /**
     * Sets the public and private key needed to sign the message. Must be set if
     * requireSignKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     *
     * @see #requireSignKeyInfo()
     */
    public void setSignKeyInfo(X509Certificate cert, PrivateKey key);

    /**
     * Sets the public and private key needed to encrypt the message. Must be set if
     * requireEncKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     *
     * @see #requireEncKeyInfo()
     */
    public void setEncKeyInfo(X509Certificate cert, PrivateKey key);

    /**
     * Sets a senderNonce if it should be present in the response
     *
     * @param senderNonce a string of base64 encoded bytes
     */
    public void setSenderNonce(String senderNonce);

    /**
     * Sets a recipient if it should be present in the response
     *
     * @param recipientNonce a string of base64 encoded bytes
     */
    public void setRecipientNonce(String recipientNonce);

    /**
     * Sets a transaction identifier if it should be present in the response
     *
     * @param transactionId transaction id
     */
    public void setTransactionId(String transactionId);

    /**
     * Sets recipient key info, key id or similar. This is usually the request key info from the request message.
     *
     * @param recipientKeyInfo key info
     */
    public void setRecipientKeyInfo(byte[] recipientKeyInfo);
}
