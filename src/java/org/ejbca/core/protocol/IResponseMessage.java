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

package org.ejbca.core.protocol;

import java.io.IOException;
import java.io.Serializable;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CRL;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;

import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ra.NotFoundException;

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
 * @version $Id$
 */
public interface IResponseMessage extends Serializable {

    /**
     * Sets the complete certificate in the response message.
     *
     * @param cert certificate in the response message.
     */
    public void setCertificate(Certificate cert);

    /**
     * Sets the CRL (if present) in the response message.
     *
     * @param crl crl in the response message.
     */
    public void setCrl(CRL crl);
    
    /** 
     * Determines if the CA certificate should be included in the response message, if
     * applicable for the response message type.
     * 
     * @param includeCACert true or false
     */
    public void setIncludeCACert(boolean incCACert);

    /** 
     * Explicitly sets the CA certificate if it is not the same as the signer certificate. Used if
     * IncludeCACert is set to true and the CA certificate is not the same as the signer certificate.
     * 
     * @param caCert a Certificate
     */
    public void setCACert(Certificate caCert);

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
     * Sets clear text info about reason for failure.
     *
     * @param failText description about failure.
     */
    public void setFailText(String failText);

    /**
     * Gets clear text info about reason for failure.
     *
     * @return failText description about failure.
     */
    public String getFailText();

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
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignRequestException, NotFoundException;

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
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     *
     * @see #requireSignKeyInfo()
     */
    public void setSignKeyInfo(Certificate cert, PrivateKey key, String provider);

    /**
     * Sets the public and private key needed to encrypt the message. Must be set if
     * requireEncKeyInfo() returns true.
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     *
     * @see #requireEncKeyInfo()
     */
    public void setEncKeyInfo(Certificate cert, PrivateKey key, String provider);

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
    
    /**
     * Sets preferred digest algorithm for the response message, if applicable. 
     * If this is not called, a default is used.
     * 
     * @param String oid of digest algorithm ex CMSSignedDataGenerator.MD5, SHA1, SHA256 etc
     */
    public void setPreferredDigestAlg(String digest);
    
    /** Sometimes (CMP) the response identifier sent depends on which request identifier was used, 
     * even if the messages themselves are the same mesages.
     * 
     * @param reqtype which type of request message this response is in response to
     */ 
    public void setRequestType(int reqtype);
    
    /**
     * For some types of request-responses there is a need for a requetsId to match the request and the
     * response together.
     * @param reqId the id from the request matching to this response
     */
    public void setRequestId(int reqid);
    
    /**
     * For some types of requests, the protection used depends on parameters from the request,
     * for example password based protection where algorithms, keyId etc is the same in the response as in the request
     * @param IRequestMessage the request from where to pick protection parameters
     */
    public void setProtectionParamsFromRequest(IRequestMessage reqMsg);
}
