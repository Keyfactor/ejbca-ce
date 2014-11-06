/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.certificate.request;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x500.X500Name;


/**
 * Base interface for request messages sent to the CA. Implementors of this interface must also
 * implement Serializable if they are to be sent to any EJB business methods.
 *
 * @version $Id$
 */
public interface RequestMessage extends Serializable {
    /**
     * Get the username used to request a certificate from EJBCA.
     *
     * @return The username from the certification request.
     */
    String getUsername();

    /**
     * Get the password used to request a certificate from EJBCA.
     *
     * @return The password from the certification request.
     */
    String getPassword();

    /**
     * Gets the issuer DN if contained in the request (the CA the request is targeted at).
     *
     * @return issuerDN of receiving CA or null.
     */
    String getIssuerDN();

    /**
     * Gets the number (of CA cert) from IssuerAndSerialNumber. Combined with getIssuerDN to identify
     * the CA-certificate of the CA the request is targeted for.
     *
     * @return serial number of CA certificate for CA issuing CRL or null.
     */
    BigInteger getSerialNo();
    
    /**
     * Gets the requested DN if contained in the request (the desired DN for the user).
     *
     * @return requested DN or null.
     */
    String getRequestDN();

    /**
     * Gets the requested DN in the pure form of an X508Name (the desired DN for the user).
     *
     * @return requested DN or null.
     */
    X500Name getRequestX500Name();

    /**
     * Gets the requested altNames if contained in the request (the desired altNames for the user).
     *
     * @return requested altNames or null.
     */
    String getRequestAltNames();
    
    /**
     * Gets a validity date from the request, if the request contains a desired validity.
     * The requested validity may, or may not be used, it depends if allowValidityOverride is set in 
     * the certificate profile.
     * 
     * @return A date now or in the future for notBefore validity in the certificate, or null if no desired validity is in the certificate.
     */
	Date getRequestValidityNotBefore();
	
    /**
     * Gets a validity date from the request, if the request contains a desired validity.
     * The requested validity may, or may not be used, it depends if allowValidityOverride is set in 
     * the certificate profile.
     * 
     * @return A date in the future for notAfter validity in the certificate, or null if no desired validity is in the certificate.
     */
	Date getRequestValidityNotAfter();

	/** 
	 * Gets any requested extensions, if the request message type is able to contain request extensions
	 * and if there are any. Requested extensions are (currently) in the form of X509Extensions.
	 * 
	 * @return X509Extensions or null
	 */
	Extensions getRequestExtensions();

    /**
     * Gets the issuer DN (of CA cert) from IssuerAndSerialNumber when this is a CRL request.
     *
     * @return issuerDN of CA issuing CRL or null.
     */
    String getCRLIssuerDN();

    /**
     * Gets the number (of CA cert) from IssuerAndSerialNumber when this is a CRL request.
     *
     * @return serial number of CA certificate for CA issuing CRL or null.
     */
    BigInteger getCRLSerialNo();

    /**
     * Get the key from a certification request.
     *
     * @return The key from a certification request. Returns null if request content hasn't been set.
     *
     * @throws InvalidKeyException If the key is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the key uses an unhandled algorithm.
     */
    PublicKey getRequestPublicKey()
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * Verifies signatures, popo etc on the request message. If verification fails the request
     * should be considered invalid.
     *
     * @return true if verification was successful, false if it failed.
     *
     * @throws InvalidKeyException If the key used for verification is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled
     *         algorithm.
     */
    boolean verify()
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;

    /**
     * indicates if this message needs recipients and private key to verify, decrypt etc. If
     * this returns true, setKeyInfo() should be called.
     *
     * @return True if and private key is needed.
     */
    boolean requireKeyInfo();

    /**
     * Sets the and private key needed to decrypt/verify the message. Must be set if
     * requireKeyInfo() returns true.
     *
     * @param cert certificate containing the key.
     * @param key private key.
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     *
     * @see #requireKeyInfo()
     */
    void setKeyInfo(Certificate cert, PrivateKey key, String provider);

    /**
     * Returns an error number after an error has occurred processing the request
     *
     * @return class specific error number
     */
    int getErrorNo();

    /**
     * Returns an error message after an error has occurred processing the request
     *
     * @return class specific error message
     */
    String getErrorText();

    /**
     * Returns a senderNonce if present in the request
     *
     * @return senderNonce as a string of base64 encoded bytes
     */
    String getSenderNonce();

    /**
     * Returns a transaction identifier if present in the request
     *
     * @return transaction id
     */
    String getTransactionId();

    /**
     * Returns requesters key info, key id or similar
     *
     * @return request key info
     */
    byte[] getRequestKeyInfo();
    
    /**
     * Returns the name of the preferred Digest algorithm to be used in the response if applicable.
     * Defaults to CMSSignedGenerator.DIGEST_SHA1 for normal messages.
     *  
     * @return oid of digest algorithm ex CMSSignedGenerator.DIGEST_SHA1, SHA256 etc
     */
    String getPreferredDigestAlg(); 
    
    
    /** If the CA certificate should be included in the response or not, default to true = yes.
     * Not applicable for all request/response types.
     * 
     * @return true or false
     */
    boolean includeCACert();

    /** Sometimes (CMP) the response identifier sent depends on which request identifier was used, 
     * even if the messages themselves are the same messages.
     * 
     * @param reqtype which type of request message this response is in response to
     */ 
    int getRequestType();
    
    /**
     * For some types of request-responses there is a need for a requestId to match the request and the
     * response together.
     * @param reqId the id from the request matching to this response
     */
    int getRequestId();
    
    /**
     * Sets the private key needed to create a response message.
     *
     * @param key private key.
     * @param provider the provider to use, if the private key is on a HSM you must use a special provider. If null is given, the default BC provider is used.
     */
    void setResponseKeyInfo(PrivateKey key, String provider);
    
}
