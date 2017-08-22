/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca.internal;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.endentity.ExtendedInformation;

/** Class used to select which request message and public key to use to issue a certificate, by looking
 * at the various input in priority order. 
 * 3. Request inside endEntityInformation has priority over providedPublicKey and providedRequestMessage
 * 2. providedPublicKey has priority over the public key in providedRequestMessage
 * 1. providedRequestMessage and it's public key is used
 * 
 * @version $Id$
 */
public class RequestAndPublicKeySelector {

	/** Class logger. */
    private static final Logger log = Logger.getLogger(RequestAndPublicKeySelector.class);
    
    private PublicKey publicKey;
    private RequestMessage requestMessage;
    /** Constructor taking input needed to make decision on which public key and requets message to use. After construction caller can use the methods
     * {@link #getPublicKey()} and {@link #getRequestMessage()} to retrieve the selected objects.
     * 
     * @param providedRequestMessage
     * @param providedPublicKey
     * @param endEntityInformation
     */
    public RequestAndPublicKeySelector(final RequestMessage providedRequestMessage, final PublicKey providedPublicKey, final ExtendedInformation endEntityInformation) {
        requestMessage = providedRequestMessage; //The request message was provided outside of endEntityInformation
        String debugPublicKeySource = null;
        String debugRequestMessageSource = null;
        if (providedRequestMessage != null){
            try {
                publicKey = providedRequestMessage.getRequestPublicKey();
                debugPublicKeySource = "from providedRequestMessage";
                debugRequestMessageSource = "from providedRequestMessage";
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e1) {
                //Fine since public key can be provided with providedPublicKey or endEntityInformation.extendedInformation.certificateRequest
            }
        }
        //ProvidedPublicKey has priority over providedRequestMessage.requestPublicKey
        if (providedPublicKey != null){
            publicKey = providedPublicKey;
            debugPublicKeySource = "separately";
        }
        //Request inside endEntityInformation has priority over providedPublicKey and providedRequestMessage
        if (endEntityInformation != null && endEntityInformation.getCertificateRequest() != null){
            requestMessage = RequestMessageUtils.genPKCS10RequestMessage(endEntityInformation.getCertificateRequest());
            try {
                publicKey = requestMessage.getRequestPublicKey();
                debugPublicKeySource = "from endEntity.extendedInformaion.certificateRequest";
                debugRequestMessageSource = "from endEntity.extendedInformaion.certificateRequest";
            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Error occured with extracting public key from endEntityInformation.extendedInformation. Proceeding with one provided separately", e);
                }
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Public key is provided " + debugPublicKeySource);
            log.debug("Request is provided " + debugRequestMessageSource);
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public RequestMessage getRequestMessage() {
        return requestMessage;
    }
}
