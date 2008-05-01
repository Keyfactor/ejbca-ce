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

import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Random;

import org.apache.log4j.Logger;
import org.ejbca.util.Base64;



/**
 * Utility class to gather a few functions
 *
 * @version $Id$
 */
public class RequestMessageUtils {
    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
    static final long serialVersionUID = 3597275157018205138L;

    private static final Logger log = Logger.getLogger(RequestMessageUtils.class);

    public static IResponseMessage createResponseMessage(Class responseClass, IRequestMessage req, Certificate cert, PrivateKey signPriv, PrivateKey encPriv, String provider){
    	IResponseMessage ret = null;
    	// Create the response message and set all required fields
    	try {
    		ret = (IResponseMessage) responseClass.newInstance();
    	} catch (InstantiationException e) {
    		//TODO : do something with these exceptions
    		log.error("Error creating response message", e);
    		return null;
    	} catch (IllegalAccessException e) {
    		log.error("Error creating response message", e);
    		return null;
    	}
    	if (ret.requireSignKeyInfo()) {
    		ret.setSignKeyInfo((X509Certificate) cert, signPriv, provider);
    	}
    	if (ret.requireEncKeyInfo()) {
    		ret.setEncKeyInfo((X509Certificate) cert, encPriv, provider);
    	}
    	if (req.getSenderNonce() != null) {
    		ret.setRecipientNonce(req.getSenderNonce());
    	}
    	if (req.getTransactionId() != null) {
    		ret.setTransactionId(req.getTransactionId());
    	}
    	// Sendernonce is a random number
    	byte[] senderNonce = new byte[16];
        Random randomSource = new Random();
    	randomSource.nextBytes(senderNonce);
    	ret.setSenderNonce(new String(Base64.encode(senderNonce)));
    	// If we have a specified request key info, use it in the reply
    	if (req.getRequestKeyInfo() != null) {
    		ret.setRecipientKeyInfo(req.getRequestKeyInfo());
    	}
    	// Which digest algorithm to use to create the response, if applicable
    	ret.setPreferredDigestAlg(req.getPreferredDigestAlg());
    	// Include the CA cert or not in the response, if applicable for the response type
    	ret.setIncludeCACert(req.includeCACert());
    	// Hint to the response which request type it is in response to
    	ret.setRequestType(req.getRequestType());
    	ret.setRequestId(req.getRequestId());
    	// If there is some protection parameters we need to lift over from the request message, the request and response knows about it
    	ret.setProtectionParamsFromRequest(req);
    	return ret;
    }


}
