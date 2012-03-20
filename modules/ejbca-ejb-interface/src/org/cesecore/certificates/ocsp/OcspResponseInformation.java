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
package org.cesecore.certificates.ocsp;

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;

/**
 * Data carrier that wraps the contents of an OCSPResp, since OCSPResp and many of its members aren't serializable. 
 * 
 * @version $Id$
 *
 */
public class OcspResponseInformation implements Serializable {

    private static final long serialVersionUID = -4177593916232755218L;
    private static final Logger log = Logger.getLogger(OcspResponseInformation.class);
    private final byte[] ocspResponse;
    private final long maxAge;
    private boolean addCacheHeaders = true;
    private Long nextUpdate = null;
    private Long thisUpdate = null;
    private String responseHeader = null;

    public OcspResponseInformation(OCSPResp ocspResponse, long maxAge) throws OCSPException, IOException {
        this.ocspResponse = ocspResponse.getEncoded();
        this.maxAge = maxAge;
        /*
         * This may seem like a somewhat odd place to perform the below operations (instead of in the end servlet which demanded 
         * this object), but BouncyCastle (up to 1.47) is  a bit shy about making their classes serializable. This means that 
         * OCSPResp can't be transmitted, neither can many of the objects it contains such as SingleResp. Luckily we only need 
         * these classes for the diagnostic operations performed below, so we can sum up the result in the boolean member 
         * addCacheHeaders.  If BC choose to change their policy, the below code can med moved to a more logical location. 
         *  -mikek
         */
        if (ocspResponse.getResponseObject() == null) {
            log.debug("Will not add cache headers for response to bad request.");
            addCacheHeaders = false;
        } else {
            SingleResp[] singleRespones = ((BasicOCSPResp) ocspResponse.getResponseObject()).getResponses();
            if (singleRespones.length != 1) {
                log.debug("Will not add RFC 5019 cache headers: reponse contains multiple embedded responses.");
                addCacheHeaders = false;
            } else if (singleRespones[0].getNextUpdate() == null) {
                log.debug("Will not add RFC 5019 cache headers: nextUpdate isn't set.");
                addCacheHeaders = false;
            } else if (singleRespones[0].getSingleExtensions() != null
                    && singleRespones[0].getSingleExtensions().getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce) == null) {
                log.debug("Will not add RFC 5019 cache headers: response contains a nonce.");
                addCacheHeaders = false;
            } else {
                nextUpdate = singleRespones[0].getNextUpdate().getTime();
                thisUpdate = singleRespones[0].getThisUpdate().getTime();
                try {
                    responseHeader = new String(Hex.encode(MessageDigest.getInstance("SHA-1", "BC").digest(ocspResponse.getEncoded())));
                } catch (NoSuchProviderException e) {
                    throw new OcspFailureException("Bouncycastle was nor available as a provider", e);
                } catch (NoSuchAlgorithmException e) {
                    throw new OcspFailureException("SHA-1 was not an available algorithm for MessageDigester", e);
                }
            }
        }
    }

    public byte[] getOcspResponse() {
        return ocspResponse;
    }

    public long getMaxAge() {
        return maxAge;
    }

    public boolean shouldAddCacheHeaders() {
        return addCacheHeaders;
    }

    public long getNextUpdate() {
        return nextUpdate;
    }

    public long getThisUpdate() {
        return thisUpdate;
    }

    public String getResponseHeader() {
        return responseHeader;
    }

}
