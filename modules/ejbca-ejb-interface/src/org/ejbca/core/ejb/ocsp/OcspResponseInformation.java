/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.ocsp;

import java.io.IOException;
import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;

/**
 * Data carrier that wraps the contents of an OCSPResp, since OCSPResp and many of its members aren't serializable.
 */
public class OcspResponseInformation implements Serializable {

    private static final long serialVersionUID = -4177593916232755218L;
    private static final Logger log = Logger.getLogger(OcspResponseInformation.class);
    private final byte[] ocspResponse;
    private final int status;
    private final long maxAge;
    private boolean addCacheHeaders = true;
    private boolean explicitNoCache = false;
    private Long nextUpdate = null;
    private Long thisUpdate = null;
    private String responseHeader = null;
    private X509Certificate signerCert = null;

    public OcspResponseInformation(OCSPResp ocspResponse, long maxAge, X509Certificate signerCert) throws OCSPException {
        try {
            this.ocspResponse = ocspResponse.getEncoded();
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IOException caught when encoding ocsp response.", e);
        }
        this.maxAge = maxAge;
        this.signerCert = signerCert;
        this.status = ocspResponse.getStatus();
        /*
         * This may seem like a somewhat odd place to perform the below operations (instead of in the end servlet which demanded 
         * this object), but BouncyCastle (up to 1.47) is  a bit shy about making their classes serializable. This means that 
         * OCSPResp can't be transmitted, neither can many of the objects it contains such as SingleResp. Luckily we only need 
         * these classes for the diagnostic operations performed below, so we can sum up the result in the boolean member 
         * addCacheHeaders.  If BC choose to change their policy, the below code can med moved to a more logical location. 
         *  -mikek
         */
        if (ocspResponse.getResponseObject() == null) {
            if (log.isDebugEnabled()) {
                log.debug("Will not add cache headers for response to bad request.");
            }
            addCacheHeaders = false;
        } else {
            final BasicOCSPResp basicOCSPResp = (BasicOCSPResp)ocspResponse.getResponseObject();
            final SingleResp[] singleResponses = basicOCSPResp.getResponses();
            if (singleResponses.length != 1) {
                if (log.isDebugEnabled()) {
                    log.debug("Will not add RFC 5019 cache headers: reponse contains multiple embedded responses.");
                }
                addCacheHeaders = false;
            } else if (singleResponses[0].getNextUpdate() == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Will not add RFC 5019 cache headers: nextUpdate isn't set.");
                }
                addCacheHeaders = false;
            } else if (basicOCSPResp.hasExtensions() && basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce) != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Will not add RFC 5019 cache headers: response contains a nonce.");
                }
                addCacheHeaders = false;
            } else {
                nextUpdate = singleResponses[0].getNextUpdate().getTime();
                thisUpdate = singleResponses[0].getThisUpdate().getTime();
                try {
                    responseHeader = new String(Hex.encode(MessageDigest.getInstance("SHA-1", BouncyCastleProvider.PROVIDER_NAME).digest(this.ocspResponse)));
                } catch (NoSuchProviderException e) {
                    throw new OcspFailureException("Bouncycastle was not available as a provider", e);
                } catch (NoSuchAlgorithmException e) {
                    throw new OcspFailureException("SHA-1 was not an available algorithm for MessageDigester", e);
                }
            }
            if (addCacheHeaders && singleResponses[0].getCertStatus() instanceof UnknownStatus) {
                explicitNoCache = true;
            }
        }
    }

    public byte[] getOcspResponse() {
        return ocspResponse;
    }

    /**
     * @return duration in milliseconds how long the reponse should be cacheable
     */
    public long getMaxAge() {
        return maxAge;
    }

    public boolean shouldAddCacheHeaders() {
        return addCacheHeaders;
    }

    /**
     * @return Date.getTime() long value for nextUpdate time
     */
    public long getNextUpdate() {
        return nextUpdate;
    }

    /**
     * @return Date.getTime() long value for thisUpdate time
     */
    public long getThisUpdate() {
        return thisUpdate;
    }

    public String getResponseHeader() {
        return responseHeader;
    }

    /** @return true if we explicitly should state that the response should not be cached. */
    public boolean isExplicitNoCache() {
        return explicitNoCache;
    }

    public X509Certificate getSignerCert() {
        return signerCert;
    }

    /** @return one of OCSPResp.SUCCESSFUL... */
    public int getStatus() {
        return status;
    }
}
