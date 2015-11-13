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
package org.cesecore.certificates.certificatetransparency;

import java.io.Serializable;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.util.KeyTools;

/**
 * Represents a Certificate Transparency log
 * 
 * @version $Id$
 */
public final class CTLogInfo implements Serializable {

    private static final Logger log = Logger.getLogger(CTLogInfo.class);
    private static final long serialVersionUID = 1L;
    
    private final int logId;
    private final byte[] publicKeyBytes;
    private final String url; // base URL, without "add-chain" or "add-pre-chain"
    private int timeout = 5000; // milliseconds
    
    private transient PublicKey publicKey;
    
    /**
     * Creates a CT log info object, but does not parse the public key yet
     * (so it can be created from static blocks etc.)
     * 
     * @param url  Base URL to the log. The CT log library will automatically append
     *        the strings "add-chain" or "add-pre-chain" depending on whether
     *        EJBCA is submitting a pre-certificate or a regular certificate.
     * @param publicKeyBytes  The ASN1 encoded public key of the log.
     */
    public CTLogInfo(final String url, final byte[] publicKeyBytes) {
        if (!url.endsWith("/")) {
            log.error("CT Log URL must end with a slash. URL: "+url); // EJBCA 6.4 didn't enforce this due to a regression 
        }
        if (!url.endsWith("/ct/v1/")) {
            log.warn("CT Log URL should end with /ct/v1/. URL: "+url);
        }
        this.logId = url.hashCode();
        this.url = url;
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("publicKeyBytes is null");
        }
        this.publicKeyBytes = publicKeyBytes.clone();
    }
    
    private void ensureParsed() {
        if (publicKey == null) {
            publicKey = KeyTools.getPublicKeyFromBytes(publicKeyBytes);
            if (publicKey == null) {
                throw new IllegalStateException("Failed to parse key");
            }
        }
    }

    /** @return Internal Id consisting of the hashcode of the URL */
    public int getLogId() {
        return logId;
    }

    public PublicKey getLogPublicKey() {
        ensureParsed();
        return publicKey;
    }
    
    /** @return Log Key ID as specified by the RFC, in human-readable format */
    public String getLogKeyIdString() {
        try {
            ensureParsed();
            final MessageDigest md = MessageDigest.getInstance("SHA256");
            final byte[] keyId = md.digest(publicKey.getEncoded());
            return new String(Hex.encode(keyId)).substring(0, 8).toUpperCase();
        } catch (NoSuchAlgorithmException e) {
            // Should not happen, but not critical.
            return "";
        } catch (Exception e) {
            return e.getLocalizedMessage();
        }
    }

    public String getUrl() {
        return url;
    }
    
    public int getTimeout() {
        return timeout;
    }
    
    public void setTimeout(final int timeout) {
        this.timeout = timeout;
    }
    
    /** Makes sure that a URL ends with /ct/v1/ */
    public static String fixUrl(final String urlToFix) {
        String url = (urlToFix.endsWith("/") ? urlToFix : urlToFix + "/");
        if (!url.endsWith("/ct/v1/")) {
            if (!url.endsWith("/ct/")) {
                url = url + "ct/v1/";
            } else {
                url = url + "v1/";
            }
        }
        return url;
    }

}
