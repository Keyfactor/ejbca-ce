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

import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.util.KeyTools;

/**
 * Represents a Certificate Transparency log
 * 
 * @version $Id$
 */
public final class CTLogInfo implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final int logId;
    private final byte[] publicKeyBytes;
    private final String url;
    private int timeout = 5000; // milliseconds
    
    private transient PublicKey publicKey;
    
    /**
     * Creates a CT log info object, but does not parse the public key yet
     * (so it can be created from static blocks etc.)
     */
    public CTLogInfo(final String url, final byte[] publicKeyBytes) {
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
                throw new RuntimeException("Failed to parse key");
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

}
