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
package org.cesecore.authentication.oauth;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.Random;

import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;

/**
 * Represents an OAuth Public Key entry
 *
 * @version $Id$
 */
public final class OAuthKeyInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    private final int internalId;
    private byte[] publicKeyBytes;
    private String keyIdentifier;
    private int skewLimit = 60000;

    private transient PublicKey publicKey;

    private static final Random random = new Random();

    /**
     * Creates a OAuth Key info object, but does not parse the public key yet
     * (so it can be created from static blocks etc.)
     *
     * @param keyIdentifier  Key identifier
     * @param publicKeyBytes  The ASN1 encoded public key.
     */
    public OAuthKeyInfo(final String keyIdentifier, final byte[] publicKeyBytes, final int skewLimit) {
        this.internalId = random.nextInt();
        this.keyIdentifier = keyIdentifier;
        if (publicKeyBytes == null) {
            throw new IllegalArgumentException("publicKeyBytes is null");
        }
        this.publicKeyBytes = publicKeyBytes.clone();
        this.skewLimit = skewLimit;
    }

    private void ensureParsed() {
        if (publicKey == null) {
            publicKey = KeyTools.getPublicKeyFromBytes(publicKeyBytes);
            if (publicKey == null) {
                throw new IllegalStateException("Failed to parse key");
            }
        }
    }

    /** @return Internal Id*/
    public int getInternalId() {
        return internalId;
    }

    public PublicKey getOauthPublicKey() {
        ensureParsed();
        return publicKey;
    }

    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }

    public void setOauthPublicKey(final byte[] publicKeyBytes) {
        this.publicKey = null;
        this.publicKeyBytes = publicKeyBytes;
    }

    /** @return OAuth Public Key fingerprint */
    public String getKeyFingerprint() {
        try {
            ensureParsed();
            final byte[] fingerprint = CertTools.generateSHA256Fingerprint(publicKey.getEncoded());
            return Base64.toBase64String(fingerprint);
        } catch (Exception e) {
            return e.getLocalizedMessage();
        }
    }

    public int getSkewLimit() {
        return skewLimit;
    }

    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(final String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }

    public void setSkewLimit(final int skewLimit) {
        if (skewLimit < 0) {
            throw new IllegalArgumentException("Skew limit value is negative");
        }
        this.skewLimit = skewLimit;
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || o.getClass() != OAuthKeyInfo.class) {
            return false;
        }

        final OAuthKeyInfo oauthKeyInfo = (OAuthKeyInfo) o;
        return internalId == oauthKeyInfo.getInternalId() &&
                keyIdentifier.equals(oauthKeyInfo.getKeyIdentifier());
    }

    @Override
    public int hashCode() {
        return internalId + (keyIdentifier.hashCode() * 4711);
    }

    @Override
    public String toString() {
        return getKeyIdentifier();
    }
}
