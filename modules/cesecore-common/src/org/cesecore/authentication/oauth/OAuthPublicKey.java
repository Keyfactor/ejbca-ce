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

import org.bouncycastle.util.encoders.Base64;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.KeyTools;

import java.io.Serializable;
import java.security.PublicKey;

public class OAuthPublicKey implements Serializable {
    private static final long serialVersionUID = 1L;

    private byte[] publicKeyBytes;
    private String keyIdentifier;
    private transient PublicKey publicKey;

    public OAuthPublicKey(byte[] publicKeyBytes, String keyIdentifier) {
        this.publicKeyBytes = publicKeyBytes.clone();
        this.keyIdentifier = keyIdentifier;
    }

    private void ensureParsed() {
        if (publicKey == null) {
            publicKey = KeyTools.getPublicKeyFromBytes(publicKeyBytes);
            if (publicKey == null) {
                throw new IllegalStateException("Failed to parse key");
            }
        }
    }

    public PublicKey getOauthPublicKey() {
        ensureParsed();
        return publicKey;
    }


    public byte[] getPublicKeyBytes() {
        return publicKeyBytes;
    }

    public void setPublicKeyBytes(final byte[] publicKeyBytes) {
        this.publicKey = null;
        this.publicKeyBytes = publicKeyBytes;
    }

    /**
     * @return OAuth Public Key fingerprint
     */
    public String getKeyFingerprint() {
        try {
            ensureParsed();
            final byte[] fingerprint = CertTools.generateSHA256Fingerprint(publicKey.getEncoded());
            return Base64.toBase64String(fingerprint);
        } catch (Exception e) {
            return e.getLocalizedMessage();
        }
    }

    public String getKeyIdentifier() {
        return keyIdentifier;
    }

    public void setKeyIdentifier(final String keyIdentifier) {
        this.keyIdentifier = keyIdentifier;
    }
}
