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
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;

/**
 * Represents an OAuth Public Key entry
 *
 */
public final class OAuthKeyInfo implements Serializable {
    private static final long serialVersionUID = 1L;

    private Map<String, OAuthPublicKey> keys = new LinkedHashMap<>();
    private String label;
    private String client;
    private String realm;
    private String url;
    private String clientSecret;
    private int skewLimit = 60000;


    /**
     * Creates a OAuth Key info object
     *
     * @param label  Provider label
     * @param skewLimit  skew limit.
     */
    public OAuthKeyInfo(final String label, final int skewLimit) {
        if (label == null) {
            throw new IllegalArgumentException("label is null");
        }
        this.label = label;
        this.skewLimit = skewLimit;
    }

    public int getSkewLimit() {
        return skewLimit;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getClientSecretAndDecrypt() {
        if (clientSecret != null) {
            try {
                return StringTools.pbeDecryptStringWithSha256Aes192(clientSecret);
            } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
                throw new IllegalStateException(e);
            }
        } else {
            return null;
        }
    }

    public void setClientSecretAndEncrypt(String clientSecret) {
        this.clientSecret = StringTools.pbeEncryptStringWithSha256Aes192(clientSecret);
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public Map<String, OAuthPublicKey> getKeys() {
        return keys;
    }

    public void setKeys(Map<String, OAuthPublicKey> keys) {
        this.keys = keys;
    }

    public String getClient() {
        return client;
    }

    public void setClient(String client) {
        this.client = client;
    }

    public String getRealm() {
        return realm;
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public void setSkewLimit(final int skewLimit) {
        if (skewLimit < 0) {
            throw new IllegalArgumentException("Skew limit value is negative");
        }
        this.skewLimit = skewLimit;
    }

    public void addPublicKey(String kid, byte[] bytes) {
        if (keys == null) {
            keys = new LinkedHashMap<>();
        }
        keys.put(kid, new OAuthPublicKey(bytes, kid));
    }

    public Set<String> getAllKeyIdentifiers() {
        if (keys != null) {
            return keys.keySet();
        } else {
            return null;
        }
    }

    public Collection<OAuthPublicKey> getKeyValues() {
        if (keys != null) {
            return keys.values();
        } else {
            return null;
        }
    }

    public void setKeyValues(Collection<OAuthPublicKey> values) {
        if (keys == null) {
            keys = new LinkedHashMap<>();
        }
        for (OAuthPublicKey key : values) {
            keys.put(key.getKeyIdentifier(), key);
        }
    }


    @Override
    public boolean equals(Object o) {
        if (o == null || o.getClass() != OAuthKeyInfo.class) {
            return false;
        }

        final OAuthKeyInfo oauthKeyInfo = (OAuthKeyInfo) o;
        //support old data
        if (oauthKeyInfo.getLabel() == null || label == null) {
            return false;
        }
        return label.equals(oauthKeyInfo.getLabel())
                &&
                keys.equals(oauthKeyInfo.getKeys());
    }

    @Override
    public int hashCode() {
        return  (keys.hashCode() * 4711);
    }

    @Override
    public String toString() {
        return label;
    }
}
