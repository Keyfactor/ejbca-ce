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
import java.util.Random;
import java.util.Set;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.apache.commons.lang.StringUtils;
import org.cesecore.util.StringTools;

/**
 * Represents an OAuth Public Key entry
 *
 */
public final class OAuthKeyInfo implements Serializable {
    private static final long serialVersionUID = 1L;
    private static final Random random = new Random();

    // dbIndexes of existing provider types should not be changed
    public enum OAuthProviderType {
        TYPE_GENERIC(0, "Generic"),
        TYPE_AZURE(1, "Azure"),
        TYPE_KEYCLOAK(2, "Keycloak");

        private final int index;
        private final String label;

        OAuthProviderType(int dbIndex, String label) {
            this.index = dbIndex;
            this.label = label;
        }

        public int getIndex() {
            return this.index;
        }

        public String getLabel() {
            return this.label;
        }

        public static OAuthProviderType getByIndex(final int index) {
            for (OAuthProviderType type : values()) {
                if (index == type.index) {
                    return type;
                }
            }
            return null;
        }
    }

    private final int internalId;
    private int typeInt;
    private Map<String, OAuthPublicKey> keys = new LinkedHashMap<>();
    private String label;
    private String client;
    private String realm;
    private String scope;
    private String url;
    private String clientSecret;
    private int skewLimit = 60000;


    /**
     * Creates a OAuth Key info object
     *
     * @param label  Provider label
     * @param skewLimit  skew limit.
     */
    public OAuthKeyInfo(final String label, final int skewLimit, OAuthProviderType type) {
        if (label == null) {
            throw new IllegalArgumentException("label is null");
        }
        this.internalId = random.nextInt();
        this.label = label;
        this.skewLimit = skewLimit;
        this.typeInt = type.getIndex();
    }

    public int getSkewLimit() {
        return skewLimit;
    }

    public OAuthProviderType getType() {
        return OAuthProviderType.getByIndex(typeInt);
    }

    /** @return Internal Id*/
    public Integer getInternalId() {
        return internalId;
    }

    public int getTypeInt() {
        return typeInt;
    }

    public void setTypeInt(int typeInt) {
        this.typeInt = typeInt;
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

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
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

    public String getOauthLoginUrl() {
        if (getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK)) {
            return getTypeSpecificUrl("auth");
        }
        if (getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_AZURE)) {
            return getTypeSpecificUrl("authorize");
        }
        return url;
    }

    public String getTokenUrl() {
        return getTypeSpecificUrl("token");
    }

    public String getLogoutUrl() {
        return getTypeSpecificUrl("logout");
    }

    private String getTypeSpecificUrl(String endpoint){
        switch (getType()) {
            case TYPE_KEYCLOAK: {
                String uri = getUrl();
                uri += getUrl().endsWith("/") ? "" : "/";
                uri += "realms/" + getRealm() + "/protocol/openid-connect/" + endpoint;
                return uri;
            }
            case TYPE_AZURE: {
                String uri = getUrl();
                uri += getUrl().endsWith("/") ? "" : "/";
                uri += getRealm() + "/oauth2/v2.0/" + endpoint;
                return uri;
            }
            case TYPE_GENERIC: {
                return getUrl();
            }
        }
        return null;
    }


    /** Fixes mistakes in the given URL (like removing trailing slashes). Exact behavior depends on the provider type. */
    public String fixUrl(final String urlToFix) {
        if (urlToFix == null) {
            return null;
        }
        switch (OAuthProviderType.getByIndex(typeInt)) {
        case TYPE_KEYCLOAK:
            return StringUtils.stripEnd(StringUtils.trim(urlToFix), "/");
        default:
            return urlToFix;
        }
    }

    @Override
    public boolean equals(Object o) {
        if (o == null || o.getClass() != OAuthKeyInfo.class) {
            return false;
        }

        final OAuthKeyInfo oauthKeyInfo = (OAuthKeyInfo) o;
        return StringUtils.equals(label, oauthKeyInfo.getLabel()) &&
                internalId == oauthKeyInfo.getInternalId() &&
                (keys == oauthKeyInfo.getKeys() || // also true if both are null
                    (keys != null && keys.equals(oauthKeyInfo.getKeys())));
    }

    @Override
    public int hashCode() {
        return  keys != null ? internalId + (keys.hashCode() * 4711) : internalId;
    }

    @Override
    public String toString() {
        return label;
    }
}
