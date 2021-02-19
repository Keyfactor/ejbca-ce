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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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
        keys.put(kid, new OAuthPublicKey(bytes, kid));
    }

    public Set<String> getAllKeyIdentifiers(){
        return keys.keySet();
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
