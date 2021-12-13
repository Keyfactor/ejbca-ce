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

package org.cesecore.config;

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.configuration.ConfigurationBase;

public class OAuthConfiguration extends ConfigurationBase implements Serializable {
    /** Class logger. */
    private static final long serialVersionUID = 1L;

    public static final String OAUTH_CONFIGURATION_ID = "OAUTH";
    private static final   String OAUTH_KEYS          = "oauthkeys";
    // Default OAuth Keys
    private static final   String DEFAULT_OAUTH_KEY   = "defaultoauthkey";

    public Map<String,OAuthKeyInfo> getOauthKeys() {
        @SuppressWarnings("unchecked")
        final Map<String,OAuthKeyInfo> ret = (Map<String,OAuthKeyInfo>)data.get(OAUTH_KEYS);
        return (ret == null ? new LinkedHashMap<>() : new LinkedHashMap<>(ret));
    }

    /** Sets the available OAuth keys */
    public void setOauthKeys(Map<String,OAuthKeyInfo> oauthKeys) {
        data.put(OAUTH_KEYS, oauthKeys);
    }

    public void addOauthKey(OAuthKeyInfo oauthKey) {
        LinkedHashMap<String,OAuthKeyInfo> keys = new LinkedHashMap<>(getOauthKeys());
        keys.put(oauthKey.getLabel(), oauthKey);
        setOauthKeys(keys);
    }

    public void removeOauthKey(String label) {
        LinkedHashMap<String, OAuthKeyInfo> keys = new LinkedHashMap<>(getOauthKeys());
        if (getDefaultOauthKey() != null && getDefaultOauthKey().getLabel().equals(label)) {
            setDefaultOauthKey(null);
        }
        keys.remove(label);
        setOauthKeys(keys);
    }

    public OAuthKeyInfo getDefaultOauthKey() {
        return (OAuthKeyInfo)data.get(DEFAULT_OAUTH_KEY);
    }

    public void setDefaultOauthKey(OAuthKeyInfo defaultKey) {
        data.put(DEFAULT_OAUTH_KEY, defaultKey);
    }


    public OAuthKeyInfo getOauthKeyByLabel(String label){
        Map<String, OAuthKeyInfo> oauthKeys = getOauthKeys();
        final Optional<OAuthKeyInfo> optionalEntry = oauthKeys.values().stream().filter(
                oauthInfo ->
                        oauthInfo.getLabel().equals(label)).findFirst();
        return optionalEntry.orElse(null);
    }

    public OAuthKeyInfo getOauthKeyById(Integer id){
        Map<String, OAuthKeyInfo> oauthKeys = getOauthKeys();
        final Optional<OAuthKeyInfo> optionalEntry = oauthKeys.values().stream().filter(
                oauthInfo ->
                        oauthInfo.getInternalId().equals(id)).findFirst();
        return optionalEntry.orElse(null);
    }

    @Override
    public void upgrade() {

    }

    @Override
    public String getConfigurationId() {
        return OAUTH_CONFIGURATION_ID;
    }
}
