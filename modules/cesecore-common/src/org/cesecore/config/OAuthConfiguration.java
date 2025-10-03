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
import java.util.Arrays;
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
    private static final String ALLOWED_OAUTH_HOSTS = "allowedoauthhosts";

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

    // Methods used by configdump
    public String getDefaultOauthKeyLabel() {
        return getDefaultOauthKey() == null ? null : getDefaultOauthKey().getLabel();
    }

    public void setDefaultOauthKeyLabel(final String label) {
        if (label != null && !label.isBlank() && !"none".equalsIgnoreCase(label)) {
            final Map<String, OAuthKeyInfo> oAuthKeyInfoMap = getOauthKeys();

            if (oAuthKeyInfoMap != null && !oAuthKeyInfoMap.isEmpty()) {
                final OAuthKeyInfo defaultOauthKey = oAuthKeyInfoMap.get(label);
                if (defaultOauthKey != null) {
                    setDefaultOauthKey(defaultOauthKey);
                } else {
                    throw new IllegalArgumentException("No OAuth key with label " + label + " found.");
                }
            } else {
                throw new IllegalArgumentException("No OAuth keys found.");
            }

        } else {
            setDefaultOauthKey(null);
        }
    }

    public String[] getAllowedOauthHosts() {
        final String[] allowedOauthHosts = (String[]) data.get(ALLOWED_OAUTH_HOSTS);
        if (allowedOauthHosts == null) {
            return new String[0];
        } else {
            return allowedOauthHosts;
        }
    }

    public void setAllowedOauthHosts(String[] allowedOauthHosts) {
        final String[] allowedOAuthHostFinalList = filterValidHostnames(allowedOauthHosts); // Validate the OAuth allowlist before saving
        data.put(ALLOWED_OAUTH_HOSTS, allowedOAuthHostFinalList);
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

    /**
     * Filters the provided list of hostnames and returns a new list containing only the valid hostnames.
     *
     * @param allowlist the string array of hostnames to be filtered
     * @return a string array of hostnames that are valid, according to the validation criteria in the isValidHostname() method
     */
    private String[] filterValidHostnames(final String[] allowlist) {
        return Arrays.stream(allowlist)
                .filter(this::isValidHostname)
                .toArray(String[]::new);

    }

    /**
     * Validates a hostname
     * @param hostname The hostname to validate
     * @return true if valid, false otherwise
     */
    private boolean isValidHostname(final String hostname) {
        // Basic hostname validation
        String hostnameRegex = "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$";
        return hostname != null && hostname.matches(hostnameRegex);
    }
}
