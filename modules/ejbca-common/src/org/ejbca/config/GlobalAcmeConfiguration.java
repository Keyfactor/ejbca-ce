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
package org.ejbca.config;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.configuration.ConfigurationBase;

/**
 * Global Configuration object which holds all the AcmeConfigurations and generic protocol settings.
 */
public class GlobalAcmeConfiguration extends ConfigurationBase implements Serializable {

    private static final long serialVersionUID = 1L;
    //private static final Logger log = Logger.getLogger(GlobalAcmeConfiguration.class);

    public static final String ACME_CONFIGURATION_ID = "ACME";
    
    private static final String KEY_INITIALIZED = "initialized";
    private static final String KEY_DEFAULT_ACME_CONFIGURATION_ID = "defaultAcmeConfigurationId";
    private static final String KEY_ACME_CONFIGURATION_PREFIX = "acmeConfiguration_";
    private static final String KEY_REPLAY_NONCE_VALIDITY = "replayNonceValiditity";
    private static final String KEY_REPLAY_NONCE_SECRETS_HMAC_WITH_SHA256 = "replayNonceSecretsHmacWithSHA256";

    @Override
    public void upgrade() {}

    @Override
    public String getConfigurationId() {
        return ACME_CONFIGURATION_ID;
    }

    public Properties getAsProperties() {
        final Properties properties = new Properties();
        properties.put(KEY_INITIALIZED, isInitialized());
        properties.put(KEY_DEFAULT_ACME_CONFIGURATION_ID, getDefaultAcmeConfigurationId());
        properties.put(KEY_REPLAY_NONCE_VALIDITY, getReplayNonceValidity());
        properties.put("acmeConfigurationIds", Arrays.toString(getAcmeConfigurationIds().toArray()));
        properties.put(KEY_REPLAY_NONCE_SECRETS_HMAC_WITH_SHA256,
                getReplayNonceSharedSecrets(PKCSObjectIdentifiers.id_hmacWithSHA256.getId())==null ? "not configured" : "configured");
        return properties;
    }

    /** @return true if this global configuration has been initialized */
    public boolean isInitialized() {
        return Boolean.valueOf((String)super.data.get(KEY_INITIALIZED));
    }
    /** Set to true when this global configuration has been initialized */
    public void setInitialized(final boolean initialized) {
        super.data.put(KEY_INITIALIZED, String.valueOf(initialized));
    }

    /** @return the default configured AcmeConfiguration IDs that will be used if none is specified in the request path */
    public String getDefaultAcmeConfigurationId() {
        return (String) data.get(KEY_DEFAULT_ACME_CONFIGURATION_ID);
    }
    /** Set the default configured AcmeConfiguration IDs that will be used if none is specified in the request path */
    public void setDefaultAcmeConfigurationId(final String defaultAcmeConfigurationId) {
        data.put(KEY_DEFAULT_ACME_CONFIGURATION_ID, defaultAcmeConfigurationId);
    }

    /**
     * Returns all available AcmeConfiguration IDs.
     * 
     * @return the list of IDs or an empty list. 
     */
    public List<String> getAcmeConfigurationIds() {
        final Set<String> acmeConfigurationIds = new HashSet<>();
        for (final Object key : data.keySet()) {
            if (key instanceof String && ((String)key).startsWith(KEY_ACME_CONFIGURATION_PREFIX)) {
                acmeConfigurationIds.add(((String)key).substring(KEY_ACME_CONFIGURATION_PREFIX.length()));
            }
        }
        return new ArrayList<>(acmeConfigurationIds);
    }

    /** @return the AcmeConfiguration that will be based on the configurationId specified in the request path */
    public AcmeConfiguration getAcmeConfiguration(final String configurationId) {
        final Object upgradeableDataHashMapData = data.get(KEY_ACME_CONFIGURATION_PREFIX + configurationId);
        if (upgradeableDataHashMapData==null) {
            return null;
        }
        final AcmeConfiguration acmeConfiguration = new AcmeConfiguration(upgradeableDataHashMapData);
        acmeConfiguration.setConfigurationId(configurationId);
        return acmeConfiguration;
    }
    
    /**
     * Adds a new or overwrites a persisted AcmeConfiguration in the backing object.
     * 
     * Sets the objects ID as default ACME alias ID if the first object is added. 
     * 
     * @param acmeConfiguration the ACME alias.
     */
    public void updateAcmeConfiguration(final AcmeConfiguration acmeConfiguration) {
        data.put(KEY_ACME_CONFIGURATION_PREFIX + acmeConfiguration.getConfigurationId(), acmeConfiguration.saveData());
        final List<String> aliasIds = getAcmeConfigurationIds();
        // Set default ACME alias if the first one is created.
        if (aliasIds.size() == 1) {
            setDefaultAcmeConfigurationId(aliasIds.get(0));
        }
    }

    /** @return the validity period of newly generated nonces */
    public long getReplayNonceValidity() {
        final Long replayNonceValidity = (Long)data.get(KEY_REPLAY_NONCE_VALIDITY);
        return replayNonceValidity==null ? 600*1000L : replayNonceValidity.longValue();
    }
    public void setReplayNonceValidity(final long replayNonceValidity) {
        data.put(KEY_REPLAY_NONCE_VALIDITY, replayNonceValidity);
    }

    /** @return all replay-nonce secrets for the specified algorithm that have been configured */
    @SuppressWarnings("unchecked")
    public ArrayList<String> getReplayNonceSharedSecrets(final String hmacOid) throws IllegalArgumentException, IllegalStateException {
        final ArrayList<String> sharedSecretStrings;
        if (PKCSObjectIdentifiers.id_hmacWithSHA256.getId().equals(hmacOid)) {
            sharedSecretStrings = (ArrayList<String>)data.get(KEY_REPLAY_NONCE_SECRETS_HMAC_WITH_SHA256);
        } else {
            throw new IllegalArgumentException("Unsupported hmac algorithm '" + hmacOid + "'.");
        }
        if (sharedSecretStrings==null || sharedSecretStrings.isEmpty()) {
            throw new IllegalStateException("No secret for replay protection has been configured yet for this algorithm '" + hmacOid + "'.");
        }
        return sharedSecretStrings;
    }

    /** @return the latest replay-nonce secret for the specified algorithm that have been configured */
    public byte[] getReplayNonceSharedSecretCurrent(final String hmacOid) throws IllegalArgumentException, IllegalStateException {
        final ArrayList<String> replayNonceSharedSecrets = getReplayNonceSharedSecrets(hmacOid);
        return Hex.decode(replayNonceSharedSecrets.get(replayNonceSharedSecrets.size()-1));
    }

    /** Add a new replay-nonce secret for the specified algorithm to use for all new generated replay-nonces */
    public void addReplayNonceSharedSecret(final String hmacOid, byte[] secret) throws IllegalArgumentException, IllegalStateException {
        // TODO: Use obfuscation during serialized transfer, but StringTools.encrypt when data is at rest
        // TODO: Consider also adding a timestamp to when the new secret was added, to allow smooth purge of old secret during roll-over
        final String sharedSecretString = new String(Hex.encode(secret), StandardCharsets.UTF_8);
        if (PKCSObjectIdentifiers.id_hmacWithSHA256.getId().equals(hmacOid)) {
            @SuppressWarnings("unchecked")
            ArrayList<String> sharedSecretStrings = (ArrayList<String>)data.get(KEY_REPLAY_NONCE_SECRETS_HMAC_WITH_SHA256);
            if (sharedSecretStrings==null) {
                sharedSecretStrings = new ArrayList<>();
            }
            sharedSecretStrings.add(sharedSecretString);
            data.put(KEY_REPLAY_NONCE_SECRETS_HMAC_WITH_SHA256, sharedSecretStrings);
        } else {
            throw new IllegalArgumentException("Unsupported hmac algorithm '" + hmacOid + "'.");
        }
    }

    public boolean aliasExists(String configurationId) {
        if(StringUtils.isNotEmpty(configurationId)) {
            AcmeConfiguration acmeConfiguration = getAcmeConfiguration(configurationId);
            return acmeConfiguration != null;
        }
        return false;
    }

    public void renameConfigId(String newConfigId, String oldConfigId){
        AcmeConfiguration acmeConfiguration = getAcmeConfiguration(oldConfigId);
        acmeConfiguration.setConfigurationId(newConfigId);
        removeConfigId(oldConfigId);
        updateAcmeConfiguration(acmeConfiguration);
    }

    /**
     * Removes a persisted AcmeConfiguration from the backing object.
     * 
     * Sets the objects ID as default ACME alias ID if only one object is left or null if empty. 
     * 
     * @param configId the ACME alias.
     */
    public void removeConfigId(String configId) {
        data.remove(KEY_ACME_CONFIGURATION_PREFIX + configId);
        final List<String> aliasIds = getAcmeConfigurationIds();
        // Set default ACME alias if there is only one. Reset if no ACME alias.
        if (aliasIds.size() == 0) {
            setDefaultAcmeConfigurationId(null);
        } else if (aliasIds.size() == 1) {
            setDefaultAcmeConfigurationId(aliasIds.get(0));
        }
    }
}
