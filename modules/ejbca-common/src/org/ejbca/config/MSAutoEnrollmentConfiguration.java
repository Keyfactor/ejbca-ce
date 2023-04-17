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
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;
import org.cesecore.configuration.ConfigurationBase;

/**
 * Configuration for the Microsoft Auto Enrollment
 */
public class MSAutoEnrollmentConfiguration extends ConfigurationBase implements Serializable {
    private static final long serialVersionUID = 1L;
    public static final String CONFIGURATION_ID = "MS_AUTO_ENROLLMENT";

    private static final Logger log = Logger.getLogger(MSAutoEnrollmentConfiguration.class);
    
    // Aliases 
    private static final String ALIAS_LIST = "aliaslist";
    private static final Set<String> DEFAULT_ALIAS_LIST      = new LinkedHashSet<>();
    
    // MSAE Kerberos
    private static final String MSAE_FOREST_ROOT = "msaeForestRoot";
    private static final String MSAE_DOMAIN = "msaeDomain";
    private static final String MSAE_KEYTAB_FILENAME = "msaeKeyTabFilename";
    private static final String MSAE_KEYTAB_BYTES = "msaeKeyTabBytes";
    private static final String POLICY_NAME = "policyName";
    private static final String POLICY_UID = "policyUid";
    private static final String SPN = "servicePrincipalName";

    
    // MSAE Krb5Conf
    private static final Object MSAE_KRB5_CONF_BYTES = "msaeKrb5ConfBytes";
    private static final Object MSAE_KRB5_CONF_FILENAME = "msaeKrb5ConfFilename";

    // MSAE Settings
    private static final String IS_USE_SSL = "isUseSSL";
    private static final String IS_FOLLOW_LDAP_REFERRAL = "isFollowLdapReferral";
    private static final String AD_CONNECTION_PORT = "adConnectionPort";
    private static final String LDAP_READ_TIMEOUT = "ldapReadTimeout";
    private static final String LDAP_CONNECT_TIMEOUT = "ldapConnectTimeout";
    private static final String AD_LOGIN_DN = "adLoginDN";
    private static final String AD_LOGIN_PASSWORD = "adLoginPassword";
    private static final String AUTH_KEY_BINDING = "authKeyBinding";

    // MS Enrollment Servlet Settings
    private static final String CA_NAME = "caName";

    // Template to Settings
    private static final String MS_TEMPLATE_SETTINGS = "msTemplateSettings";


    private static final int DEFAULT_AD_CONNECTION_PORT = 389;
    
    private static final int DEFAULT_LDAP_READ_TIMEOUT = 5000; // In milliseconds
    
    private static final int DEFAULT_LDAP_CONNECT_TIMEOUT = 5000; // In milliseconds

    public MSAutoEnrollmentConfiguration() {
        super();
    }
    
    public MSAutoEnrollmentConfiguration(Serializable dataobj) {
        @SuppressWarnings("unchecked")
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }

    /**
     * Copy constructor for {@link MSAutoEnrollmentConfiguration}
     */
    public MSAutoEnrollmentConfiguration(MSAutoEnrollmentConfiguration autoenrollmentConfiguration) {
        super();
        setAliasList(new LinkedHashSet<>());
        for(String alias : autoenrollmentConfiguration.getAliasList()) {
            addAlias(alias);
            for(String key : getAllAliasKeys(alias)) {
                String value = autoenrollmentConfiguration.getValue(key, alias);
                setValue(key, value, alias);
            }
        }
    }

    private void initWithDefaults(String alias) {
        if(StringUtils.isNotEmpty(alias)) {
            alias = alias + ".";
            data.put(alias + MSAE_FOREST_ROOT, "");
            data.put(alias + MSAE_DOMAIN, "");
            data.put(alias + MSAE_KEYTAB_FILENAME, "");
            data.put(alias + MSAE_KEYTAB_BYTES, null);
            data.put(alias + POLICY_NAME, "");
            data.put(alias + SPN, "");
            data.put(alias + MSAE_KRB5_CONF_BYTES, null);
            data.put(alias + MSAE_KRB5_CONF_FILENAME, "");
            data.put(alias + IS_USE_SSL, "false");
            data.put(alias + IS_FOLLOW_LDAP_REFERRAL, "false");
            data.put(alias + AD_CONNECTION_PORT, String.valueOf(DEFAULT_AD_CONNECTION_PORT));
            data.put(alias + AD_LOGIN_DN, "");
            data.put(alias + AD_LOGIN_PASSWORD, "");
            data.put(alias + AUTH_KEY_BINDING, null);
            data.put(alias + CA_NAME, "");
            data.put(alias + MS_TEMPLATE_SETTINGS, new ArrayList<>());
        } else {
            log.debug("No alias found");
        }
    }

    public static Set<String> getAllAliasKeys(String alias) {
        alias = alias + ".";
        Set<String> keys = new LinkedHashSet<>();
        keys.add(alias + MSAE_FOREST_ROOT);
        keys.add(alias + MSAE_DOMAIN);
        keys.add(alias + MSAE_KEYTAB_FILENAME);
        keys.add(alias + MSAE_KEYTAB_BYTES);
        keys.add(alias + POLICY_NAME);
        keys.add(alias + POLICY_UID);
        keys.add(alias + SPN);
        keys.add(alias + MSAE_KRB5_CONF_BYTES);
        keys.add(alias + MSAE_KRB5_CONF_FILENAME);
        keys.add(alias + IS_USE_SSL);
        keys.add(alias + IS_FOLLOW_LDAP_REFERRAL);
        keys.add(alias + AD_CONNECTION_PORT);
        keys.add(alias + AD_LOGIN_DN);
        keys.add(alias + AD_LOGIN_PASSWORD);
        keys.add(alias + AUTH_KEY_BINDING);
        keys.add(alias + CA_NAME);
        keys.add(alias + MS_TEMPLATE_SETTINGS);
        return keys;
    }
    
    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION, Float.valueOf(LATEST_VERSION));
        }
    }

    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    // MSAE Kerberos Settings
    
    public String getMsaeForestRoot(String alias) {
        String key = alias + "." + MSAE_FOREST_ROOT;
        return getValue(key, alias);
    }
    
    public void setMsaeForestRoot(String alias, final String msaeForestRoot) {
        String key = alias + "." + MSAE_FOREST_ROOT;
        setValue(key, msaeForestRoot, alias);
    }
    
    public String getMsaeDomain(String alias) {
        String key = alias + "." + MSAE_DOMAIN;
        return getValue(key, alias);
    }

    public void setMsaeDomain(String alias, final String msaeDomain) {
        String key = alias + "." + MSAE_DOMAIN;
        setValue(key, msaeDomain, alias);
    }

    public String getPolicyName(String alias) {
        String key = alias + "." + POLICY_NAME;
        return getValue(key, alias);
    }

    public void setPolicyName(String alias, final String policyName) {
        String key = alias + "." + POLICY_NAME;
        setValue(key, policyName, alias);
    }
    
    public String getSpn(String alias) {
        String key = alias + "." + SPN;
        return getValue(key, alias);
    }

    public void setSpn(String alias, final String spn) {
        String key = alias + "." + SPN;
        setValue(key, spn, alias);
    }
    
    public String getPolicyUid(String alias) {
        String key = alias + "." + POLICY_UID;
        return getValue(key, alias);
    }

    public void setPolicyUid(String alias) {
        String key = alias + "." + POLICY_UID;
        // Only set this once per node.
        if (data.get(key) == null) {
            final String policyUid = "{" + UUID.randomUUID().toString() + "}";
            setValue(key, policyUid, alias);
        }
    }

    public String getMsaeKeyTabFilename(String alias) {
        String key = alias + "." + MSAE_KEYTAB_FILENAME;
        return getValue(key, alias);
    }

    public void setMsaeKeyTabFilename(String alias, final String msaeKeyTabFilename) {
        String key = alias + "." + MSAE_KEYTAB_FILENAME;
        setValue(key, msaeKeyTabFilename, alias);
    }

    public byte[] getMsaeKeyTabBytes(String alias) {
        String key = alias + "." + MSAE_KEYTAB_BYTES;
        return getValueBytes(key, alias);
    }

    public void setMsaeKeyTabBytes(String alias, final byte[]  msaeKeyTabBytes) {
        String key = alias + "." + MSAE_KEYTAB_BYTES;
        setValueBytes(key, msaeKeyTabBytes, alias);
    }
    
    // MSAE Krb5 Conf
    public String getMsaeKrb5ConfFilename(String alias) {
        String key = alias + "." + MSAE_KRB5_CONF_FILENAME;
        return getValue(key, alias);
    }

    public void setMsaeKrb5ConfFilename(String alias, final String msaeKrb5ConfFilename) {
        String key = alias + "." + MSAE_KRB5_CONF_FILENAME;
        setValue(key, msaeKrb5ConfFilename, alias);
    }

    public byte[] getMsaeKrb5ConfBytes(String alias) {
        String key = alias + "." + MSAE_KRB5_CONF_BYTES;
        return getValueBytes(key, alias);
    }

    public void setMsaeKrb5ConfBytes(String alias, final byte[] msaeKrb5ConfBytes) {
        String key = alias + "." + MSAE_KRB5_CONF_BYTES;
        setValueBytes(key, msaeKrb5ConfBytes, alias);
    }
    

    // MSAE Settings
    public boolean isUseSSL(String alias) {
        String key = alias + "." + IS_USE_SSL;
        String value = getValue(key, alias);
        return StringUtils.equals(value, "true");
    }

    public void setIsUseSsl(String alias, final boolean isUseSsl) {
        String key = alias + "." + IS_USE_SSL;
        setValue(key, isUseSsl ? "true" : "false", alias);
    }

    public boolean isFollowLdapReferral(String alias) {
        String key = alias + "." + IS_FOLLOW_LDAP_REFERRAL;
        String value = getValue(key, alias);
        return StringUtils.equals(value, "true");
    }

    public void setFollowLdapReferral(String alias, final boolean followLdapReferral) {
        String key = alias + "." + IS_FOLLOW_LDAP_REFERRAL;
        setValue(key, followLdapReferral ? "true" : "false", alias);
    }

    public int getADConnectionPort(String alias) {
        String key = alias + "." + AD_CONNECTION_PORT;
        String value = getValue(key, alias);
        return value == null ? DEFAULT_AD_CONNECTION_PORT : Integer.valueOf(value);
    }

    public void setAdConnectionPort(String alias, final int port) {
        String key = alias + "." + AD_CONNECTION_PORT;
        setValue(key, String.valueOf(port), alias);
    }
    
    public int getLdapReadTimeout(String alias) {
        String key = alias + "." + LDAP_READ_TIMEOUT;
        String value = getValue(key, alias);
        return value == null ? DEFAULT_LDAP_READ_TIMEOUT : Integer.valueOf(value);
    }

    public void setLdapReadTimeout(String alias, final int ldapReadTimeout) {
        String key = alias + "." + LDAP_READ_TIMEOUT;
        setValue(key, String.valueOf(ldapReadTimeout), alias);
    }
    
    public int getLdapConnectTimeout(String alias) {
        String key = alias + "." + LDAP_CONNECT_TIMEOUT;
        String value = getValue(key, alias);
        return value == null ? DEFAULT_LDAP_CONNECT_TIMEOUT : Integer.valueOf(value);
    }

    public void setLdapConnectTimeout(String alias, final int ldapConnectTimeout) {
        String key = alias + "." + LDAP_CONNECT_TIMEOUT;
        setValue(key, String.valueOf(ldapConnectTimeout), alias);
    }

    public String getAdLoginDN(String alias) {
        String key = alias + "." + AD_LOGIN_DN;
        return getValue(key, alias);
    }

    public void setAdLoginDN(String alias, final String adLoginDN) {
        String key = alias + "." + AD_LOGIN_DN;
        setValue(key, adLoginDN, alias);
    }

    public String getAdLoginPassword(String alias) {
        String key = alias + "." + AD_LOGIN_PASSWORD;
        return getDecryptedValue(getValue(key, alias));
    }

    public void setAdLoginPassword(String alias, final String adLoginPassword) {
        String key = alias + "." + AD_LOGIN_PASSWORD;
        setValue(key, getEncryptedValue(adLoginPassword), alias);
    }

    public Integer getAuthKeyBinding(String alias) {
        String key = alias + "." + AUTH_KEY_BINDING;
        String value = getValue(key, alias);
        return StringUtils.isEmpty(value) ? null : Integer.valueOf(value);
    }

    public void setAuthKeyBinding(String alias, final Integer authKeyBinding) {
        String key = alias + "." + AUTH_KEY_BINDING;
        if (authKeyBinding == null) {
            setValue(key, null, alias);
        } else {
            setValue(key, String.valueOf(authKeyBinding), alias);
        }
    }

    // MS Enrollment Servlet Settings
    public String getCaName(String alias) {
        String key = alias + "." + CA_NAME;
        return getValue(key, alias);
    }
    
    public void setCaName(String alias, final String caName) {
        String key = alias + "." + CA_NAME;
        setValue(key, caName, alias);
    }

    // MS Template Settings
    @SuppressWarnings("unchecked")
    public List<MSAutoEnrollmentSettingsTemplate> getMsTemplateSettings(String alias) {
        String key = alias + "." + MS_TEMPLATE_SETTINGS;
        return (List<MSAutoEnrollmentSettingsTemplate>) data.get(key);
    }

    public void setMsTemplateSettings(String alias, final List<MSAutoEnrollmentSettingsTemplate> msTemplateSettings) {
        String key = alias + "." + MS_TEMPLATE_SETTINGS;
        data.put(key, msTemplateSettings);
    }
    
    
    
    // Aliases
    
    public String getValue(String key, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                return (String) data.get(key);
            } else {
                log.info("Could not find key '" + key + "' in the autoenrollment configuration data");
            }
        } else {
            log.info("Autoenrollment alias '" + alias + "' does not exist");
        }
        return null;
    }
    
    public byte[] getValueBytes(String key, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                return (byte[]) data.get(key);
            } else {
                log.info("Could not find key '" + key + "' in the autoenrollment configuration data");
            }
        } else {
            log.info("Autoenrollment alias '" + alias + "' does not exist");
        }
        return null;
    }

    public void setValueBytes(String key, byte[] value, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Added '" + key + "=" + value + "' to the Autoenrollment configuration data");
                }
            } else {
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Key '" + key + "' does not exist in the autoenrollment configuration data, adding it");
                }
            }
        } else {
            log.info("Autoenrollment alias '" + alias + "' does not exist");
        }
    }
    
    public void setValue(String key, String value, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Added '" + key + "=" + value + "' to the Autoenrollment configuration data");
                }
            } else {
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Key '" + key + "' does not exist in the Autoenrollment configuration data, adding it");
                }
            }
        } else {
            log.info("Autoenrollment alias '" + alias + "' does not exist");
        }
    }

    public void setAliasList(final Set<String> aliaslist) {
        data.put(ALIAS_LIST, aliaslist);
    }

    public Set<String> getAliasList() {
        @SuppressWarnings("unchecked")
        Set<String> ret = (Set<String>) data.get(ALIAS_LIST);

        return (ret == null ? DEFAULT_ALIAS_LIST : ret);
    }

    public List<String> getSortedAliasList() {
        List<String> result = new ArrayList<>(getAliasList());
        Collections.sort(result, new Comparator<String>() {
            @Override
            public int compare(String o1, String o2) {
                return o1.compareToIgnoreCase(o2);
            }
        });
        return result;
    }

    public boolean aliasExists(String alias) {
        if(StringUtils.isNotEmpty(alias)) {
            Set<String> aliases = getAliasList();
            return aliases.contains(alias);
        }
        if(log.isDebugEnabled()) {
            log.debug("Autoenrollment alias '" + alias+"' does not exist.");
        }
        return false;
    }

    public void addAlias(String alias) {
        if(log.isDebugEnabled()) {
            log.debug("Adding Autoenrollment alias: " + alias);
        }

        if(StringUtils.isEmpty(alias)) {
            if(log.isDebugEnabled()) {
                log.debug("No alias is added because no alias was provided.");
            }
            return;
        }

        Set<String> aliases = getAliasList();
        if(aliases.contains(alias)) {
            if(log.isDebugEnabled()) {
                log.debug("Autoenrollment alias '" + alias + "' already exists.");
            }
            return;
        }
        initWithDefaults(alias);
        aliases.add(alias);
        data.put(ALIAS_LIST, aliases);
    }

    public void removeAlias(String alias) {
        if(log.isDebugEnabled()) {
            log.debug("Removing Autoenrollment alias: " + alias);
        }

        if(StringUtils.isEmpty(alias)) {
            if(log.isDebugEnabled()) {
                log.debug("No alias is removed because no alias was provided.");
            }
            return;
        }

        Set<String> aliases = getAliasList();
        if(!aliases.contains(alias)) {
            if(log.isDebugEnabled()) {
                log.debug("Autoenrollment alias '" + alias + "' does not exist");
            }
            return;
        }

        for(String key : getAllAliasKeys(alias)) {
            data.remove(key);
        }
        aliases.remove(alias);
        data.put(ALIAS_LIST, aliases);
    }

    public void renameAlias(String oldAlias, String newAlias) {
        if(log.isDebugEnabled()) {
            log.debug("Renaming Autoenrollment alias '" + oldAlias + "' to '" + newAlias + "'");
        }

        if(StringUtils.isEmpty(oldAlias) || StringUtils.isEmpty(newAlias)) {
            log.info("No alias is renamed because one or both aliases were not provided.");
            return;
        }

        Set<String> aliases = getAliasList();
        if(!aliases.contains(oldAlias)) {
            log.info("Cannot rename. Autoenrollment alias '" + oldAlias + "' does not exists.");
            return;
        }

        if(aliases.contains(newAlias)) {
            log.info("Cannot rename. Autoenrollment alias '" + newAlias + "' already exists.");
            return;
        }

        Set<String> oldKeys = getAllAliasKeys(oldAlias);
        Iterator<String> itr = oldKeys.iterator();
        while(itr.hasNext()) {
            String oldkey = itr.next();
            String newkey = oldkey;
            newkey = StringUtils.replace(newkey, oldAlias, newAlias);
            Object value = data.get(oldkey);
            data.put(newkey, value);
        }
        removeAlias(oldAlias);
        aliases.remove(oldAlias);
        aliases.add(newAlias);
        data.put(ALIAS_LIST, aliases);
    }

    public void cloneAlias(String originAlias, String cloneAlias) {
        if(log.isDebugEnabled()) {
            log.debug("Cloning Autoenrollment alias '" + originAlias + "' to '" + cloneAlias + "'");
        }

        if(StringUtils.isEmpty(originAlias) || StringUtils.isEmpty(cloneAlias)) {
            log.info("No alias is cloned because one or both aliased were not provided");
            return;
        }

        Set<String> aliases = getAliasList();
        if(!aliases.contains(originAlias)) {
            log.info("Cannot clone. Autoenrollment alias '" + originAlias + "' does not exist.");
            return;
        }

        if(aliases.contains(cloneAlias)) {
            log.info("Cannot clone. Autoenrollment alias '" + cloneAlias + "' already exists.");
            return;
        }

        Iterator<String> itr = getAllAliasKeys(originAlias).iterator();
        while(itr.hasNext()) {
            String originalKey = itr.next();
            String cloneKey = originalKey;
            cloneKey = StringUtils.replace(cloneKey, originAlias, cloneAlias);
            Object value = data.get(originalKey);
            data.put(cloneKey, value);
        }
        aliases.add(cloneAlias);
        data.put(ALIAS_LIST, aliases);
    }

    /**
     * @return the configuration as a regular Properties object
     */
    public Properties getAsProperties() {
        final Properties properties = new Properties();
        Set<String> aliases = getAliasList();
        Iterator<String> itr = aliases.iterator();
        while(itr.hasNext()) {
            String alias = itr.next();
            Properties aliasp = getAsProperties(alias);
            properties.putAll(aliasp);
        }
        return properties;
    }

    public Properties getAsProperties(String alias) {
        if(aliasExists(alias)) {
            final Properties properties = new Properties();
            final Iterator<String> i = getAllAliasKeys(alias).iterator();
            while (i.hasNext()) {
                final String key = i.next();
                final Object value = data.get(key);
                properties.setProperty(key, value == null? "" : value.toString());
            }
            return properties;
        }
        return null;
    }
    
    @Override
    public void filterDiffMapForLogging(Map<Object,Object> diff) {
        Set<String> aliases = getAliasList();
        for (String alias : aliases) {
            filterDiffMapForLogging(diff, alias + "." + AD_LOGIN_PASSWORD);
        }
    }     
    
}
