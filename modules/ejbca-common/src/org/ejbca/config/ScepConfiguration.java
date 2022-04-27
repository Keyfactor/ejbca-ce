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
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;
import org.ejbca.core.model.ra.UsernameGeneratorParams;

/**
 * Configuration of the SCEP protocol.
 */
public class ScepConfiguration extends ConfigurationBase implements Serializable {
    
    private static final long serialVersionUID = -2051789798029184421L;

    private static final Logger log = Logger.getLogger(ScepConfiguration.class);
    
    public enum Mode {
        CA("CA"), RA("RA");

        private final String resource;

        private Mode(final String resource) {
            this.resource = resource;
        }

        public String getResource() {
            return resource;
        }
        
        @Override
        public String toString() {
            return resource;
        }
    }
    
    // Constants: Configuration keys
    public static final String SCEP_PREFIX = "scep.";
    public static final String SCEP_RAMODE_OLD = "ra.createOrEditUser";
    public static final String SCEP_OPERATIONMODE = "operationmode";
    public static final String SCEP_INCLUDE_CA = "includeca";
    public static final String SCEP_RETURN_CA_CHAIN_IN_GETCACERT = "returnCaChainInGetCaCert";
    public static final String SCEP_ALLOW_LEGACY_DIGEST_ALGORITHM = "allowLegacyDigestAlgorithm";
    public static final String SCEP_RA_CERTPROFILE = "ra.certificateProfile";
    public static final String SCEP_RA_ENTITYPROFILE = "ra.entityProfile";
    public static final String SCEP_RA_AUTHPWD = "ra.authPwd";
    public static final String SCEP_RA_DEFAULTCA = "ra.defaultCA";
    public static final String SCEP_RA_NAME_GENERATION_SCHEME = "ra.namegenerationscheme";
    public static final String SCEP_RA_NAME_GENERATION_PARAMETERS = "ra.namegenerationparameters";
    public static final String SCEP_RA_NAME_GENERATION_PREFIX = "ra.namegenerationprefix";
    public static final String SCEP_RA_NAME_GENERATION_POSTFIX = "ra.namegenerationpostfix";
    public static final String SCEP_CLIENT_CERTIFICATE_RENEWAL = "clientCertificateRenewal";
    public static final String SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY = "clientCertificateRenewalWithOldKey";
    
    //Intune configuration values
    public static final String SCEP_USE_INTUNE = "useIntune";
    public static final String AUTH_AUTHORITY = "intuneAuthority";
    public static final String AAD_APP_ID = "intuneAadAppId";
    public static final String AAD_APP_KEY = "intuneAadAppKey";
    public static final String AAD_USE_KEY_BINDING = "intuneAadUseKeyBinding";
    public static final String AAD_APP_KEY_BINDING = "intuneAadKeyBinding";
    public static final String TENANT = "intuneTenant";
    public static final String INTUNE_RESOURCE_URL = "intuneResourceUrl";
    public static final String GRAPH_API_VERSION = "intuneGraphApiVersion";
    public static final String GRAPH_RESOURCE_URL = "intuneGraphResourceUrl";
    public static final String PROXY_HOST = "intuneProxyHost";
    public static final String PROXY_PORT = "intuneProxyPort";
    public static final String PROXY_USER = "intuneProxyUser";
    public static final String PROXY_PASS = "intuneProxyPass";
       
    // This List is used in the command line handling of updating a config value to insure a correct value.
    public static final List<String> SCEP_BOOLEAN_KEYS = Arrays.asList(SCEP_INCLUDE_CA, SCEP_RETURN_CA_CHAIN_IN_GETCACERT);
    
    public static final String SCEP_CONFIGURATION_ID = "2";
    

    private final String ALIAS_LIST = "aliaslist";
 
    // Default Values
    public static final float LATEST_VERSION = 6f;
    public static final String EJBCA_VERSION = InternalConfiguration.getAppVersion();
    
    
    public static final Set<String> DEFAULT_ALIAS_LIST      = new LinkedHashSet<String>();
    public static final String DEFAULT_OPERATION_MODE = Mode.CA.getResource();
    public static final String DEFAULT_INCLUDE_CA = Boolean.TRUE.toString();
    public static final String DEFAULT_ALLOW_LEGACY_DIGEST_ALGORITHM = Boolean.FALSE.toString();
    public static final String DEFAULT_CLIENT_CERTIFICATE_RENEWAL = Boolean.FALSE.toString();
    public static final String DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY = Boolean.FALSE.toString();
    public static final String DEFAULT_RA_CERTPROFILE = "ENDUSER";
    public static final String DEFAULT_RA_ENTITYPROFILE = "EMPTY";
    public static final String DEFAULT_RA_DEFAULTCA = "";
    public static final String DEFAULT_RA_AUTHPWD = "";
    public static final String DEFAULT_RA_NAME_GENERATION_SCHEME = UsernameGeneratorParams.DN;
    public static final String DEFAULT_RA_NAME_GENERATION_PARAMETERS = "CN";
    public static final String DEFAULT_RA_NAME_GENERATION_PREFIX = "";
    public static final String DEFAULT_RA_NAME_GENERATION_POSTFIX = "";
    public static final String DEFAULT_RETURN_CA_CHAIN_IN_GETCACERT = Boolean.TRUE.toString();

    
    /** Creates a new instance of ScepConfiguration */
    public ScepConfiguration()  {
       super();
    }
    
    public ScepConfiguration(Serializable dataobj) {
        @SuppressWarnings("unchecked")
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }
    
    
    /** Initializes a new scep configuration with default values. */
    public void initialize(String alias){
        alias += ".";
        data.put(alias + SCEP_OPERATIONMODE, DEFAULT_OPERATION_MODE);
        data.put(alias + SCEP_INCLUDE_CA, DEFAULT_INCLUDE_CA);
        data.put(alias + SCEP_RETURN_CA_CHAIN_IN_GETCACERT, DEFAULT_RETURN_CA_CHAIN_IN_GETCACERT);
        data.put(alias + SCEP_ALLOW_LEGACY_DIGEST_ALGORITHM, DEFAULT_ALLOW_LEGACY_DIGEST_ALGORITHM);
        data.put(alias + SCEP_RA_CERTPROFILE, DEFAULT_RA_CERTPROFILE);
        data.put(alias + SCEP_RA_ENTITYPROFILE, DEFAULT_RA_ENTITYPROFILE);
        data.put(alias + SCEP_RA_DEFAULTCA, DEFAULT_RA_DEFAULTCA);
        data.put(alias + SCEP_RA_AUTHPWD, DEFAULT_RA_AUTHPWD);
        data.put(alias + SCEP_RA_NAME_GENERATION_SCHEME, DEFAULT_RA_NAME_GENERATION_SCHEME);
        data.put(alias + SCEP_RA_NAME_GENERATION_PARAMETERS, DEFAULT_RA_NAME_GENERATION_PARAMETERS);
        data.put(alias + SCEP_RA_NAME_GENERATION_PREFIX, DEFAULT_RA_NAME_GENERATION_PREFIX);
        data.put(alias + SCEP_RA_NAME_GENERATION_POSTFIX, DEFAULT_RA_NAME_GENERATION_POSTFIX);
        data.put(alias + SCEP_CLIENT_CERTIFICATE_RENEWAL, DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
        data.put(alias + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY, DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
        
        data.put(alias + SCEP_USE_INTUNE, Boolean.FALSE.toString());
        data.put(alias + AUTH_AUTHORITY, "");
        data.put(alias + AAD_APP_ID, "");
        data.put(alias + AAD_APP_KEY, "");
        data.put(alias + AAD_USE_KEY_BINDING, Boolean.FALSE.toString());
        data.put(alias + AAD_APP_KEY_BINDING, "");
        data.put(alias + TENANT, "");
        data.put(alias + INTUNE_RESOURCE_URL, "");
        data.put(alias + GRAPH_API_VERSION, "");
        data.put(alias + GRAPH_RESOURCE_URL, "");
        data.put(alias + PROXY_HOST, "");
        data.put(alias + PROXY_PORT, "");
        data.put(alias + PROXY_USER, "");
        data.put(alias + PROXY_PASS, "");
    }
    
    // return all the key with an alias
    public static Set<String> getAllAliasKeys(String alias) {
        alias += ".";
        Set<String> keys = new LinkedHashSet<String>();
        keys.add(alias + SCEP_OPERATIONMODE);
        keys.add(alias + SCEP_INCLUDE_CA);
        keys.add(alias + SCEP_RETURN_CA_CHAIN_IN_GETCACERT);
        keys.add(alias + SCEP_ALLOW_LEGACY_DIGEST_ALGORITHM);
        keys.add(alias + SCEP_RA_CERTPROFILE);
        keys.add(alias + SCEP_RA_ENTITYPROFILE);
        keys.add(alias + SCEP_RA_DEFAULTCA);
        keys.add(alias + SCEP_RA_AUTHPWD);
        keys.add(alias + SCEP_RA_NAME_GENERATION_SCHEME);
        keys.add(alias + SCEP_RA_NAME_GENERATION_PARAMETERS);
        keys.add(alias + SCEP_RA_NAME_GENERATION_PREFIX);
        keys.add(alias + SCEP_RA_NAME_GENERATION_POSTFIX);
        keys.add(alias + SCEP_CLIENT_CERTIFICATE_RENEWAL);
        keys.add(alias + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
        
        keys.add(alias + SCEP_USE_INTUNE);
        keys.add(alias + AUTH_AUTHORITY);
        keys.add(alias + AAD_APP_ID);
        keys.add(alias + AAD_USE_KEY_BINDING);
        keys.add(alias + AAD_APP_KEY);
        keys.add(alias + AAD_APP_KEY_BINDING);
        keys.add(alias + TENANT);
        keys.add(alias + INTUNE_RESOURCE_URL);
        keys.add(alias + GRAPH_API_VERSION);
        keys.add(alias + GRAPH_RESOURCE_URL);
        keys.add(alias + PROXY_HOST);
        keys.add(alias + PROXY_PORT);
        keys.add(alias + PROXY_USER);
        keys.add(alias + PROXY_PASS);
        return keys;
    }
    
    /**
     * Client Certificate Renewal is defined in the SCEP draft as the capability of a certificate enrollment request to be interpreted as a 
     * certificate renewal request if the previous certificate has passed half its validity. 
     * 
     * @param alias A SCEP configuration alias
     * @return true of SCEP Client Certificate Renewal is enabled
     */
    public boolean getClientCertificateRenewal(final String alias) {
        String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL;
        String value = getValue(key, alias);
        //Lazy initialization for SCEP configurations older than 6.3.1
        if(value == null) {
            data.put(alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL, DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
            return Boolean.getBoolean(DEFAULT_CLIENT_CERTIFICATE_RENEWAL);
        }
        return Boolean.valueOf(value);
    }
    /**
     * @see ScepConfiguration#getClientCertificateRenewal(String)
     * 
     * @param alias A SCEP configuration alias
     * @param clientCertificateRenewal true of Client Certificate Renewal is to be enabled
     */
    public void setClientCertificateRenewal(String alias, boolean clientCertificateRenewal) {
        String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL;
        setValue(key,  Boolean.toString(clientCertificateRenewal), alias);
    }

    /**
     * @see ScepConfiguration#getClientCertificateRenewal(String) for information about Client Certificate Renewal
     * 
     * The SCEP draft makes it optional whether or not old keys may be reused during Client Certificate Renewal
     * 
     * @param alias A SCEP configuration alias
     * @return true of old keys are allowed Client Certificate Renewal
     */
    public boolean getAllowClientCertificateRenewalWithOldKey(final String alias) {
        String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY;
        String value = getValue(key, alias);
        //Lazy initialization for SCEP configurations older than 6.3.1
        if(value == null) {
            data.put(alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY, DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
            return Boolean.getBoolean(DEFAULT_ALLOW_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY);
        }
        return Boolean.valueOf(value);
    }
    
    /**
     * @see ScepConfiguration#getAllowClientCertificateRenewalWithOldKey(String)
     * 
     * @param alias A SCEP configuration alias
     * @param allowClientCertificateRenewalWithOldKey set true to allow Client Certificate Renewal using old keys
     */
    public void setAllowClientCertificateRenewalWithOldKey(String alias, boolean allowClientCertificateRenewalWithOldKey) {
        String key = alias + "." + SCEP_CLIENT_CERTIFICATE_RENEWAL_WITH_OLD_KEY;
        setValue(key, Boolean.toString(allowClientCertificateRenewalWithOldKey), alias);
    }
    
    /**
     * Get a boolean indicating whether the SCEP alias given as parameter is operating in
     * RA mode or CA mode.
     * 
     * @param alias the alias.
     * @return true if the alias is operating in RA mode, or false if the alias is operating in CA mode.
     */
    public boolean getRAMode(String alias) {
        String key = alias + "." + SCEP_OPERATIONMODE;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, Mode.RA.getResource());
    }
    public void setRAMode(String alias, boolean ramode) {
        String key = alias + "." + SCEP_OPERATIONMODE;
        setValue(key, ramode ? Mode.RA.getResource() : Mode.CA.getResource(), alias);
    }
    
    public boolean getIncludeCA(String alias) {
        String key = alias + "." + SCEP_INCLUDE_CA;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }
    
    public void setIncludeCA(String alias, boolean includeca) {
        String key = alias + "." + SCEP_INCLUDE_CA;
        setValue(key, Boolean.toString(includeca), alias);
    }
    
    public boolean getReturnCaChainInGetCaCert(String alias) {
        String key = alias + "." + SCEP_RETURN_CA_CHAIN_IN_GETCACERT;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }

    public void setReturnCaChainInGetCaCert(String alias, boolean returnCaChainInGetCaCert) {
        String key = alias + "." + SCEP_RETURN_CA_CHAIN_IN_GETCACERT;
        setValue(key, Boolean.toString(returnCaChainInGetCaCert), alias);
    } 

    
    public boolean getAllowLegacyDigestAlgorithm(String alias) {
        String key = alias + "." + SCEP_ALLOW_LEGACY_DIGEST_ALGORITHM;
        String value = getValue(key, alias);
        // Allow for SCEP configurations older than 7.5.1 to use SHA-1 in responses by default
        if(value == null) {
            data.put(alias + "." + SCEP_ALLOW_LEGACY_DIGEST_ALGORITHM, "true");
            return Boolean.getBoolean("true");
        }
        return StringUtils.equalsIgnoreCase(value, "true");
    }
        
    public void setAllowLegacyDigestAlgorithm(String alias, boolean allowLegacyDigestAlgorithm) {
        String key = alias + "." + SCEP_ALLOW_LEGACY_DIGEST_ALGORITHM;
        setValue(key, Boolean.toString(allowLegacyDigestAlgorithm), alias);
    }
    
    public String getRACertProfile(String alias) {
        String key = alias + "." + SCEP_RA_CERTPROFILE;
        return getValue(key, alias);
    }
    public void setRACertProfile(String alias, String cp) {
        String key = alias + "." + SCEP_RA_CERTPROFILE;
        setValue(key, cp, alias);
    }
    
    public String getRAEndEntityProfile(String alias) {
        String key = alias + "." + SCEP_RA_ENTITYPROFILE;
        return getValue(key, alias);
    }
    public void setRAEndEntityProfile(String alias, String eep) {
        String key = alias + "." + SCEP_RA_ENTITYPROFILE;
        setValue(key, eep, alias);
    }
    
    public String getRADefaultCA(String alias) {
        String key = alias + "." + SCEP_RA_DEFAULTCA;
        return getValue(key, alias);
    }
    public void setRADefaultCA(String alias, String ca) {
        String key = alias + "." + SCEP_RA_DEFAULTCA;
        setValue(key, ca, alias);
    }

    public String getRAAuthPassword(String alias) {
        String key = alias + "." + SCEP_RA_AUTHPWD;
        return getDecryptedValue(getValue(key, alias));
    }
    public void setRAAuthpassword(String alias, String pwd) {
        String key = alias + "." + SCEP_RA_AUTHPWD;
        setValue(key, getEncryptedValue(pwd), alias);
    }

    public String getRANameGenerationScheme(String alias) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_SCHEME;
        return getValue(key, alias);
    }
    public void setRANameGenerationScheme(String alias, String scheme) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_SCHEME;
        setValue(key, scheme, alias);
    }

    public String getRANameGenerationParameters(String alias) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_PARAMETERS;
        return getValue(key, alias);
    }
    public void setRANameGenerationParameters(String alias, String parameters) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_PARAMETERS;
        setValue(key, parameters, alias);
    }

    public String getRANameGenerationPrefix(String alias) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_PREFIX;
        return getValue(key, alias);
    }
    public void setRANameGenerationPrefix(String alias, String prefix) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_PREFIX;
        setValue(key, prefix, alias);
    }

    public String getRANameGenerationPostfix(String alias) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_POSTFIX;
        return getValue(key, alias);
    }
    public void setRANameGenerationPostfix(String alias, String postfix) {
        String key = alias + "." + SCEP_RA_NAME_GENERATION_POSTFIX;
        setValue(key, postfix, alias);
    }
    
    public void setUseIntune(final String alias, final boolean useIntune) {
        String key = alias + "." + SCEP_USE_INTUNE;
        setValue(key, Boolean.toString(useIntune), alias);
    }
    
    public boolean getUseIntune(final String alias) {
        String key = alias + "." + SCEP_USE_INTUNE;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, Boolean.TRUE.toString());
    }
    
    public void setIntuneAuthority(final String alias, final String value) {
        String key = alias + "." + AUTH_AUTHORITY;
        setValue(key, value, alias);
    }

    public String getIntuneAuthority(final String alias) {
        String key = alias + "." + AUTH_AUTHORITY;
        return getValue(key, alias);
    }
    
    public void setIntuneAadAppId(final String alias, final String value) {
        String key = alias + "." + AAD_APP_ID;
        setValue(key, value, alias);
    }
    
    public String getIntuneAadAppId(final String alias) {
        String key = alias + "." + AAD_APP_ID;
        return getValue(key, alias);
    }
    
    public boolean getIntuneAadUseKeyBinding(final String alias) {
        final String key = alias + "." + AAD_USE_KEY_BINDING;
        return Boolean.valueOf(getValue(key, alias));
    }
    
    public void setIntuneAadUseKeyBinding(final String alias, final boolean value) {
        String key = alias + "." + AAD_USE_KEY_BINDING;
        setValue(key, Boolean.toString(value), alias);
    }

    public void setIntuneAadAppKey(final String alias, final String value) {
        String key = alias + "." + AAD_APP_KEY;
        setValue(key, getEncryptedValue(value), alias);
    }
    
    public String getIntuneAadAppKey(final String alias) {
        String key = alias + "." + AAD_APP_KEY;
        return getDecryptedValue(getValue(key, alias));
    }

    public String getIntuneAadAppKeyBinding(final String alias) {
        String key = alias + "." + AAD_APP_KEY_BINDING;
        return getValue(key, alias);
    }

    public void setIntuneAadAppKeyBinding(final String alias, final String value) {
        String key = alias + "." + AAD_APP_KEY_BINDING;
        setValue(key, value, alias);
    }

    public void setIntuneTenant(final String alias, final String value) {
        String key = alias + "." + TENANT;
        setValue(key, value, alias);
    }
    
    public String getIntuneTenant(final String alias) {
        String key = alias + "." + TENANT;
        return getValue(key, alias);
    }
    
    public void setIntuneResourceUrl(final String alias, final String value) {
        String key = alias + "." + INTUNE_RESOURCE_URL;
        setValue(key, value, alias);
    }
    
    public String getIntuneResourceUrl(final String alias) {
        String key = alias + "." + INTUNE_RESOURCE_URL;
        return getValue(key, alias);
    }
    
    public void setIntuneGraphApiVersion(final String alias, final String value) {
        String key = alias + "." + GRAPH_API_VERSION;
        setValue(key, value, alias);
    }
    
    public String getIntuneGraphApiVersion(final String alias) {
        String key = alias + "." + GRAPH_API_VERSION;
        return getValue(key, alias);
    }

    public void setIntuneGraphResourceUrl(final String alias, final String value) {
        String key = alias + "." + GRAPH_RESOURCE_URL;
        setValue(key, value, alias);
    }
    
    public String getIntuneGraphResourceUrl(final String alias) {
        String key = alias + "." + GRAPH_RESOURCE_URL;
        return getValue(key, alias);
    }
        
    public void setIntuneProxyHost(final String alias, final String value) {
        String key = alias + "." + PROXY_HOST;
        setValue(key, value, alias);
    }
    
    public String getIntuneProxyHost(final String alias) {
        String key = alias + "." + PROXY_HOST;
        return getValue(key, alias);
    }
    
    public void setIntuneProxyPort(final String alias, final String value) {
        String key = alias + "." + PROXY_PORT;
        setValue(key, value, alias);
    }
    
    public String getIntuneProxyPort(final String alias) {
        String key = alias + "." + PROXY_PORT;
        return getValue(key, alias);
    }
        
    public void setIntuneProxyUser(final String alias, final String value) {
        String key = alias + "." + PROXY_USER;
        setValue(key, value, alias);
    }
    
    public String getIntuneProxyUser(final String alias) {
        String key = alias + "." + PROXY_USER;
        return getValue(key, alias);
    }
    
    public void setIntuneProxyPass(final String alias, final String value) {
        String key = alias + "." + PROXY_PASS;
        setValue(key, getEncryptedValue(value), alias);
    }
    
    public String getIntuneProxyPass(final String alias) {
        String key = alias + "." + PROXY_PASS;
        return getDecryptedValue(getValue(key, alias));
    }

    public Properties getIntuneProperties(final String alias) {
        Properties intuneProperties = new Properties();
        intuneProperties.put("PROVIDER_NAME_AND_VERSION", GlobalConfiguration.EJBCA_VERSION);
        if (StringUtils.isNotBlank(getIntuneAuthority(alias))) {
            intuneProperties.put("AUTH_AUTHORITY", getIntuneAuthority(alias));
        }
        if (StringUtils.isNotBlank(getIntuneAadAppId(alias))) {
            intuneProperties.put("AAD_APP_ID", getIntuneAadAppId(alias));
        }
        intuneProperties.put("AAD_USE_KEY_BINDING", Boolean.toString(getIntuneAadUseKeyBinding(alias)));
        if (!getIntuneAadUseKeyBinding(alias) && StringUtils.isNotBlank(getIntuneAadAppKey(alias))) {
            intuneProperties.put("AAD_APP_KEY", getIntuneAadAppKey(alias));
        }
        if (getIntuneAadUseKeyBinding(alias) && StringUtils.isNotBlank(getIntuneAadAppKeyBinding(alias))) {
            intuneProperties.put("AAD_APP_KEY_BINDING", getIntuneAadAppKeyBinding(alias));
        }
        if (StringUtils.isNotBlank(getIntuneTenant(alias))) {
            intuneProperties.put("TENANT", getIntuneTenant(alias));
        }
        if (StringUtils.isNotBlank(getIntuneResourceUrl(alias))) {
            intuneProperties.put("INTUNE_RESOURCE_URL", getIntuneResourceUrl(alias));
        }
        if (StringUtils.isNotBlank(getIntuneGraphApiVersion(alias))) {
            intuneProperties.put("GRAPH_API_VERSION", getIntuneGraphApiVersion(alias));
        }
        if (StringUtils.isNotBlank(getIntuneGraphResourceUrl(alias))) {
            intuneProperties.put("GRAPH_RESOURCE_URL", getIntuneGraphResourceUrl(alias));
        }
        if (StringUtils.isNotBlank(getIntuneProxyHost(alias))) {
            intuneProperties.put("PROXY_HOST", getIntuneProxyHost(alias));
        }
        if (StringUtils.isNotBlank(getIntuneProxyPort(alias))) {
            intuneProperties.put("PROXY_PORT", getIntuneProxyPort(alias));
        }
        if (StringUtils.isNotBlank(getIntuneProxyUser(alias))) {
            intuneProperties.put("PROXY_USER", getIntuneProxyUser(alias));
        }
        if (StringUtils.isNotBlank(getIntuneProxyPass(alias))) {
            intuneProperties.put("PROXY_PASS", getIntuneProxyPass(alias));
        }
        return intuneProperties;
    }
    
    public String getValue(String key, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                if (data.get(key) instanceof Boolean) {
                    return Boolean.toString((Boolean) data.get(key));
                }
                return (String) data.get(key);
            } else {
                log.info("Could not find key '" + key + "' in the SCEP configuration data");
            }
        } else {
            log.info("SCEP alias '" + alias + "' does not exist trying to get value for '" + key + "'");
        }
        return null;
    }
    public void setValue(String key, String value, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Added '" + key + "=" + value + "' to the SCEP configuration data");
                }
            } else {
                log.info("Key '" + key + "' does not exist in the SCEP configuration data");
            }
        } else {
            log.info("SCEP alias '" + alias + "' does not exist trying to set value for '" + key + "'");
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
    public boolean aliasExists(String alias) {
        if(StringUtils.isNotEmpty(alias)) {
            Set<String> aliases = getAliasList();
            return aliases.contains(alias);
        }
        return false;
    }

    public void addAlias(String alias) {
        if(log.isDebugEnabled()) {
            log.debug("Adding SCEP alias: " + alias);
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
                log.debug("SCEP alias '" + alias + "' already exists.");
            }
            return;
        }
        
        initialize(alias);
        aliases.add(alias);
        data.put(ALIAS_LIST, aliases);
    }
    public void removeAlias(String alias) {
        if(log.isDebugEnabled()) {
            log.debug("Removing SCEP alias: " + alias);
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
                log.debug("SCEP alias '" + alias + "' does not exist");
            }
            return;
        }
        
        Set<String> removeKeys = getAllAliasKeys(alias);
        Iterator<String> itr = removeKeys.iterator();
        while(itr.hasNext()) {
            String key = itr.next();
            data.remove(key);
        }
        aliases.remove(alias);
        data.put(ALIAS_LIST, aliases);
    }
    public void renameAlias(String oldAlias, String newAlias) {
        if(log.isDebugEnabled()) {
            log.debug("Renaming SCEP alias '" + oldAlias + "' to '" + newAlias + "'");
        }
        
        if(StringUtils.isEmpty(oldAlias) || StringUtils.isEmpty(newAlias)) {
            log.info("No alias is renamed because one or both aliases were not provided.");
            return;
        }
        
        Set<String> aliases = getAliasList();
        if(!aliases.contains(oldAlias)) {
            log.info("Cannot rename. SCEP alias '" + oldAlias + "' does not exists.");
            return;
        }
        
        if(aliases.contains(newAlias)) {
            log.info("Cannot rename. SCEP alias '" + newAlias + "' already exists.");
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
            log.debug("Cloning SCEP alias '" + originAlias + "' to '" + cloneAlias + "'");
        }
        
        if(StringUtils.isEmpty(originAlias) || StringUtils.isEmpty(cloneAlias)) {
            log.info("No alias is cloned because one or both aliased were not provided");
            return;
        }
        
        Set<String> aliases = getAliasList();
        if(!aliases.contains(originAlias)) {
            log.info("Cannot clone. SCEP alias '" + originAlias + "' does not exist.");
            return;
        }
        
        if(aliases.contains(cloneAlias)) {
            log.info("Cannot clone. SCEP alias '" + cloneAlias + "' already exists.");
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
    
    
    
     
    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implementation of UpgradableDataHashMap function upgrade. */

    @Override
    public void upgrade(){
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            log.info("Upgrading ScepConfiguration from version " + getVersion() + " to " + LATEST_VERSION);
            //V4.0
            for (String alias : getAliasList()) {
                alias += ".";
                if (data.get(alias + SCEP_USE_INTUNE) == null) {
                    data.put(alias + SCEP_USE_INTUNE, Boolean.FALSE.toString());
                }
                if (data.get(alias + AUTH_AUTHORITY) == null) {
                    data.put(alias + AUTH_AUTHORITY, "");
                }
                if (data.get(alias + AAD_APP_ID) == null) {
                    data.put(alias + AAD_APP_ID, "");
                }
                if (data.get(alias + AAD_APP_KEY) == null) {
                    data.put(alias + AAD_APP_KEY, "");
                }
                if (data.get(alias + AAD_USE_KEY_BINDING) == null) {
                    data.put(alias + AAD_USE_KEY_BINDING, Boolean.FALSE.toString());
                }
                if (data.get(alias + AAD_APP_KEY_BINDING) == null) {
                    data.put(alias + AAD_APP_KEY_BINDING, "");
                }
                if (data.get(alias + TENANT) == null) {
                    data.put(alias + TENANT, "");
                }
                if (data.get(alias + INTUNE_RESOURCE_URL) == null) {
                    data.put(alias + INTUNE_RESOURCE_URL, "");
                }
                if (data.get(alias + GRAPH_API_VERSION) == null) {
                    data.put(alias + GRAPH_API_VERSION, "");
                }
                if (data.get(alias + GRAPH_RESOURCE_URL) == null) {
                    data.put(alias + GRAPH_RESOURCE_URL, "");
                }
                if (data.get(alias + PROXY_HOST) == null) {
                    data.put(alias + PROXY_HOST, "");
                }
                if (data.get(alias + PROXY_PORT) == null) {
                    data.put(alias + PROXY_PORT, "");
                }
                if (data.get(alias + PROXY_USER) == null) {
                    data.put(alias + PROXY_USER, "");
                }
                if (data.get(alias + PROXY_PASS) == null) {
                    data.put(alias + PROXY_PASS, "");
                }
                if (data.get(alias + SCEP_RETURN_CA_CHAIN_IN_GETCACERT) == null) {
                    data.put(alias + SCEP_RETURN_CA_CHAIN_IN_GETCACERT, Boolean.FALSE.toString());
                }
            }
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));         
        }
    }

    @Override
    public String getConfigurationId() {
        return SCEP_CONFIGURATION_ID;
    }

    
    @Override
    public void filterDiffMapForLogging(Map<Object,Object> diff) {
        Set<String> aliases = getAliasList();
        for (String alias : aliases) {
            filterDiffMapForLogging(diff, alias + "." + SCEP_RA_AUTHPWD);
            filterDiffMapForLogging(diff, alias + "." + AAD_APP_KEY);
            filterDiffMapForLogging(diff, alias + "." + PROXY_PASS);            
        }
    }

    
}
