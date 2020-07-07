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
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;
import org.ejbca.core.model.ra.UsernameGeneratorParams;

/**
 * Configuration of the SCEP protocol.
 * 
 * @version $Id$
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
    public static final String SERVICE_VERSION_PROP_NAME = "intuneServiceVersionPropName";
    public static final String AAD_APP_ID = "intuneAadAppId";
    public static final String AAD_APP_KEY = "intuneAadAppKey";
    public static final String TENANT = "intuneTenant";
    public static final String INTUNE_APP_ID = "intuneAppId";
    public static final String INTUNE_RESOURCE_URL = "intuneResourceUrl";
    public static final String GRAPH_API_VERSION = "intuneGraphApiVersion";
    public static final String GRAPH_RESOURCE_URL = "intuneGraphResourceUrl";
    public static final String PROXY_HOST = "intuneProxyHost";
    public static final String PROXY_PORT = "intuneProxyPort";
    public static final String PROXY_USER = "intuneProxyUser";
    public static final String PROXY_PASS = "intuneProxyPass";
    public static final String AUTH_AUTHORITY = "intuneAuthAuthority";
       
    // This List is used in the command line handling of updating a config value to insure a correct value.
    public static final List<String> SCEP_BOOLEAN_KEYS = Arrays.asList(SCEP_INCLUDE_CA);
    
    public static final String SCEP_CONFIGURATION_ID = "2";
    

    private final String ALIAS_LIST = "aliaslist";
 
    // Default Values
    public static final float LATEST_VERSION = 4f;
    public static final String EJBCA_VERSION = InternalConfiguration.getAppVersion();
    
    
    public static final Set<String> DEFAULT_ALIAS_LIST      = new LinkedHashSet<String>();
    public static final String DEFAULT_OPERATION_MODE = Mode.CA.getResource();
    public static final String DEFAULT_INCLUDE_CA = Boolean.TRUE.toString();
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
    
    public static final String DEFAULT_INTUNE_RESOURCE_URL = "https://api.manage.microsoft.com/";
    public static final String DEFAULT_INTUNE_GRAPH_API_VERSION = "1.6";
    public static final String DEFAULT_INTUNE_GRAPH_RESOURCE_URL = "https://graph.windows.net/";
    public static final String DEFAULT_INTUNE_AUTH_AUTHORITY = "https://login.microsoftonline.com/";
    
    
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
        if(StringUtils.isNotEmpty(alias)) {
            data.put(alias + SCEP_OPERATIONMODE, DEFAULT_OPERATION_MODE);
            data.put(alias + SCEP_INCLUDE_CA, DEFAULT_INCLUDE_CA);
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
            data.put(alias + SERVICE_VERSION_PROP_NAME, "");
            data.put(alias + AAD_APP_ID, "");
            data.put(alias + AAD_APP_KEY, "");
            data.put(alias + TENANT, "");
            data.put(alias + INTUNE_APP_ID, "");
            data.put(alias + INTUNE_RESOURCE_URL, DEFAULT_INTUNE_RESOURCE_URL);
            data.put(alias + GRAPH_API_VERSION, DEFAULT_INTUNE_GRAPH_API_VERSION);
            data.put(alias + GRAPH_RESOURCE_URL, DEFAULT_INTUNE_GRAPH_RESOURCE_URL);
            data.put(alias + PROXY_HOST, "");
            data.put(alias + PROXY_PORT, "");
            data.put(alias + PROXY_USER, "");
            data.put(alias + PROXY_PASS, "");
            data.put(alias + AUTH_AUTHORITY, DEFAULT_INTUNE_AUTH_AUTHORITY);
               
        }
    }
    
    // return all the key with an alias
    public static Set<String> getAllAliasKeys(String alias) {
        alias += ".";
        Set<String> keys = new LinkedHashSet<String>();
        keys.add(alias + SCEP_OPERATIONMODE);
        keys.add(alias + SCEP_INCLUDE_CA);
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
        keys.add(alias + SERVICE_VERSION_PROP_NAME);
        keys.add(alias + AAD_APP_ID);
        keys.add(alias + AAD_APP_KEY);
        keys.add(alias + TENANT);
        keys.add(alias + INTUNE_APP_ID);
        keys.add(alias + INTUNE_RESOURCE_URL);
        keys.add(alias + GRAPH_API_VERSION);
        keys.add(alias + GRAPH_RESOURCE_URL);
        keys.add(alias + PROXY_HOST);
        keys.add(alias + PROXY_PORT);
        keys.add(alias + PROXY_USER);
        keys.add(alias + PROXY_PASS);
        keys.add(alias + AUTH_AUTHORITY);
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
        return getValue(key, alias);
    }
    public void setRAAuthpassword(String alias, String pwd) {
        String key = alias + "." + SCEP_RA_AUTHPWD;
        setValue(key, pwd, alias);
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
    
    public void setIntuneServiceVersionPropName(final String alias, final String value) {
        String key = alias + "." + SERVICE_VERSION_PROP_NAME;
        setValue(key, value, alias);
    }
    
    public String getIntuneServiceVersionPropName(final String alias) {
        String key = alias + "." + SERVICE_VERSION_PROP_NAME;
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
    
    public void setIntuneAadAppKey(final String alias, final String value) {
        String key = alias + "." + AAD_APP_KEY;
        setValue(key, value, alias);
    }
    
    public String getIntuneAadAppKey(final String alias) {
        String key = alias + "." + AAD_APP_KEY;
        return getValue(key, alias);
    }
    
    public void setIntuneTenant(final String alias, final String value) {
        String key = alias + "." + TENANT;
        setValue(key, value, alias);
    }
    
    public String getIntuneTenant(final String alias) {
        String key = alias + "." + TENANT;
        return getValue(key, alias);
    }
    
    public void setIntuneAppId(final String alias, final String value) {
        String key = alias + "." + INTUNE_APP_ID;
        setValue(key, value, alias);
    }
    
    public String getIntuneAppId(final String alias) {
        String key = alias + "." + INTUNE_APP_ID;
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
        setValue(key, value, alias);
    }
    
    public String getIntuneProxyPass(final String alias) {
        String key = alias + "." + PROXY_PASS;
        return getValue(key, alias);
    }
    
    public void setIntuneAuthAuthority(final String alias, final String value) {
        String key = alias + "." + AUTH_AUTHORITY;
        setValue(key, value, alias);
    }
    
    public String getIntuneAuthAuthority(final String alias) {
        String key = alias + "." + AUTH_AUTHORITY;
        return getValue(key, alias);
    }    
    
    public Properties getIntuneProperties(final String alias) {
        Properties intuneProperties = new Properties();

        intuneProperties.put("PROVIDER_NAME_AND_VERSION", GlobalConfiguration.EJBCA_VERSION);
        intuneProperties.put("AUTH_AUTHORITY", getIntuneAuthAuthority(alias));

        if (StringUtils.isNotBlank(getIntuneProxyHost(alias))) {
            intuneProperties.put("SERVICE_VERSION_PROP_NAME", getIntuneServiceVersionPropName(alias));
            intuneProperties.put("AAD_APP_ID", getIntuneAadAppId(alias));
            intuneProperties.put("AAD_APP_KEY", getIntuneAadAppKey(alias));
            intuneProperties.put("TENANT", getIntuneTenant(alias));
            intuneProperties.put("INTUNE_APP_ID", getIntuneAadAppId(alias));
            intuneProperties.put("INTUNE_RESOURCE_URL", getIntuneResourceUrl(alias));
            intuneProperties.put("GRAPH_API_VERSION", getIntuneGraphApiVersion(alias));
            intuneProperties.put("GRAPH_RESOURCE_URL", getIntuneGraphResourceUrl(alias));
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
                return (String) data.get(key);
            } else {
                log.error("Could not find key '" + key + "' in the SCEP configuration data");
            }
        } else {
            log.error("SCEP alias '" + alias + "' does not exist");
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
                log.error("Key '" + key + "' does not exist in the SCEP configuration data");
            }
        } else {
            log.error("SCEP alias '" + alias + "' does not exist");
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
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {    
            //V4.0 
            for (String alias : getAliasList()) {
                data.put(alias + SCEP_USE_INTUNE, Boolean.FALSE.toString());
                data.put(alias + SERVICE_VERSION_PROP_NAME, "");
                data.put(alias + AAD_APP_ID, "");
                data.put(alias + AAD_APP_KEY, "");
                data.put(alias + TENANT, "");
                data.put(alias + INTUNE_APP_ID, "");
                data.put(alias + INTUNE_RESOURCE_URL, DEFAULT_INTUNE_RESOURCE_URL);
                data.put(alias + GRAPH_API_VERSION, DEFAULT_INTUNE_GRAPH_API_VERSION);
                data.put(alias + GRAPH_RESOURCE_URL, DEFAULT_INTUNE_GRAPH_RESOURCE_URL);
                data.put(alias + PROXY_HOST, "");
                data.put(alias + PROXY_PORT, "");
                data.put(alias + PROXY_USER, "");
                data.put(alias + PROXY_PASS, "");
                data.put(alias + AUTH_AUTHORITY, DEFAULT_INTUNE_AUTH_AUTHORITY);
            }
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));         
        }
    }

    @Override
    public String getConfigurationId() {
        return SCEP_CONFIGURATION_ID;
    }
    
}
