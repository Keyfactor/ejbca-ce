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

/**
 * 
 * @version $Id$
 *
 */

public class ScepConfiguration extends ConfigurationBase implements Serializable {
    
    
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
    
    
    
    // This List is used in the command line handling of updating a config value to insure a correct value.
    public static final List<String> SCEP_BOOLEAN_KEYS = Arrays.asList(SCEP_INCLUDE_CA);
    
    private final String ALIAS_LIST = "aliaslist";
    public static final String SCEP_CONFIGURATION_ID = "2";
    
    private static final long serialVersionUID = -2051789798029184421L;

    private static final Logger log = Logger.getLogger(ScepConfiguration.class);
    
    
    // Default Values
    public static final float LATEST_VERSION = 3f;
    public static final String EJBCA_VERSION = InternalConfiguration.getAppVersion();
    
    
    public static final Set<String> DEFAULT_ALIAS_LIST      = new LinkedHashSet<String>();
    public static final String DEFAULT_OPERATION_MODE = "ca";
    public static final String DEFAULT_INCLUDE_CA = "true";
    public static final String DEFAULT_RA_CERTPROFILE = "ENDUSER";
    public static final String DEFAULT_RA_ENTITYPROFILE = "EMPTY";
    public static final String DEFAULT_RA_DEFAULTCA = "";
    public static final String DEFAULT_RA_AUTHPWD = "";
    public static final String DEFAULT_RA_NAME_GENERATION_SCHEME = "DN";
    public static final String DEFAULT_RA_NAME_GENERATION_PARAMETERS = "CN";
    public static final String DEFAULT_RA_NAME_GENERATION_PREFIX = "";
    public static final String DEFAULT_RA_NAME_GENERATION_POSTFIX = "";
    
    
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
        return keys;
    }

    /** Method used by the Admin GUI. */
    public boolean getRAMode(String alias) {
        String key = alias + "." + SCEP_OPERATIONMODE;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "ra");
    }
    public void setRAMode(String alias, boolean ramode) {
        String key = alias + "." + SCEP_OPERATIONMODE;
        setValue(key, ramode? "ra" : "ca", alias);
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
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));          
        }
    }

    @Override
    public String getConfigurationId() {
        return SCEP_CONFIGURATION_ID;
    }
    
}
