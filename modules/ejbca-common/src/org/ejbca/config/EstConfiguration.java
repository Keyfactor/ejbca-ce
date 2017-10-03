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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
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
 * This is a  class containing Est configuration parameters.
 *
 * @version $Id: EstConfiguration.java 25659 2017-04-05 12:19:30Z aveen4711 $
 */
public class EstConfiguration extends ConfigurationBase implements Serializable {

    private static final long serialVersionUID = -2787354158199916828L;

    private static final Logger log = Logger.getLogger(EstConfiguration.class);
    
    // Constants: Configuration keys
    public static final String CONFIG_DEFAULTCA               = "defaultca";
    public static final String CONFIG_CERTPROFILE             = "certprofile";
    public static final String CONFIG_EEPROFILE           = "eeprofile";
    
    private final String ALIAS_LIST = "aliaslist";
    public static final String EST_CONFIGURATION_ID = "4";

    // Default Values
    public static final float LATEST_VERSION = 3f;
    public static final String EJBCA_VERSION = InternalConfiguration.getAppVersion();
    
    // Default values
    private static final Set<String> DEFAULT_ALIAS_LIST      = new LinkedHashSet<>();
    private static final String DEFAULT_DEFAULTCA = "";
    public static final String DEFAULT_EEPROFILE = "1";
    private static final String DEFAULT_CERTPROFILE = "ENDUSER";

    /** Creates a new instance of EstConfiguration */
    public EstConfiguration()  {
       super();
    }
    
    public EstConfiguration(Serializable dataobj) {
        @SuppressWarnings("unchecked")
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }
    
    /**
     * Copy constructor for {@link EstConfiguration}
     */
    public EstConfiguration(EstConfiguration estConfiguration) {
        super();
        setAliasList(new LinkedHashSet<String>());
        for(String alias : estConfiguration.getAliasList()) {
            addAlias(alias);
            for(String key : getAllAliasKeys(alias)) {
                String value = estConfiguration.getValue(key, alias);
                setValue(key, value, alias);
            }
        }
      }
    
    /** Initializes a new cmp configuration with default values. */
    public void initialize(String alias){
        if(StringUtils.isNotEmpty(alias)) {
            alias = alias + ".";
            data.put(alias + CONFIG_DEFAULTCA, DEFAULT_DEFAULTCA);   
            data.put(alias + CONFIG_CERTPROFILE, DEFAULT_CERTPROFILE);
            data.put(alias + CONFIG_EEPROFILE, DEFAULT_EEPROFILE); 
        }
    }
    
    // return all the key with an alias
    public static Set<String> getAllAliasKeys(String alias) {
        alias = alias + ".";
        Set<String> keys = new LinkedHashSet<>();
        keys.add(alias + CONFIG_DEFAULTCA);
        return keys;
    }

    /** Method used by the Admin GUI. */
    public String getDefaultCA(String alias) {
        String key = alias + "." + CONFIG_DEFAULTCA;
        return getValue(key, alias);
    }
    public void setDefaultCA(String alias, String defCA) {
        String key = alias + "." + CONFIG_DEFAULTCA;
        setValue(key, defCA, alias);
    }

    public String getCertProfile(String alias) {
        String key = alias + "." + CONFIG_CERTPROFILE;
        return getValue(key, alias);
    }
    public void setCertProfile(String alias, String cp) {
        String key = alias + "." + CONFIG_CERTPROFILE;
        setValue(key, cp, alias);
    }
    
    public String getEndEntityProfile(String alias) {
        String key = alias + "." + CONFIG_EEPROFILE;
        return getValue(key, alias);
    }
    public void setEndEntityProfile(String alias, String eep) {
        String key = alias + "." + CONFIG_EEPROFILE;
        setValue(key, eep, alias);
    }

    public String getValue(String key, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                return (String) data.get(key);
            } else {
                log.error("Could not find key '" + key + "' in the EST configuration data");
            }
        } else {
            log.error("EST alias '" + alias + "' does not exist");
        }
        return null;
    }

    public void setValue(String key, String value, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Added '" + key + "=" + value + "' to the EST configuration data");
                }
            } else {
                log.error("Key '" + key + "' does not exist in the EST configuration data");
            }
        } else {
            log.error("EST alias '" + alias + "' does not exist");
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
        return false;
    }

    public void addAlias(String alias) {
        if(log.isDebugEnabled()) {
            log.debug("Adding EST alias: " + alias);
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
                log.debug("EST alias '" + alias + "' already exists.");
            }
            return;
        }
        
        initialize(alias);
        aliases.add(alias);
        data.put(ALIAS_LIST, aliases);
    }

    public void removeAlias(String alias) {
        if(log.isDebugEnabled()) {
            log.debug("Removing EST alias: " + alias);
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
                log.debug("EST alias '" + alias + "' does not exist");
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
            log.debug("Renaming EST alias '" + oldAlias + "' to '" + newAlias + "'");
        }
        
        if(StringUtils.isEmpty(oldAlias) || StringUtils.isEmpty(newAlias)) {
            log.info("No alias is renamed because one or both aliases were not provided.");
            return;
        }
        
        Set<String> aliases = getAliasList();
        if(!aliases.contains(oldAlias)) {
            log.info("Cannot rename. EST alias '" + oldAlias + "' does not exists.");
            return;
        }
        
        if(aliases.contains(newAlias)) {
            log.info("Cannot rename. EST alias '" + newAlias + "' already exists.");
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
            log.debug("Cloning EST alias '" + originAlias + "' to '" + cloneAlias + "'");
        }
        
        if(StringUtils.isEmpty(originAlias) || StringUtils.isEmpty(cloneAlias)) {
            log.info("No alias is cloned because one or both aliased were not provided");
            return;
        }
        
        Set<String> aliases = getAliasList();
        if(!aliases.contains(originAlias)) {
            log.info("Cannot clone. EST alias '" + originAlias + "' does not exist.");
            return;
        }
        
        if(aliases.contains(cloneAlias)) {
            log.info("Cannot clone. EST alias '" + cloneAlias + "' already exists.");
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
    public float getLatestVersion() {
       return LATEST_VERSION;
    }

    /** Implementation of UpgradableDataHashMap function upgrade. */
    @Override
    public void upgrade() {
        if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));          
        }
    }

    @Override
    public String getConfigurationId() {
        return EST_CONFIGURATION_ID;
    }

}







