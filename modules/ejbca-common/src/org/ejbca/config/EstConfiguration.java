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
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.configuration.ConfigurationBase;


/**
 * This is a  class containing EST configuration parameters.
 *
 * @version $Id$
 */
public class EstConfiguration extends ConfigurationBase implements Serializable {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(EstConfiguration.class);

    // Constants: Configuration keys
    public static final String CONFIG_DEFAULTCA     = "defaultca";
    public static final String CONFIG_CERTPROFILE   = "certprofile";
    public static final String CONFIG_EEPROFILE     = "eeprofile";
    public static final String CONFIG_REQCERT       = "requirecert";
    public static final String CONFIG_REQUSERNAME   = "requsername";
    public static final String CONFIG_REQPASSWORD   = "reqpassword";
    public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY  = "allowupdatewithsamekey";
    public static final String CONFIG_RA_NAMEGENERATIONSCHEME = "ra.namegenerationscheme";
    public static final String CONFIG_RA_NAMEGENERATIONPARAMS = "ra.namegenerationparameters";
    public static final String CONFIG_RA_NAMEGENERATIONPREFIX = "ra.namegenerationprefix";
    public static final String CONFIG_RA_NAMEGENERATIONPOSTFIX= "ra.namegenerationpostfix";

    private final String ALIAS_LIST = "aliaslist";
    public static final String EST_CONFIGURATION_ID = "4";

    // Default Values
    public static final float LATEST_VERSION = 3f;
    public static final String EJBCA_VERSION = InternalConfiguration.getAppVersion();

    // Default values
    private static final Set<String> DEFAULT_ALIAS_LIST      = new LinkedHashSet<>();
    private static final String DEFAULT_DEFAULTCA = "";
    public static final String DEFAULT_EEPROFILE = String.valueOf(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
    private static final String DEFAULT_CERTPROFILE = String.valueOf(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    private static final String DEFAULT_REQCERT = "true";
    private static final String DEFAULT_REQUSERNAME = "";
    private static final String DEFAULT_REQPASSWORD = "";
    private static final String DEFAULT_ALLOWUPDATEWITHSAMEKEY = "true";
    private static final String DEFAULT_RA_USERNAME_GENERATION_SCHEME = "DN";
    private static final String DEFAULT_RA_USERNAME_GENERATION_PARAMS = "CN";
    private static final String DEFAULT_RA_USERNAME_GENERATION_PREFIX = "";
    private static final String DEFAULT_RA_USERNAME_GENERATION_POSTFIX = "";

    // This List is used in the command line handling of updating a config value to ensure a correct value.
    public static final List<String> EST_BOOLEAN_KEYS = Arrays.asList(CONFIG_REQCERT, CONFIG_ALLOWUPDATEWITHSAMEKEY);

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
            data.put(alias + CONFIG_REQCERT, DEFAULT_REQCERT);
            data.put(alias + CONFIG_REQUSERNAME, DEFAULT_REQUSERNAME);
            data.put(alias + CONFIG_REQPASSWORD, DEFAULT_REQPASSWORD);
            data.put(alias + CONFIG_ALLOWUPDATEWITHSAMEKEY, DEFAULT_ALLOWUPDATEWITHSAMEKEY);
            data.put(alias + CONFIG_RA_NAMEGENERATIONSCHEME, DEFAULT_RA_USERNAME_GENERATION_SCHEME);
            data.put(alias + CONFIG_RA_NAMEGENERATIONPARAMS, DEFAULT_RA_USERNAME_GENERATION_PARAMS);
            data.put(alias + CONFIG_RA_NAMEGENERATIONPREFIX, DEFAULT_RA_USERNAME_GENERATION_PREFIX);
            data.put(alias + CONFIG_RA_NAMEGENERATIONPOSTFIX, DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
        }
    }

    // return all the key with an alias
    public static Set<String> getAllAliasKeys(String alias) {
        alias = alias + ".";
        Set<String> keys = new LinkedHashSet<>();
        keys.add(alias + CONFIG_DEFAULTCA);
        keys.add(alias + CONFIG_CERTPROFILE);
        keys.add(alias + CONFIG_EEPROFILE);
        keys.add(alias + CONFIG_REQCERT);
        keys.add(alias + CONFIG_REQUSERNAME);
        keys.add(alias + CONFIG_REQPASSWORD);
        keys.add(alias + CONFIG_ALLOWUPDATEWITHSAMEKEY);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONSCHEME);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONPARAMS);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONPREFIX);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONPOSTFIX);
        return keys;
    }

    /**
     * @param alias the EST alias to get value from
     * @return CA ID in String format, String format to be backwards compatible with EJBCA 6.11 when it was stored as CA Name instead of ID
     */
    public String getDefaultCAID(String alias) {
        String key = alias + "." + CONFIG_DEFAULTCA;
        return getValue(key, alias);
    }
    public void setDefaultCAID(String alias, int defaultCAID) {
        String key = alias + "." + CONFIG_DEFAULTCA;
        setValue(key, String.valueOf(defaultCAID), alias);
    }

    /**
     * @param alias the EST alias to get value from
     * @return Certificate Profile ID in String format, String format to be backwards compatible with EJBCA 6.11 when it was stored as CP Name instead of ID
     */
    public String getCertProfileID(String alias) {
        String key = alias + "." + CONFIG_CERTPROFILE;
        return getValue(key, alias);
    }
    /**
     * @param alias the EST alias to edit
     * @param cprofileID Certificate Profile ID
     */
    public void setCertProfileID(String alias, int cprofileID) {
        String key = alias + "." + CONFIG_CERTPROFILE;
        setValue(key, String.valueOf(cprofileID), alias);
    }

    public int getEndEntityProfileID(String alias) {
        String key = alias + "." + CONFIG_EEPROFILE;
        try {
            Integer id = Integer.valueOf(getValue(key, alias));
            return id;
        } catch (NumberFormatException e) {
            log.error("Invalid End Entity Profile ID stored in EST alias, returning 0: "+alias, e);
            return 0;
        }
    }
    /**
     * @param alias the EST alias to edit
     * @param eeprofileID End Entity Profile ID
     */
    public void setEndEntityProfileID(String alias, int eeprofileID) {
        String key = alias + "." + CONFIG_EEPROFILE;
        setValue(key, String.valueOf(eeprofileID), alias);
    }

    /**
     * @param alias the alias to check for
     *
     * @return true if we require a certificate for authentication
     */
    public boolean getCert(String alias) {
        String key = alias + "." + CONFIG_REQCERT;
        return StringUtils.equalsIgnoreCase(getValue(key, alias), "true");
    }

    public void setCert(String alias, boolean reqCert) {
        String key = alias + "." + CONFIG_REQCERT;
        setValue(key, Boolean.toString(reqCert), alias);
    }

    /**
     * @param alias the alias to check for
     *
     * @return username if any, or null if none
     */
    public String getUsername(String alias) {
        String key = alias + "." + CONFIG_REQUSERNAME;
        return getValue(key, alias);
    }

    public void setUsername(String alias, String username) {
        String key = alias + "." + CONFIG_REQUSERNAME;
        setValue(key, username, alias);
    }

    /**
     * @param alias the alias to check for
     *
     * @return password if any, or null if none
     */
    public String getPassword(String alias) {
        String key = alias + "." + CONFIG_REQPASSWORD;
        return getValue(key, alias);
    }

    public void setPassword(String alias, String password) {
        String key = alias + "." + CONFIG_REQPASSWORD;
        setValue(key, password, alias);
    }

    /**
     * @param alias the alias to check for
     *
     * @return true if allowed to reenroll with the same key
     */
    public boolean getKurAllowSameKey(String alias) {
        String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }

    public void setKurAllowSameKey(String alias, boolean allowSameKey) {
        String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
        setValue(key, Boolean.toString(allowSameKey), alias);
    }

    public String getValue(String key, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                return (String) data.get(key);
            } else {
                log.info("Could not find key '" + key + "' in the EST configuration data");
            }
        } else {
            log.info("EST alias '" + alias + "' does not exist");
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
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Key '" + key + "' does not exist in the EST configuration data, adding it");
                }
            }
        } else {
            log.info("EST alias '" + alias + "' does not exist");
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
            log.debug("EST alias '" + alias+"' does not exist.");
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

    /**
     * Getter for RA Name Generation Scheme for given alias
     * @param alias the EST alias to get the name generation scheme for
     *
     */
    public String getRANameGenScheme(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
        
        //Set default to RANDOM for aliases greated before RA name generation was added
        String value = getValue(key, alias);
        if (value == null) {
            value = "RANDOM";
        }
        return value;
    }

    /**
     * Setter for RA Name Generation Scheme
     * @param alias the EST alias to set the name generation scheme for
     * @param scheme RA name generation scheme
     *
     */
    public void setRANameGenScheme(String alias, String scheme) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
        setValue(key, scheme, alias);
    }
    
    /**
     * Getter for RA Name Generation Params for given alias
     * @param alias the EST alias to get the name generation DN parameters for
     *
     */
    public String getRANameGenParams(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
        return getValue(key, alias);
    }

    /**
     * Setter for RA Name Generation Parameters
     * @param alias the EST alias to set the name generation DN parameters for
     * @param params RA name generation scheme DN parameters
     *
     */    
    public void setRANameGenParams(String alias, String params) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
        setValue(key, params, alias);
    }

    /**
     * Getter for RA Name Generation Prefix for given alias
     * @param alias the EST alias to get the name generation prefix for
     *
     */
    public String getRANameGenPrefix(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;

        //Set default to empty String for aliases greated before RA name generation was added
        String value = getValue(key, alias);
        if (value == null) {
            value = "";
        }
        return value;
    }


    /**
     * Setter for RA Name Generation Prefix
     * @param alias the EST alias to set the name generation prefix for
     * @param prefix RA name prefix
     *
     */ 
    public void setRANameGenPrefix(String alias, String prefix) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;
        setValue(key, prefix, alias);
    }
    

    /**
     * Getter for RA Name Generation Postfix
     * @param alias the EST alias to set the name generation postfix for
     *
     */     
    public String getRANameGenPostfix(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
        
        //Set default to empty String for aliases greated before RA name generation was added
        String value = getValue(key, alias);
        if (value == null) {
            value = "";
        }
        return value;
    }

     /**
     * Setter for RA Name Generation Postfix
     * @param alias the EST alias to set the name generation postfix for
     * @param postfix RA name postfix
     *
     */    
    public void setRANameGenPostfix(String alias, String postfix) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
        setValue(key, postfix, alias);
    }

}