/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.util.Collection;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;


/**
 * This is a  class containing CMP configuration parameters.
 *
 * @version $Id$
 */
public class CmpConfiguration extends Configuration implements Serializable {

    // Constants: Authentication modules
    public static final String AUTHMODULE_REG_TOKEN_PWD         = "RegTokenPwd";
    public static final String AUTHMODULE_DN_PART_PWD           = "DnPartPwd";
    public static final String AUTHMODULE_HMAC                  = "HMAC";
    public static final String AUTHMODULE_ENDENTITY_CERTIFICATE = "EndEntityCertificate";

    
    // Constants: Configuration keys
    public static final String CONFIG_DEFAULTCA               = "defaultca";
    public static final String CONFIG_ALLOWRAVERIFYPOPO       = "allowraverifypopo";
    public static final String CONFIG_OPERATIONMODE           = "operationmode";
    public static final String CONFIG_AUTHENTICATIONMODULE    = "authenticationmodule";
    public static final String CONFIG_AUTHENTICATIONPARAMETERS= "authenticationparameters";
    public static final String CONFIG_EXTRACTUSERNAMECOMPONENT= "extractusernamecomponent";
    public static final String CONFIG_RA_ALLOWCUSTOMCERTSERNO = "ra.allowcustomcertserno";
    public static final String CONFIG_RA_NAMEGENERATIONSCHEME = "ra.namegenerationscheme";
    public static final String CONFIG_RA_NAMEGENERATIONPARAMS = "ra.namegenerationparameters";
    public static final String CONFIG_RA_NAMEGENERATIONPREFIX = "ra.namegenerationprefix";
    public static final String CONFIG_RA_NAMEGENERATIONPOSTFIX= "ra.namegenerationpostfix";
    public static final String CONFIG_RA_PASSWORDGENPARAMS    = "ra.passwordgenparams";
    public static final String CONFIG_RA_ENDENTITYPROFILE     = "ra.endentityprofile";
    public static final String CONFIG_RA_CERTIFICATEPROFILE   = "ra.certificateprofile";
    public static final String CONFIG_RESPONSEPROTECTION      = "responseprotection";
    public static final String CONFIG_RACANAME                = "ra.caname";
    public static final String CONFIG_VENDORCERTIFICATEMODE   = "vendorcertificatemode"; 
    public static final String CONFIG_VENDORCA                = "vendorca";
    public static final String CONFIG_RACERT_PATH             = "racertificatepath";
    public static final String CONFIG_ALLOWAUTOMATICKEYUPDATE = "allowautomatickeyupdate";
    public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY  = "allowupdatewithsamekey";
    public static final String CONFIG_CERTREQHANDLER_CLASS    = "certreqhandler.class";
    public static final String CONFIG_UNIDDATASOURCE          = "uniddatasource";
    
    private final String ALIAS_LIST = "aliaslist";

    
    
    private static final long serialVersionUID = -2051789798029184421L;

    private static final Logger log = Logger.getLogger(CmpConfiguration.class);
    
    
    // Default Values
    public static final float LATEST_VERSION = 3f;
    public static final String EJBCA_VERSION = InternalConfiguration.getAppVersion();
    
    // Default values
    private static final Set<String> DEFAULT_ALIAS_LIST      = new HashSet<String>();
    private static final String DEFAULT_DEFAULTCA = "";
    private static final String DEFAULT_OPERATION_MODE = "client";
    private static final String DEFAULT_EXTRACT_USERNAME_COMPONENT = "DN";
    private static final String DEFAULT_VENDOR_MODE = "false";
    private static final String DEFAULT_VENDOR_CA = "";
    private static final String DEFAULT_KUR_ALLOW_AUTOMATIC_KEYUPDATE = "false";
    private static final String DEFAULT_KUR_ALLOW_SAME_KEY = "false";
    private static final String DEFAULT_RESPONSE_PROTECTION = "signature";
    private static final String DEFAULT_ALLOW_RA_VERIFY_POPO = "false"; 
    private static final String DEFAULT_RA_USERNAME_GENERATION_SCHEME = "DN";
    private static final String DEFAULT_RA_USERNAME_GENERATION_PARAMS = "CN";
    private static final String DEFAULT_RA_USERNAME_GENERATION_PREFIX = "";
    private static final String DEFAULT_RA_USERNAME_GENERATION_POSTFIX = "";
    private static final String DEFAULT_RA_PASSWORD_GENERARION_PARAMS = "random";
    private static final String DEFAULT_RA_ALLOW_CUSTOM_SERNO = "false";
    private static final String DEFAULT_RA_EEPROFILE = "EMPTY";
    private static final String DEFAULT_RA_CERTPROFILE = "ENDUSER";
    private static final String DEFAULT_RA_CANAME = "ManagementCA";
    private static final String DEFAULT_RA_AUTHENTICATION_MODULE = CmpConfiguration.AUTHMODULE_HMAC;
    private static final String DEFAULT_RA_AUTHENTICATION_PARAMS = "-";
    private static final String DEFAULT_CLIENT_AUTHENTICATION_MODULE = CmpConfiguration.AUTHMODULE_REG_TOKEN_PWD + ";" + CmpConfiguration.AUTHMODULE_HMAC;
    private static final String DEFAULT_CLIENT_AUTHENTICATION_PARAMS = "-;-";
    private static final String DEFAULT_RACERT_PATH = "";
    private static final String DEFAULT_CERTREQHANDLER = ""; //"org.ejbca.core.protocol.unid.UnidFnrHandler";
    private static final String DEFAULT_UNID_DATASOURCE = ""; //"java:/UnidDS";

    
    /** Creates a new instance of GlobalConfiguration */
    public CmpConfiguration()  {
       super();
    }
    
    public CmpConfiguration(Serializable dataobj) {
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }
    
    
    /** Initializes a new global configuration with data used in ra web interface. */
    public void initialize(String alias){
        
            alias = alias + ".";
            data.put(alias + CONFIG_DEFAULTCA, DEFAULT_DEFAULTCA);
            data.put(alias + CONFIG_RESPONSEPROTECTION, DEFAULT_RESPONSE_PROTECTION);
            data.put(alias + CONFIG_OPERATIONMODE, DEFAULT_OPERATION_MODE);
            data.put(alias + CONFIG_AUTHENTICATIONMODULE, DEFAULT_CLIENT_AUTHENTICATION_MODULE);
            data.put(alias + CONFIG_AUTHENTICATIONPARAMETERS, DEFAULT_CLIENT_AUTHENTICATION_PARAMS);
            data.put(alias + CONFIG_EXTRACTUSERNAMECOMPONENT, DEFAULT_EXTRACT_USERNAME_COMPONENT);
            data.put(alias + CONFIG_VENDORCERTIFICATEMODE, DEFAULT_VENDOR_MODE);
            data.put(alias + CONFIG_VENDORCA, DEFAULT_VENDOR_CA);
            data.put(alias + CONFIG_ALLOWRAVERIFYPOPO, DEFAULT_ALLOW_RA_VERIFY_POPO);
            data.put(alias + CONFIG_RA_NAMEGENERATIONSCHEME, DEFAULT_RA_USERNAME_GENERATION_SCHEME);
            data.put(alias + CONFIG_RA_NAMEGENERATIONPARAMS, DEFAULT_RA_USERNAME_GENERATION_PARAMS);
            data.put(alias + CONFIG_RA_NAMEGENERATIONPREFIX, DEFAULT_RA_USERNAME_GENERATION_PREFIX);
            data.put(alias + CONFIG_RA_NAMEGENERATIONPOSTFIX, DEFAULT_RA_USERNAME_GENERATION_POSTFIX);
            data.put(alias + CONFIG_RA_PASSWORDGENPARAMS, DEFAULT_RA_PASSWORD_GENERARION_PARAMS);
            data.put(alias + CONFIG_RA_ALLOWCUSTOMCERTSERNO, DEFAULT_RA_ALLOW_CUSTOM_SERNO);
            data.put(alias + CONFIG_RA_ENDENTITYPROFILE, DEFAULT_RA_EEPROFILE);
            data.put(alias + CONFIG_RA_CERTIFICATEPROFILE, DEFAULT_RA_CERTPROFILE);
            data.put(alias + CONFIG_RACANAME, DEFAULT_RA_CANAME);
            data.put(alias + CONFIG_RACERT_PATH, DEFAULT_RACERT_PATH);
            data.put(alias + CONFIG_ALLOWAUTOMATICKEYUPDATE, DEFAULT_KUR_ALLOW_AUTOMATIC_KEYUPDATE);       
            data.put(alias + CONFIG_ALLOWUPDATEWITHSAMEKEY, DEFAULT_KUR_ALLOW_SAME_KEY);
            data.put(alias + CONFIG_CERTREQHANDLER_CLASS, DEFAULT_CERTREQHANDLER);
            data.put(alias + CONFIG_UNIDDATASOURCE, DEFAULT_UNID_DATASOURCE);
    }
    
    public void initializeCmpConfig(String alias) {
        if(StringUtils.isNotEmpty(alias)) {
            initialize(alias);
        }
    }

    /** Checks if cmp configuration have been initialized. */
    public boolean isInitialized(){
      Set aliaslist = (Set) data.get(ALIAS_LIST);
      return aliaslist.size() > 0;
    }

    /** Method used by the Admin GUI. */
    public String getCMPDefaultCA(String alias) {
        String key = alias + "." + CONFIG_DEFAULTCA;
        return getValue(key, alias);
    }
    public void setCMPDefaultCA(String alias, String defCA) {
        String key = alias + "." + CONFIG_DEFAULTCA;
        setValue(key, defCA, alias);
    }
    
    
    public String getResponseProtection(String alias) {
        String key = alias + "." + CONFIG_RESPONSEPROTECTION;
        return getValue(key, alias);
    }
    public void setResponseProtection(String alias, String protection) {
        String key = alias + "." + CONFIG_RESPONSEPROTECTION;
        setValue(key, protection, alias);
    }
    
    
    public boolean getRAMode(String alias) {
        String key = alias + "." + CONFIG_OPERATIONMODE;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "ra");
    }
    public void setRAMode(String alias, boolean ramode) {
        String key = alias + "." + CONFIG_OPERATIONMODE;
        setValue(key, ramode? "ra" : "client", alias);
    }
    

    public String getAuthenticationModule(String alias) {
        String key = alias + "." + CONFIG_AUTHENTICATIONMODULE;
        return getValue(key, alias);
    }
    public void setAuthenticationModule(String alias, String authModule) {
        String key = alias + "." + CONFIG_AUTHENTICATIONMODULE;
        setValue(key, authModule, alias);
    }
    
    
    public String getAuthenticationParameters(String alias) {
        String key = alias + "." + CONFIG_AUTHENTICATIONPARAMETERS;
        return getValue(key, alias);
    }
    public void setAuthenticationParameters(String alias, String authParams) {
        String key = alias + "." + CONFIG_AUTHENTICATIONPARAMETERS;
        setValue(key, authParams, alias);
    }
    public String getAuthenticationParameter(String authModule, String alias) {

        if(StringUtils.isNotEmpty(alias)) {
            String confModule = getAuthenticationModule(alias);
            String confParams = getAuthenticationParameters(alias);
        
            String modules[] = confModule.split(";");
            String params[] = confParams.split(";");
        
            for(int i=0; i<modules.length; i++) {
                if(StringUtils.equals(modules[i].trim(), authModule)) {
                    return params[i];
                }
            }
        
            return "-";
        } else {
            return "-";
        }

    }
    
    
    public String getExtractUsernameComponent(String alias) {
        String key = alias + "." + CONFIG_EXTRACTUSERNAMECOMPONENT;
        return getValue(key, alias);
    }
    public void setExtractUsernameComponent(String alias, String extractComponent) {
        String key = alias + "." + CONFIG_EXTRACTUSERNAMECOMPONENT;
        setValue(key, extractComponent, alias);
    }
    
    
    public boolean getVendorMode(String alias) {
        String key = alias + "." + CONFIG_VENDORCERTIFICATEMODE;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }
    public void setVendorMode(String alias, boolean vendormode) {
        String key = alias + "." + CONFIG_VENDORCERTIFICATEMODE;
        setValue(key, Boolean.toString(vendormode), alias);
    }
    
    
    public String getVendorCA(String alias) {
        String key = alias + "." + CONFIG_VENDORCA;
        return getValue(key, alias);
    }
    public void setVendorCA(String alias, String vendorCA) {
        String key = alias + "." + CONFIG_VENDORCA;
        setValue(key, vendorCA, alias);
    }
    
    
    public boolean getAllowRAVerifyPOPO(String alias) {
        String key = alias + "." + CONFIG_ALLOWRAVERIFYPOPO;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }
    public void setAllowRAVerifyPOPO(String alias, boolean raVerifyPopo) {
        String key = alias + "." + CONFIG_ALLOWRAVERIFYPOPO;
        setValue(key, Boolean.toString(raVerifyPopo), alias);
    }
    
    
    public String getRANameGenScheme(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
        return getValue(key, alias);
    }
    public void setRANameGenScheme(String alias, String scheme) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONSCHEME;
        setValue(key, scheme, alias);
    }
    
    
    public String getRANameGenParams(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
        return getValue(key, alias);
    }
    public void setRANameGenParams(String alias, String params) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPARAMS;
        setValue(key, params, alias);
    }
    
    
    public String getRANameGenPrefix(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;
        return getValue(key, alias);
    }
    public void setRANameGenPrefix(String alias, String prefix) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPREFIX;
        setValue(key, prefix, alias);
    }
    
    
    public String getRANameGenPostfix(String alias) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
        return getValue(key, alias);
    }
    public void setRANameGenPostfix(String alias, String postfix) {
        String key = alias + "." + CONFIG_RA_NAMEGENERATIONPOSTFIX;
        setValue(key, postfix, alias);
    }
    
    
    public String getRAPwdGenParams(String alias) {
        String key = alias + "." + CONFIG_RA_PASSWORDGENPARAMS;
        return getValue(key, alias);
    }
    public void setRAPwdGenParams(String alias, String params) {
        String key = alias + "." + CONFIG_RA_PASSWORDGENPARAMS;
        setValue(key, params, alias);
    }
    
    public boolean getAllowRACustomSerno(String alias) {
        String key = alias + "." + CONFIG_RA_ALLOWCUSTOMCERTSERNO;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }
    public void setAllowRACustomSerno(String alias, boolean allowCustomSerno) {
        String key = alias + "." + CONFIG_RA_ALLOWCUSTOMCERTSERNO;
        setValue(key, Boolean.toString(allowCustomSerno), alias);
    }
    
    
    public String getRAEEProfile(String alias) {
        String key = alias + "." + CONFIG_RA_ENDENTITYPROFILE;
        return getValue(key, alias);
    }
    public void setRAEEProfile(String alias, String eep) {
        String key = alias + "." + CONFIG_RA_ENDENTITYPROFILE;
        setValue(key, eep, alias);
    }
    
    
    public String getRACertProfile(String alias) {
        String key = alias + "." + CONFIG_RA_CERTIFICATEPROFILE;
        return getValue(key, alias);
    }
    public void setRACertProfile(String alias, String certp) {
        String key = alias + "." + CONFIG_RA_CERTIFICATEPROFILE;
        setValue(key, certp, alias);
    }
    
    
    public String getRACAName(String alias) {
        String key = alias + "." + CONFIG_RACANAME;
        return getValue(key, alias);
    }
    public void setRACAName(String alias, String caname) {
        String key = alias + "." + CONFIG_RACANAME;
        setValue(key, caname, alias);
    }
    
    public String getRACertPath(String alias) {
        String key = alias + "." + CONFIG_RACERT_PATH;
        return getValue(key, alias);
    }
    public void setRACertPath(String alias, String certpath) {
        String key = alias + "." + CONFIG_RACERT_PATH;
        setValue(key, certpath, alias);
    }
    
    public boolean getKurAllowAutomaticUpdate(String alias) {
        String key = alias + "." + CONFIG_ALLOWAUTOMATICKEYUPDATE;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }
    public void setKurAllowAutomaticUpdate(String alias, boolean allowAutomaticUpdate) {
        String key = alias + "." + CONFIG_ALLOWAUTOMATICKEYUPDATE;
        setValue(key, Boolean.toString(allowAutomaticUpdate), alias);
    }
    
    
    public boolean getKurAllowSameKey(String alias) {
        String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
        String value = getValue(key, alias);
        return StringUtils.equalsIgnoreCase(value, "true");
    }
    public void setKurAllowSameKey(String alias, boolean allowSameKey) {
        String key = alias + "." + CONFIG_ALLOWUPDATEWITHSAMEKEY;
        setValue(key, Boolean.toString(allowSameKey), alias);
    }
    
    public String getCertReqHandlerClass(String alias) {
        String key = alias + "." + CONFIG_CERTREQHANDLER_CLASS;
        return getValue(key, alias);
    }
    public void setCertReqHandlerClass(String alias, String certReqClass) {
        String key = alias + "." + CONFIG_CERTREQHANDLER_CLASS;
        setValue(key, certReqClass, alias);
    }
    
    public String getUnidDataSource(String alias) {
        String key = alias + "." + CONFIG_UNIDDATASOURCE;
        return getValue(key, alias);
    }
    public void setUnidDataSource(String alias, String unidDataSource) {
        String key = alias + "." + CONFIG_UNIDDATASOURCE;
        setValue(key, unidDataSource, alias);
    }
    
    
    
    public String getValue(String key, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                return (String) data.get(key);
            } else {
                log.error("Could not find key '" + key + "' in the CMP configuration data");
            }
        } else {
            log.error("CMP alias '" + alias + "' does not exist");
        }
        return null;
    }
    public void setValue(String key, String value, String alias) {
        if(aliasExists(alias)) {
            if(data.containsKey(key)) {
                data.put(key, value);
                if(log.isDebugEnabled()) {
                    log.debug("Added '" + key + "=" + value + "' to the CMP configuration data");
                }
            } else {
                log.error("Key '" + key + "' does not exist in the CMP configuration data");
            }
        } else {
            log.error("CMP alias '" + alias + "' does not exist");
        }
    }
    
    
    
   
    public Collection<String> getCmpResponseProtectionList(boolean ramode) {
        ArrayList<String> pl = new ArrayList<String>();
        pl.add("signature");
        if(ramode) {
            pl.add("pbe");
        }
        return pl;
    }
    
    public Collection<String> getCmpRANameGenerationSchemes() {
        ArrayList<String> sl = new ArrayList<String>();
        sl.add("RANDOM");
        sl.add("DN"); // DNComponent as username
        sl.add("USERNAME"); // DN as username
        sl.add("FIXED");
        return sl;
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
        if(StringUtils.isNotEmpty(alias)) {
            Set<String> aliases = getAliasList();
            if(!aliases.contains(alias)) {
                initialize(alias);
                aliases.add(alias);
                data.put(ALIAS_LIST, aliases);
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("CMP alias '" + alias + "' already exists.");
                }
            }
        } else {
            log.error("No alias is added because no alias was provided.");
        }
    }
    public void removeAlias(String alias) {
        Set<String> aliases = getAliasList();
        if(aliases.contains(alias)) {
            Set<String> removeKeys = getAllAliasKeys(alias);
            Iterator itr = removeKeys.iterator();
            while(itr.hasNext()) {
                String key = (String) itr.next();
                data.remove(key);
            }
            aliases.remove(alias);
            data.put(ALIAS_LIST, aliases);
        } else {
            if(log.isDebugEnabled()) {
                log.debug("CMP alias '" + alias + "' does not exist");
            }
        }
    }
    public void renameAlias(String oldAlias, String newAlias) { //throws CMPAliasExistsException, CMPAliasDoesNotExistException {
        Set<String> aliases = getAliasList();
        if(aliases.contains(oldAlias)) {
            if(aliases.contains(newAlias)) {
                //throw new CMPAliasExistsException("CMP alias '" + newAlias + "' exists already");
                log.error("CMP alias '" + newAlias + "' already exists.");
            } else {
                Set<String> oldKeys = getAllAliasKeys(oldAlias);
                Iterator itr = oldKeys.iterator();
                while(itr.hasNext()) {
                    String oldkey = (String) itr.next();
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
        } else {
            //throw new CMPAliasDoesNotExistException("CMP alias '" + oldAlias + "' does not exist");
            log.error("CMP alias '" + oldAlias + "' does not exists.");
        }
    }
    public void cloneAlias(String originAlias, String cloneAlias) {
        Set<String> aliases = getAliasList();
        if(aliases.contains(originAlias)) {
            if(aliases.contains(cloneAlias)) {
                //ERROR MESSAGE: clonealias already exists
                log.error("CMP alias '" + cloneAlias + "' already exists.");
            } else {
                Iterator itr = getAllAliasKeys(originAlias).iterator();
                while(itr.hasNext()) {
                    String originalKey = (String) itr.next();
                    String cloneKey = originalKey;
                    cloneKey = StringUtils.replace(cloneKey, originAlias, cloneAlias);
                    Object value = data.get(originalKey);
                    data.put(cloneKey, value);
                }
                aliases.add(cloneAlias);
                data.put(ALIAS_LIST, aliases);
            }
        } else {
            // ERROR MESSAGE: original alias does not exist
            log.error("CMP alias '" + originAlias + "' does not exist.");
        }
    }
    public static Set<String> getAllAliasKeys(String alias) {
    	alias = alias + ".";
    	
        Set<String> keys = new HashSet<String>();
        keys.add(alias + CONFIG_DEFAULTCA);
        keys.add(alias + CONFIG_RESPONSEPROTECTION);
        keys.add(alias + CONFIG_OPERATIONMODE);
        keys.add(alias + CONFIG_AUTHENTICATIONMODULE);
        keys.add(alias + CONFIG_AUTHENTICATIONPARAMETERS);
        keys.add(alias + CONFIG_EXTRACTUSERNAMECOMPONENT);
        keys.add(alias + CONFIG_VENDORCERTIFICATEMODE);
        keys.add(alias + CONFIG_VENDORCA);
        keys.add(alias + CONFIG_ALLOWRAVERIFYPOPO);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONSCHEME);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONPARAMS);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONPREFIX);
        keys.add(alias + CONFIG_RA_NAMEGENERATIONPOSTFIX);
        keys.add(alias + CONFIG_RA_PASSWORDGENPARAMS);
        keys.add(alias + CONFIG_RA_ALLOWCUSTOMCERTSERNO);
        keys.add(alias + CONFIG_RA_ENDENTITYPROFILE);
        keys.add(alias + CONFIG_RA_CERTIFICATEPROFILE);
        keys.add(alias + CONFIG_RACANAME);
        keys.add(alias + CONFIG_RACERT_PATH);
        keys.add(alias + CONFIG_ALLOWAUTOMATICKEYUPDATE);       
        keys.add(alias + CONFIG_ALLOWUPDATEWITHSAMEKEY);
        keys.add(alias + CONFIG_CERTREQHANDLER_CLASS);
        keys.add(alias + CONFIG_UNIDDATASOURCE);
        return keys;
    }
    
    
    /**
     * @return the configuration as a regular Properties object
     */
    public Properties getAsProperties() {
        final Properties properties = new Properties();
        final Iterator i = data.keySet().iterator();
        while (i.hasNext()) {
            final String key = (String) i.next();
            final Object value = data.get(key);
            if(value instanceof String) {
                properties.setProperty(key, (String) data.get(key));
            }
        }
        return properties;
    }
    
    public Properties getAsProperties(String alias) {
        if(aliasExists(alias)) {
            final Properties properties = new Properties();
            final Iterator i = getAllAliasKeys(alias).iterator();
            while (i.hasNext()) {
                final String key = (String) i.next();
                final Object value = data.get(key);
                properties.setProperty(key, value.toString());
            }
            return properties;
        }
        return null;
    }
    
    
    
       
/*
       public void setEnableCommandLineInterface(final boolean enable) { data.put(ENABLECOMMANDLINEINTERFACE, Boolean.valueOf(enable)); }
       public boolean getEnableCommandLineInterface() {
           final Boolean ret = (Boolean) data.get(ENABLECOMMANDLINEINTERFACE);
           return (ret == null ? DEFAULTENABLECOMMANDLINEINTERFACE : ret);
       }
       
       public void setEnableCommandLineInterfaceDefaultUser(final boolean enable) { data.put(ENABLECOMMANDLINEINTERFACEDEFAULTUSER, Boolean.valueOf(enable)); }
       public boolean getEnableCommandLineInterfaceDefaultUser() {
           final Boolean ret = (Boolean) data.get(ENABLECOMMANDLINEINTERFACEDEFAULTUSER);
           return(ret == null ? DEFAULTENABLECOMMANDLINEINTERFACEDEFAULTUSER : ret);
       }
*/
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

}







