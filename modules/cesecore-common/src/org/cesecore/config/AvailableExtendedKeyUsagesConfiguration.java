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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;

public class AvailableExtendedKeyUsagesConfiguration extends ConfigurationBase implements Serializable{

    private static final Logger log = Logger.getLogger(AvailableExtendedKeyUsagesConfiguration.class);
    
    private static final long serialVersionUID = -3430732247486886608L;
    public static final String AVAILABLE_EXTENDED_KEY_USAGES_CONFIGURATION_ID = "AVAILABLE_EXTEENDED_KEY_USAGES";
    
    /** Creates a new instance of AvailableExtendedKeyUsagesConfiguration */
    public AvailableExtendedKeyUsagesConfiguration()  {
       super();
       if(data.size() == 1) {
           fillAvailableExtendedKeyUsages();
       }
    }
    
    public AvailableExtendedKeyUsagesConfiguration(Serializable dataobj) {
        @SuppressWarnings("unchecked")
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }
    
    @Override
    public String getConfigurationId() {
        return AVAILABLE_EXTENDED_KEY_USAGES_CONFIGURATION_ID;
    }
    
    public void addExtKeyUsage(String oid, String name) {
        data.put(oid, name);
    }
    
    public void removeExtKeyUsage(String oid) {
        data.remove(oid);
    }
    
    public String getExtKeyUsageName(String oid) {
        return (String) data.get(oid);
    }
    
    public List<String> getAllOIDs() {
        Set<Object> keyset = data.keySet();
        ArrayList<String> keys = new ArrayList<String>();
        for(Object k : keyset) {
            if(!StringUtils.equalsIgnoreCase((String) k, "version")) {
                keys.add( (String) k );
            }
        }
        return keys;
    }
    
    public Map<String, String> getAllEKUOidsAndNames() {
        Map<String, String> ret = (Map<String, String>) saveData();
        ret.remove("version");
        return ret;
    }
    
    public Properties getAsProperties() {
        Properties properties = new Properties();
        Map<String, String> allEkus = getAllEKUOidsAndNames();
        for(Entry<String, String> eku : allEkus.entrySet()) {
            properties.setProperty(eku.getKey(), eku.getValue());
        }
        return properties;
    }
    
    public void fillAvailableExtendedKeyUsages() {
        if(ConfigurationHolder.isConfigFileExist("extendedkeyusage.properties")) {
            String propsfile = System.getenv("EJBCA_HOME") + "/modules/admin-gui/resources/languages/languagefile.en.properties";
            Properties language = new Properties();
            try {
                InputStream is = new FileInputStream(propsfile);
                language.load(is);
            } catch (FileNotFoundException e) {
                log.error(e);
            } catch (IOException e) {
                log.error(e);
            }
        
            final Configuration conf = ConfigurationHolder.instance();
            final String ekuname = "extendedkeyusage.name.";
            final String ekuoid = "extendedkeyusage.oid.";
            int j=0;
            for (int i = 0; i < 255; i++) {
                final String oid = conf.getString(ekuoid+i);
                if (oid != null) {
                    String name = conf.getString(ekuname+i);
                    if (name != null) {
                        // A null value in the properties file means that we should not use this value, so set it to null for real
                        if (name.equalsIgnoreCase("null")) {
                            name = null;
                        } else {
                            String readableName = language.getProperty(name);
                            data.put(oid, readableName);
                            j++;
                        }
                    } else {
                        log.error("Found extended key usage oid "+oid+", but no name defined. Not adding to list of extended key usages.");
                    }
                } 
                // No eku with a certain number == continue trying next, we will try 0-255.
            }
            if(log.isDebugEnabled()) {
                log.debug("Read " + j + " extended key usages from the configurations file");
            }
        }
    }

    @Override
    public void upgrade() {}
    
}
