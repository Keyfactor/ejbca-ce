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
package org.cesecore.certificates.certificate.certextensions;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;

/**
 * This file handles configuration of available Custom Certificate Extensions
 * 
 * @version $Id$
 */
public class AvailableCustomCertificateExtensionsConfiguration extends ConfigurationBase implements Serializable{

    private static final long serialVersionUID = 7798273820046510706L;
    private static final Logger log = Logger.getLogger(AvailableCustomCertificateExtensionsConfiguration.class);
    
    public static final String CONFIGURATION_ID = "AVAILABLE_CUSTOM_CERT_EXTENSIONS";
    
    public AvailableCustomCertificateExtensionsConfiguration() {
        super();
        if(!isConfigurationInitialized()) {
            addAvailableCustomCertExtensionsFromFile();
        }
    }
    
    public AvailableCustomCertificateExtensionsConfiguration(Serializable dataobj) {
        @SuppressWarnings("unchecked")
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }
    
    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }
    
    /**
     * @return true if there is at least one supported Custom Certificate Extension. False otherwize 
     */
    public boolean isConfigurationInitialized() {
        return data.size() > 1;
    }

    public boolean isCustomCertExtensionSupported(int id) {
        return data.containsKey(id);
    }
    
    public CustomCertificateExtension getCustomCertificateExtension(int id) {
        return (CustomCertificateExtension) data.get(id);
    }
    
    public void addCustomCertExtension(CertificateExtension ce) {
        data.put(ce.getId(), ce);
    }
    
    public void addCustomCertExtension(int id, String oid, String displayName, String classPath, boolean critical, 
            final boolean required, Properties properties) throws CertificateExtentionConfigurationException {
        try {
            Class<?> implClass = Class.forName(classPath);
            CertificateExtension certificateExtension = (CertificateExtension) implClass.newInstance();
            certificateExtension.init(id, oid.trim(), displayName, critical, required, properties);
            data.put(id, certificateExtension);
        } catch (ClassNotFoundException e) {
            throw new CertificateExtentionConfigurationException("Cannot add custom certificate extension. " + e.getLocalizedMessage());
        } catch (InstantiationException e) {
            throw new CertificateExtentionConfigurationException("Cannot add custom certificate extension. " + e.getLocalizedMessage());
        } catch (IllegalAccessException e) {
            throw new CertificateExtentionConfigurationException("Cannot add custom certificate extension. " + e.getLocalizedMessage());
        }
    }
    
    public void removeCustomCertExtension(int id) {
        data.remove(id);
    }
    
    public List<CertificateExtension> getAllAvailableCustomCertificateExtensions() {
        List<CertificateExtension> ret = new ArrayList<CertificateExtension>();
        for(Entry<Object, Object> entry : data.entrySet()) {
            Object value = entry.getValue();
            if(value instanceof CertificateExtension) {
                CertificateExtension ext = (CertificateExtension) value;
                ret.add(ext);
            }
        }
        return ret;
    }
    
    /**
     * Returns a list of the available CertificateExtensions as Properties. Each property contains the extension OID 
     * as its 'key' and the extension's label as its 'value'
     * @return
     */
    public Properties getAsProperties() {
        Properties properties = new Properties();
        for(Entry<Object, Object> entry : data.entrySet()) {
            if(entry.getValue() instanceof CertificateExtension) {
                CertificateExtension ce = (CertificateExtension) entry.getValue();
                properties.setProperty(Integer.toString(ce.getId()), ce.getDisplayName());
            }
        }
        return properties;
    }
    
    /*
     * Returns a new AvailableCustomCertificateExtensionsConfiguration object containing only extensions from the properties  
     * file certextensions.properties 
     * 
     * This method is called only when upgrading CertificateProfile to EJBCA 6.4.0 where the CustomCertExtensions are 
     * redefined to be referenced by their OIDs instead of IDs. 
     * 
     * TODO Remove this method when support for EJBCA 6.4.0 is dropped.
     */
    @Deprecated
    public static AvailableCustomCertificateExtensionsConfiguration getAvailableCustomCertExtensionsFromFile() {
        return new AvailableCustomCertificateExtensionsConfiguration();
    }
    
    
    /*
     * Imports CustomCertExtensions from certextensions.properties into the database.
     * 
     * TODO Remove this method when support for EJBCA 6.4.0 is dropped.
     */
    @Deprecated
    private void addAvailableCustomCertExtensionsFromFile() {
        // If the file has already been removed, no need to go further
        InputStream is = CertificateExtensionFactory.class.getResourceAsStream("/certextensions.properties");
        if(is == null) {
            return;
        }
        
        try{
            Properties props = new Properties();
            try {
                props.load(is);
            } finally {
                is.close();
            }
            
            int count = 0;
            for(int i=1;i<255;i++){
                if(props.get("id" + i +".oid")!=null){
                    if(log.isDebugEnabled()) {
                        log.debug("found " + props.get("id" + i +".oid"));
                    }
                    CertificateExtension ce = getCertificateExtensionFromFile(i, props);
                    addCustomCertExtension(ce);
                    count++;
                }
            }
            if(log.isDebugEnabled()) {
                log.debug("Nr of read Custom Certificate Extensions from file: " + count);
            }
        }catch(IOException e){
            log.error("Error parsing the 'certextensions.properties' file.",e);
        } catch (CertificateExtentionConfigurationException e) {
            log.error(e.getMessage(),e);
        }
    }
    
    private CertificateExtension getCertificateExtensionFromFile(int id, Properties propertiesInFile) throws CertificateExtentionConfigurationException {
        String PROPERTY_ID           = "id";
        String PROPERTY_OID          = ".oid";
        String PROPERTY_CLASSPATH    = ".classpath";
        String PROPERTY_DISPLAYNAME  = ".displayname";
        String PROPERTY_USED         = ".used";
        String PROPERTY_TRANSLATABLE = ".translatable";
        String PROPERTY_CRITICAL     = ".critical";
        String PROPERTY_REQUIRED     = ".required";
        
        try{
            String oid = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_OID);
            String classPath = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_CLASSPATH);
            String displayName = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_DISPLAYNAME);
            log.debug(PROPERTY_ID + id + PROPERTY_USED + ":" + propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_USED));
            boolean used = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_USED).trim().equalsIgnoreCase("TRUE");
            boolean translatable = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_TRANSLATABLE).trim().equalsIgnoreCase("TRUE");
            boolean critical = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_CRITICAL).trim().equalsIgnoreCase("TRUE");
            boolean required = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_REQUIRED).trim().equalsIgnoreCase("TRUE");
            log.debug(id + ", " + used + ", " +oid + ", " +critical+ ", " +translatable +  ", " + displayName);   
            if(used){
                if(oid != null && classPath != null && displayName != null){
                    Class<?> implClass = Class.forName(classPath);
                    CertificateExtension certificateExtension = (CertificateExtension) implClass.newInstance();
                    Properties extensionProperties = getExtensionProperties(id, propertiesInFile);
                    if(translatable) {
                        extensionProperties.put("translatable", true);
                    }
                    certificateExtension.init(id, oid.trim(), displayName, critical, required, extensionProperties);
                    return certificateExtension;

                }else{
                    throw new CertificateExtentionConfigurationException("Certificate Extension " + Integer.valueOf(id) + " seems to be misconfigured in the certextensions.properties");
                }
            }
            
        }catch(Exception e){
            throw new CertificateExtentionConfigurationException("Certificate Extension " + Integer.valueOf(id) + " seems to be misconfigured in the certextensions.properties",e);
        }
        return null;
    }
    
    private Properties getExtensionProperties(int id, Properties propertiesInFile) {
        Properties extProps = new Properties();
        Iterator<Object> keyIter = propertiesInFile.keySet().iterator();
        String matchString = "id" + id + ".property."; 
        while(keyIter.hasNext()){
            String nextKey = (String) keyIter.next();
            if(nextKey.startsWith(matchString)){
                if(nextKey.length() > matchString.length()){
                  extProps.put(nextKey.substring(matchString.length()), propertiesInFile.get(nextKey));               
                }
            }           
        }
        return extProps;
    }
 
    
    @Override
    public void upgrade() { }

}
