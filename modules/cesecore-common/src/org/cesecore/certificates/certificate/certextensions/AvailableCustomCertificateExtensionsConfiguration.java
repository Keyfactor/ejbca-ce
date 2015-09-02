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
import java.util.Map.Entry;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.internal.InternalResources;

public class AvailableCustomCertificateExtensionsConfiguration extends ConfigurationBase implements Serializable{

    private static final long serialVersionUID = 7798273820046510706L;
    private static final Logger log = Logger.getLogger(AvailableCustomCertificateExtensionsConfiguration.class);
    private static final InternalResources intres = InternalResources.getInstance();
    
    public static final String AVAILABLE_CUSTOM_CERTIFICATE_EXTENSTIONS_CONFIGURATION_ID = "AVAILABLE_CUSTOM_CERT_EXTENSIONS";
    
    public AvailableCustomCertificateExtensionsConfiguration() {
        super();
    }
    
    public AvailableCustomCertificateExtensionsConfiguration(Serializable dataobj) {
        @SuppressWarnings("unchecked")
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }
    
    @Override
    public String getConfigurationId() {
        return AVAILABLE_CUSTOM_CERTIFICATE_EXTENSTIONS_CONFIGURATION_ID;
    }

    public CertificateExtension getCustomCertificateExtension(int id) {
        return (CertificateExtension) data.get(id);
    }
    
    public void addCustomCertExtension(int id, CertificateExtension ce) {
        data.put(id, ce);
    }
    
    public void addCustomCertExtension(int id, String oid, String displayName, String classPath, boolean critical, Properties properties) throws CertificateExtentionConfigurationException {
        try {
            Class<?> implClass = Class.forName(classPath);
            CertificateExtension certificateExtension = (CertificateExtension) implClass.newInstance();
            certificateExtension.init(id, oid.trim(), displayName, critical, properties);
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
    
    public ArrayList<CertificateExtension> getAllAvailableCustomCertificateExtensions() {
        ArrayList<CertificateExtension> exts = new ArrayList<CertificateExtension>();
        for(Entry<Object, Object> entry : data.entrySet()) {
            Object value = entry.getValue();
            if(value instanceof CertificateExtension) {
                exts.add((CertificateExtension) value);
            }
        }
        return exts;
    }
    
    public void addAvailableCustomCertExtensionsFromFile() {
        try{
            Properties props = new Properties();
            InputStream is = null;
            try {
                is = CertificateExtensionFactory.class.getResourceAsStream("/certextensions.properties");
                if(is != null){
                    props.load(is);
                }else{
                    log.info("Certificate Extension configuration file not found. No Custom CertificateExtensions are read.");
                    return;
                }
            } finally {
                if (is != null) {
                    is.close();
                }
            }
            
            for(int i=1;i<255;i++){
                if(props.get("id" + i +".oid")!=null){
                    log.debug("found " + props.get("id" + i +".oid"));
                    //retval.addCertificateExtension(props,i);
                    CertificateExtension ce = getCertificateExtensionFromFile(i, props);
                    data.put(ce.getId(), ce);
                }else{
                    break;
                }
            }
            log.debug("Nr of read Custom Certificate Extensions: " + (data.size() - 1));
        }catch(IOException e){
            log.error(intres.getLocalizedMessage("certext.errorparsingproperty"),e);
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
        
        try{
            String oid = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_OID);
            String classPath = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_CLASSPATH);
            String displayName = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_DISPLAYNAME);
            log.debug(PROPERTY_ID + id + PROPERTY_USED + ":" + propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_USED));
            boolean used = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_USED).trim().equalsIgnoreCase("TRUE");
            boolean translatable = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_TRANSLATABLE).trim().equalsIgnoreCase("TRUE");
            boolean critical = propertiesInFile.getProperty(PROPERTY_ID + id + PROPERTY_CRITICAL).trim().equalsIgnoreCase("TRUE");
            log.debug(id + ", " + used + ", " +oid + ", " +critical+ ", " +translatable +  ", " + displayName);   
            if(used){
                if(oid != null && classPath != null && displayName != null){                    
                    Class<?> implClass = Class.forName(classPath);
                    CertificateExtension certificateExtension = (CertificateExtension) implClass.newInstance();
                    Properties extensionProperties = getExtensionProperties(id, propertiesInFile);
                    certificateExtension.init(id, oid.trim(), displayName, critical, extensionProperties);
                    return certificateExtension;

                }else{
                    throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.certextmissconfigured",Integer.valueOf(id)));
                }
            }
            
        }catch(Exception e){
            throw new CertificateExtentionConfigurationException(intres.getLocalizedMessage("certext.certextmissconfigured",Integer.valueOf(id)),e);
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
    
    public Properties getAsProperties() {
        Properties properties = new Properties();
        for(Entry<Object, Object> entry : data.entrySet()) {
            if(entry.getValue() instanceof CertificateExtension) {
                CertificateExtension ce = (CertificateExtension) entry.getValue();
                properties.setProperty(entry.getKey().toString(), ce.getOID());
            }
        }
        return properties;
    }
    
    @Override
    public void upgrade() {
        // TODO Auto-generated method stub
    }

}
