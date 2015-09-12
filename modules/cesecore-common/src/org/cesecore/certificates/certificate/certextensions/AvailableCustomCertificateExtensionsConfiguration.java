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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.Map.Entry;
import java.util.Properties;

import org.cesecore.configuration.ConfigurationBase;

public class AvailableCustomCertificateExtensionsConfiguration extends ConfigurationBase implements Serializable{

    private static final long serialVersionUID = 7798273820046510706L;
    
    public static final String CONFIGURATION_ID = "AVAILABLE_CUSTOM_CERT_EXTENSIONS";
    
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
    public void upgrade() { }

}
