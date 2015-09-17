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
package org.ejbca.ui.web.admin.configuration;
    
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtension;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing the configuration of a single CustomCertificateExtension
 * @version $Id$
 *
 */
public class CustomCertExtensionMBean extends BaseManagedBean {
    
    private static final long serialVersionUID = -6653610614851741905L;
    private static final Logger log = Logger.getLogger(SystemConfigMBean.class);
    
    private final String DEFAULT_EXTENSION_CLASSPATH = "org.cesecore.certificates.certificate.certextensions.BasicCertificateExtension";
    
    public class CurrentExtensionGUIInfo {
        private int id;
        private String oid;
        private String displayName;
        private String classPath;
        private boolean critical;
        private String properties;
        
        public CurrentExtensionGUIInfo(int id) {
            this.id = id;
            this.oid = "";
            this.displayName = "";
            this.classPath = DEFAULT_EXTENSION_CLASSPATH;
            this.critical = false;
            this.properties = "";
        }
        
        public CurrentExtensionGUIInfo(CertificateExtension extension) {
            this.id = extension.getId();
            this.oid = extension.getOID();
            this.displayName = extension.getDisplayName();
            this.classPath = extension.getClass().getCanonicalName();
            this.critical = extension.isCriticalFlag();
            this.properties = getPropertiesAsString(extension.getProperties());
        }
        
        public int getId() { return this.id; }
        public void setId(int id) { this.id = id; }
        public String getOid() { return this.oid; }
        public void setOid(String oid) { this.oid=oid; }
        public String getDisplayName() { return this.displayName; }
        public void setDisplayName(String displayName) { this.displayName=displayName; }
        public String getClassPath() { return this.classPath; }
        public void setClassPath(String classPath) { this.classPath=classPath; }
        public boolean isCritical() { return this.critical; }
        public void setCritical(boolean critical) { this.critical=critical; }
        public String getProperties() {return this.properties; }
        public void setProperties(String properties) { this.properties=properties; }
        public void setProperties(Properties properties) { this.properties=getPropertiesAsString(properties); }
        
        private String getPropertiesAsString(Properties properties) {
            if(properties.isEmpty()) {
                return "";
            }
            
            StringBuilder sb = new StringBuilder("");
            for(Object o : properties.keySet() ) {
                sb.append((String) o);
                sb.append("=");
                sb.append((String)properties.get(o));
                sb.append(",");
            }
            sb.deleteCharAt(sb.length()-1);
            return sb.toString();
        }
    }
    
    public class PropertyGUIInfo {
        private String key;
        private String value;
        private PropertyGUIInfo(String key, String value) {
            this.key = key;
            this.value = value;
        }
        public String getKey() { return this.key; }
        public void  setKey(String key) { this.key=key; }
        public String getValue() { return this.value; }
        public void setValue(String value) { this.value=value; }
    }
        
        
    private final AccessControlSessionLocal accessControlSession = getEjbcaWebBean().getEjb().getAccessControlSession();
    
    private boolean currentExtensionEditMode = true;
    private AvailableCustomCertificateExtensionsConfiguration availableExtensionsConfig = null;
    private CurrentExtensionGUIInfo currentExtensionGUIInfo = null;
    private int currentExtensionId = 0;
    private ListDataModel currentExtensionPropertiesList = null;
    private String currentPropertyKey = "";
    private String currentPropertyValue = "";
    
    public CustomCertExtensionMBean() {
        super();
    }
            
    public void flushCache() {
        currentExtensionGUIInfo = null;
        currentExtensionPropertiesList = null;
        currentPropertyKey = "";
        currentPropertyValue = "";
    }
    
    private AvailableCustomCertificateExtensionsConfiguration getAvailableExtensionsConfig() throws Exception{
        if(availableExtensionsConfig == null) {
            availableExtensionsConfig = getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
        }
        return availableExtensionsConfig;
    }
    
    public int getCurrentExtensionId() { 
        // Get the HTTP GET/POST parameter named "extensionId"
        final String idString = FacesContext.getCurrentInstance().getExternalContext().getRequestParameterMap().get("extensionId");        
        if (StringUtils.isNotEmpty(idString)) {
            try {
                int id = Integer.parseInt(idString);
                // If there is a query parameter present and the id is different we flush the cache!
                if (id != this.currentExtensionId) {
                    flushCache();
                    this.currentExtensionId = id;
                }
                // Always switch to edit mode for new ones and view mode for all others
                setCurrentExtensionEditMode(id == 0);
            } catch (NumberFormatException e) {
                String msg = "Could not parse the extension ID as an Integer. ";
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, msg, null));
                log.error(msg + e.getLocalizedMessage());
                return 0;
            }
        }
        return this.currentExtensionId;
    }
    
    /** @return cached or populate a new CustomCertificateExtension GUI representation for view or edit */
    public CurrentExtensionGUIInfo getCurrentExtensionGUIInfo() {
        if (this.currentExtensionGUIInfo == null) {
            final int id = getCurrentExtensionId();
            try {
                if(id == 0) {
                    int newID = getUnusedID();
                    if(newID==0) {
                        FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Cannot add new Extensions. " +
                                "All possible IDs are either already refering to an extension or are still used in at least one certificate profile.", null));
                        return null;
                    }
                    this.currentExtensionGUIInfo = new CurrentExtensionGUIInfo(newID);
                } else {
                    AvailableCustomCertificateExtensionsConfiguration cceConfig = getAvailableExtensionsConfig();
                    this.currentExtensionGUIInfo = new CurrentExtensionGUIInfo(cceConfig.getCustomCertificateExtension(id));
                }
            } catch(Exception e) {
                FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to access AvailableCustomCertificateExtensionsConfiguration: " + e.getLocalizedMessage(), null));
                return null;
            }
        }
        return this.currentExtensionGUIInfo;
    }
        
    public void saveCurrentExtension() {
        if (currentExtensionGUIInfo.getId() == 0) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "The CustomCertificateExtension ID cannot be 0.", null));
            return;
        }        
        if (StringUtils.isEmpty(currentExtensionGUIInfo.getOid())) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExenstion OID is set.", null));
            return;
        }
        if (StringUtils.isEmpty(currentExtensionGUIInfo.getDisplayName())) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExension Display Name is set.", null));
            return;
        }
        
        if (StringUtils.isEmpty(currentExtensionGUIInfo.getClassPath())) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExenstion Class Path is set.", null));
            return;
        }
        if (currentExtensionGUIInfo.getProperties() == null) {
            currentExtensionGUIInfo.setProperties("");
        }
        
        AvailableCustomCertificateExtensionsConfiguration cceConfig = null;
        try {
            cceConfig = getAvailableExtensionsConfig();
            cceConfig.addCustomCertExtension(currentExtensionGUIInfo.getId(), currentExtensionGUIInfo.getOid(), currentExtensionGUIInfo.getDisplayName(), currentExtensionGUIInfo.getClassPath(), currentExtensionGUIInfo.isCritical(), getPropertiesFromString(currentExtensionGUIInfo.getProperties()));
            getEjbcaWebBean().saveAvailableCustomCertExtensionsConfiguration(cceConfig);
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to get AvailableCustomCertificateExtensionsConfiguration. " + e.getLocalizedMessage() , e.getLocalizedMessage()));
            return;
        }
    }
    
    private Properties getPropertiesFromString(String props) {
        Properties properties = new Properties();
        if(!StringUtils.isEmpty(props)) {
            String[] propertyPairs = StringUtils.split(props, ",");
            String[] property = new String[2];
            for(String pair : propertyPairs) {
                property = StringUtils.split(pair, "=");
                properties.put(property[0].trim(), property[1].trim());
            }
        }
        return properties;
    }
    
    private int getUnusedID() throws Exception {
        AvailableCustomCertificateExtensionsConfiguration cceConfig = getAvailableExtensionsConfig();
        for(int i=1; i<255; i++) {
            if(cceConfig.isCustomCertExtensionSupported(i)) {
                continue;
            }
            if(isExtensionUsedInProfiles(i)) {
                continue;
            }
            return i;
        }
        return 0;
    }
        
    // -------------------------------------------------------------
    //              Current Extension Properties
    // ------------------------------------------------------------
        
    public String getCurrentPropertyKey() { return currentPropertyKey; }
    public void setCurrentPropertyKey(String key) { currentPropertyKey=key; }
    public String getCurrentPropertyValue() { return currentPropertyValue; }
    public void setCurrentPropertyValue(String value) { currentPropertyValue=value; }
    
    public ListDataModel getCurrentExtensionPropertiesList() {
        if(currentExtensionPropertiesList == null) {
            final String currentPropertiesString = getCurrentExtensionGUIInfo().getProperties();
            final Properties currentProperties = getPropertiesFromString(currentPropertiesString);
            currentExtensionPropertiesList = new ListDataModel(getPropertiesAsList(currentProperties));
        }
        return currentExtensionPropertiesList;
    }
    
    public void addExtensionProperty() {
        CurrentExtensionGUIInfo currentExtension = getCurrentExtensionGUIInfo();
        
        if(StringUtils.isEmpty(currentExtension.getOid()) || StringUtils.isEmpty(currentExtension.getDisplayName())){
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Please save Extension before adding properties." , null));
            return;
        }
        
        if (StringUtils.isEmpty(currentPropertyKey) || StringUtils.isEmpty(currentPropertyValue)) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Please specify both property key and value", null));
            return;
        }
        
        final String newProperyString = currentPropertyKey + "=" + currentPropertyValue;
        String currentProperties = currentExtension.getProperties();
        if(StringUtils.isNotEmpty(currentProperties)) {
            currentProperties += ",";
        }
        currentProperties += newProperyString;
        currentExtension.setProperties(currentProperties);
        currentExtensionGUIInfo = currentExtension;
        saveCurrentExtension();
        currentExtensionPropertiesList = new ListDataModel(getPropertiesAsList(getPropertiesFromString(currentProperties)));
        flushPropertyCache();
    }
    
    public void RemoveExtensionProperty() {
        final CurrentExtensionGUIInfo currentExtension = getCurrentExtensionGUIInfo();
        final String currentPropertiesString = currentExtension.getProperties();
        final Properties currentProperties = getPropertiesFromString(currentPropertiesString);
        final PropertyGUIInfo propToRemove = ((PropertyGUIInfo) currentExtensionPropertiesList.getRowData());
        currentProperties.remove(propToRemove.getKey());
        currentExtension.setProperties(currentProperties);
        currentExtensionGUIInfo = currentExtension;
        saveCurrentExtension();
        currentExtensionPropertiesList = new ListDataModel(getPropertiesAsList(currentProperties));
        flushPropertyCache();
    }
    
    private ArrayList<PropertyGUIInfo> getPropertiesAsList(Properties properties) {
        ArrayList<PropertyGUIInfo> ret = new ArrayList<PropertyGUIInfo>();
        for(Object o : properties.keySet()) {
            String key = (String) o;
            ret.add(new PropertyGUIInfo(key, properties.getProperty(key)));
        }
        return ret;
    }
    
    private void flushPropertyCache() {
        currentPropertyKey = "";
        currentPropertyValue = "";
    }
    
    // ----------------------------------------------------------------

    private boolean isExtensionUsedInProfiles(final int id) {
        final CertificateProfileSessionLocal certprofileSession = getEjbcaWebBean().getEjb().getCertificateProfileSession();
        Map<Integer, CertificateProfile> allCertProfiles = certprofileSession.getAllCertificateProfiles();
        for(Entry<Integer, CertificateProfile> entry : allCertProfiles.entrySet()) {
            final CertificateProfile cp = entry.getValue();
            List<Integer> usedCertExts = cp.getUsedCertificateExtensions();
            if(usedCertExts.contains(id)) {
                return true;
            }
        }
        return false;
    }
    
    /** @return true if admin may create new or modify existing Custom Certificate Extensions. */
    public boolean isAllowedToModify() {
        return accessControlSession.isAuthorizedNoLogging(getAdmin(), StandardRules.REGULAR_EDITAVAILABLECUSTOMCERTEXTENSION.resource());
    }
        
    public boolean isCurrentExtensionEditMode() { return currentExtensionEditMode; }
    public void setCurrentExtensionEditMode(boolean editMode) { this.currentExtensionEditMode = editMode; }
    public void toggleCurrentExtensionEditMode() { this.currentExtensionEditMode ^= true; }
    
    /** Invoked when admin cancels a Custom Certificate Extension create or edit. */
    public void cancelCurrentCustomExtension() {
        setCurrentExtensionEditMode(false);
        flushCache();
    }
   
}