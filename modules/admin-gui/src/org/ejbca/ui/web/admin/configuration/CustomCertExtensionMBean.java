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
    
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ServiceLoader;

import javax.faces.application.FacesMessage;
import javax.faces.context.FacesContext;
import javax.faces.event.ValueChangeEvent;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CustomCertificateExtension;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JavaServer Faces Managed Bean for managing the configuration of a single CustomCertificateExtension
 * 
 * 
 * @version $Id$
 *
 */
public class CustomCertExtensionMBean extends BaseManagedBean implements Serializable {
    
    private static final long serialVersionUID = 1L;

    /** Prefix for properties in custom certificate extensions */
    private static final String CUSTOMCERTEXTENSION_PROPERTY_PREFIX = "CUSTOMCERTEXTENSION_PROPERTY_";

    public class CurrentExtensionGUIInfo implements Serializable {
        private static final long serialVersionUID = 1L;
        private int id;
        private String oid;
        private String displayName;
        private boolean critical;
        private boolean required;
        private Map<String, CustomExtensionPropertyGUIInfo> extensionProperties;
        private CustomCertificateExtension extension;


        public CurrentExtensionGUIInfo(CustomCertificateExtension extension) {
            this.id = extension.getId();
            this.oid = extension.getOID();
            this.displayName = getEjbcaWebBean().getText(extension.getDisplayName());
            this.critical = extension.isCriticalFlag();
            this.required = extension.isRequiredFlag();
            setExtension(extension);
        }
        
        public int getId() { return this.id; }
        public void setId(int id) { this.id = id; }
        
        public String getOid() { return this.oid; }
        public void setOid(String oid) { this.oid=oid; }
        
        public String getDisplayName() { return this.displayName; }
        public void setDisplayName(String displayName) { this.displayName=displayName; }
        
        public boolean isCritical() { return this.critical; }
        public void setCritical(boolean critical) { this.critical=critical; }
        
        public boolean isRequired() { return this.required; }
        public void setRequired(final boolean required) { this.required=required; }
        
        public void setProperty(final String key, String value) throws InvalidCustomExtensionPropertyException {
            CustomExtensionPropertyGUIInfo property  = extensionProperties.get(key);
            property.setValue(value);
            extensionProperties.put(key, property);            
        }
            
        public  Map<String, CustomExtensionPropertyGUIInfo> getExtensionProperties() {         
            return extensionProperties;
        }
        
        public Properties getProperties() {
            Properties properties = new Properties();
            for(String key : extensionProperties.keySet()) {
                properties.put(key, extensionProperties.get(key).getValue());
            }
            return properties;
        }
        
        public CustomCertificateExtension getExtension() {
            return extension;
        }
        
        public void setClassPath(String classPath) {
            setExtension(availableCertificateExtensions.get(classPath));
        }
        
        public void setExtension(CustomCertificateExtension extension) {
            this.extension = extension;
            //Load the available properties
            Map<String, CustomExtensionPropertyGUIInfo> extensionPropertiesCopy = new LinkedHashMap<>();
            for (Entry<String, String[]> entry : extension.getAvailableProperties().entrySet()) {
                String key = entry.getKey();
                String label = getEjbcaWebBean().getText(CUSTOMCERTEXTENSION_PROPERTY_PREFIX + key);
                Properties properties = extension.getProperties();
                String value = (properties != null && properties.get(key) != null ? (String) properties.get(key) : null);
                CustomExtensionPropertyGUIInfo property = new CustomExtensionPropertyGUIInfo(key, label, value, entry.getValue());
                extensionPropertiesCopy.put(key, property);
            }
            extensionProperties = extensionPropertiesCopy;
        }
        
        public String getClassPath() {
            return extension.getClass().getCanonicalName();
        }
        
    }
    
    public class CustomExtensionPropertyGUIInfo {
       
        private final String key;
        private final String label;
        private String value;
        private String[] possibleValues;
        
        public CustomExtensionPropertyGUIInfo(final String key, final String label, final String value, final String ... possibleValues) {
            this.key = key;
            this.label = label;
            if(value != null) {
                this.value = value;
            } else {
                if(possibleValues.length > 0) {
                    this.value = possibleValues[0];
                } else {
                    this.value = "";
                }
            }
            this.possibleValues = possibleValues;
        }
       
        public String getKey() {
            return key;
        }
        
        public String getLabel() {
            return label;
        }

        public String getValue() {
            return value;
        }

        /**
         * Sets the value.
         * 
         * @param value the value to be set
         * @throws InvalidCustomExtensionPropertyException if a list of possible values has been set, and the given value was not in the set. 
         */
        public void setValue(String value) throws InvalidCustomExtensionPropertyException {
            //Evaluate the value, if any defaults have been given
            valueSearch: if (possibleValues.length > 0) {
                for (String possibleValue : possibleValues) {
                    if (value.equals(possibleValue)) {
                        break valueSearch;
                    }
                }
                //There should be a check for property validity here, but since I can't manage to decouple the list of properties when the page is refreshed after
                //the extension class has been changed, we'll fail nicely and simply ignore unfound values. 
                return;
            }
            this.value = value;
        }
        
        public String[] getPossibleValues() {
            return possibleValues;
        }
        
        public int getPossibleValuesCount() {
            return possibleValues.length;
        }

    }
        
        
    private final AuthorizationSessionLocal authorizationSession = getEjbcaWebBean().getEjb().getAuthorizationSession();
    
    // Declarations in faces-config.xml
    //@javax.faces.bean.ManagedProperty(value="#{systemConfigMBean}")
    private SystemConfigMBean systemConfigMBean;
    
    private AvailableCustomCertificateExtensionsConfiguration availableExtensionsConfig = null;
    private Map<String, CustomCertificateExtension> availableCertificateExtensions = null;
    private List<SelectItem> availableCertificateExtensionsList = null;
    private CurrentExtensionGUIInfo currentExtensionGUIInfo = null;
    private ListDataModel<CustomExtensionPropertyGUIInfo> currentExtensionProperties = null;
    private int currentExtensionId = 0;
    
    public CustomCertExtensionMBean() {
        super();
    }
            
    private void flushCurrentExtension() {
        availableExtensionsConfig = null;
        currentExtensionId = 0;
        currentExtensionGUIInfo = null;
        currentExtensionProperties = null;
    }
    

    
    private AvailableCustomCertificateExtensionsConfiguration getAvailableExtensionsConfig() {
        if(availableExtensionsConfig == null) {
            availableExtensionsConfig = getEjbcaWebBean().getAvailableCustomCertExtensionsConfiguration();
        }
        return availableExtensionsConfig;
    }
    
    public SystemConfigMBean getSystemConfigMBean() { return systemConfigMBean; }
    public void setSystemConfigMBean(SystemConfigMBean systemConfigMBean) { this.systemConfigMBean = systemConfigMBean; }
    
    public int getCurrentExtensionId() {
        this.currentExtensionId = systemConfigMBean.getSelectedCustomCertExtensionID();
        return this.currentExtensionId;
    }
    
    public List<SelectItem> getAvailableCustomCertificateExtensions() {
        if (availableCertificateExtensions == null) {
            availableCertificateExtensions = new HashMap<>();
            availableCertificateExtensionsList = new ArrayList<>();
            ServiceLoader<? extends CustomCertificateExtension> serviceLoader = ServiceLoader.load(CustomCertificateExtension.class);
            for (CustomCertificateExtension extension : serviceLoader) {
                availableCertificateExtensionsList.add(new SelectItem(extension.getClass().getCanonicalName(), extension.getDisplayName()));
                availableCertificateExtensions.put(extension.getClass().getCanonicalName(), extension);
            }
            Collections.sort(availableCertificateExtensionsList, new Comparator<SelectItem>() {
                @Override
                public int compare(SelectItem o1, SelectItem o2) {
                    return o1.getLabel().compareTo(o2.getLabel());
                }
            });
        }
        return availableCertificateExtensionsList;
    }
    
    /** @return cached or populate a new CustomCertificateExtension GUI representation for view or edit */
    public CurrentExtensionGUIInfo getCurrentExtensionGUIInfo() {
        AvailableCustomCertificateExtensionsConfiguration cceConfig = getAvailableExtensionsConfig();
        int currentID = getCurrentExtensionId();
        if ((currentExtensionGUIInfo == null) || (currentExtensionGUIInfo.getId() != currentID)) {
            flushCurrentExtension();
            currentExtensionGUIInfo = new CurrentExtensionGUIInfo(cceConfig.getCustomCertificateExtension(currentID));
        } 
        return currentExtensionGUIInfo;
    }
        
    @SuppressWarnings("unchecked")
    public void saveCurrentExtension() {
        if (StringUtils.isEmpty(currentExtensionGUIInfo.getOid())) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExtension OID is set.", null));
            return;
        }
        if (StringUtils.isEmpty(currentExtensionGUIInfo.getDisplayName())) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExtension Label is set.", null));
            return;
        }
        
        if (StringUtils.isEmpty(currentExtensionGUIInfo.getClassPath())) {
            FacesContext.getCurrentInstance()
            .addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "No CustomCertificateExtension is set.", null));
            return;
        }
        
        Properties properties = new Properties();
        for(CustomExtensionPropertyGUIInfo extensionProperty :  (List<CustomExtensionPropertyGUIInfo>) currentExtensionProperties.getWrappedData()) {
            properties.put(extensionProperty.getKey(), extensionProperty.getValue());
        }
        
        AvailableCustomCertificateExtensionsConfiguration cceConfig = getAvailableExtensionsConfig();
        try {
            cceConfig.addCustomCertExtension(currentExtensionGUIInfo.getId(), currentExtensionGUIInfo.getOid(), currentExtensionGUIInfo.getDisplayName(), 
                    currentExtensionGUIInfo.getClassPath(), currentExtensionGUIInfo.isCritical(), currentExtensionGUIInfo.isRequired(), properties);
            getEjbcaWebBean().saveAvailableCustomCertExtensionsConfiguration(cceConfig);
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_INFO, "Extension was saved successfully.", null));
        } catch(Exception e) {
            FacesContext.getCurrentInstance().addMessage(null, new FacesMessage(FacesMessage.SEVERITY_ERROR, "Failed to edit Custom Certificate Extension. " + e.getLocalizedMessage() , e.getLocalizedMessage()));
            return;
        }        
        flushCurrentExtension();
    }

    // -------------------------------------------------------------
    //              Current Extension Properties
    // ------------------------------------------------------------    
    public ListDataModel<CustomExtensionPropertyGUIInfo> getCurrentExtensionPropertiesList() {
        if (currentExtensionProperties == null) {
            currentExtensionProperties = new ListDataModel<>(new ArrayList<>(getCurrentExtensionGUIInfo()
                    .getExtensionProperties().values()));
        }
        return currentExtensionProperties;
    }
       
    public String update(){
        return "edit";
    }
    
    public void updateExtension(ValueChangeEvent e){
        String extensionClass = (String) e.getNewValue();  
        currentExtensionGUIInfo.setClassPath(extensionClass); 
        currentExtensionProperties.setWrappedData(null);
        currentExtensionProperties = null;
    }
    
    /** @return true if admin may create new or modify existing Custom Certificate Extensions. */
    public boolean isAllowedToEditCustomCertificateExtension() {
        return authorizationSession.isAuthorizedNoLogging(getAdmin(), StandardRules.CUSTOMCERTEXTENSIONCONFIGURATION_EDIT.resource()) && !systemConfigMBean.getCustomCertificateExtensionViewMode();
    }
   
}