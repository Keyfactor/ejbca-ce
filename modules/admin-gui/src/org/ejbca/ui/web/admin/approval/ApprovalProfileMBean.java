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
package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;

import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalProfileByAdminRoles;
import org.ejbca.core.model.approval.ApprovalProfileFieldObject;
import org.ejbca.core.model.approval.ApprovalProfileNumberOfApprovals;
import org.ejbca.core.model.approval.ApprovalProfileType;
import org.ejbca.ui.web.admin.BaseManagedBean;

public class ApprovalProfileMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -3751383340600251434L;
    
    
    
    
    public class ApprovalPropertyGuiInfo {
        private final String propertyKey;
        private final String propertyValue;
        private final String propertyDescription;
        private final List<String> propertyMetadata;
        private final String propertyMetadataString;
        private final int propertyMetadataType;
        private final String propertyMetadataTypeString;
        public ApprovalPropertyGuiInfo(final String key, final ApprovalProfileFieldObject fieldObject) {
            propertyKey = key;
            propertyValue = fieldObject.getKeyObject();
            propertyDescription = fieldObject.getDescription();
            propertyMetadata = fieldObject.getMetaData();
            
            StringBuilder options = new StringBuilder("");
            for(String option : fieldObject.getMetaData()) {
                options.append(option + ", ");
            }
            options.deleteCharAt(options.length()-2);
            propertyMetadataString = options.toString();
            
            
            
            propertyMetadataType = fieldObject.getMetaDataType();
            if(propertyMetadataType == ApprovalProfileFieldObject.METADATATYPE_CHECKBOX) {
                propertyMetadataTypeString = "Check Boxes";
            } else if(propertyMetadataType == ApprovalProfileFieldObject.METADATATYPE_RADIOBUTTON) {
                propertyMetadataTypeString = "Radio Buttons";
            } else if(propertyMetadataType == ApprovalProfileFieldObject.METADATATYPE_TEXTBOX) {
                propertyMetadataTypeString = "Text Box";
            } else {
                propertyMetadataTypeString = "Type unknown";
            }
            
        }
        public String getPropertyKey() { return propertyKey; }
        public String getPropertyValue() { return propertyValue; }
        public String getPropertyDescription() { return propertyDescription; }
        public List<String> getPropertyMetadata() { return propertyMetadata; }
        public String getPropertyMetadataString() { return propertyMetadataString; }
        public int getPropertyMetadataType() {return propertyMetadataType; }
        public String getPropertyMetadataTypeString() {return propertyMetadataTypeString;}
    }
    
    
    
    
    
    private static final Logger log = Logger.getLogger(ApprovalProfileMBean.class);
    
    private ApprovalProfilesMBean approvalProfilesMBean;
    
    private int currentApprovalProfileId = -1;
    private ApprovalProfile approvalProfile = null;
    
    public ApprovalProfilesMBean getApprovalProfilesMBean() { return approvalProfilesMBean; }
    public void setApprovalProfilesMBean(ApprovalProfilesMBean approvalProfilesMBean) { this.approvalProfilesMBean = approvalProfilesMBean; }
    
    public Integer getSelectedApprovalProfileId() {
        return approvalProfilesMBean.getSelectedApprovalProfileId();
    }
    
    public String getSelectedApprovalProfileName() {
        return getEjbcaWebBean().getEjb().getApprovalProfileSession().getApprovalProfileName(getSelectedApprovalProfileId());
    }

    public ApprovalProfile getApprovalProfile() {
        if (currentApprovalProfileId!=-1 && approvalProfile!=null && getSelectedApprovalProfileId().intValue() != currentApprovalProfileId) {
            reset();
        }
        if (approvalProfile==null) {
            currentApprovalProfileId = getSelectedApprovalProfileId().intValue();
            final ApprovalProfile approvalProfile = getEjbcaWebBean().getEjb().getApprovalProfileSession().getApprovalProfile(currentApprovalProfileId);
            try {
                this.approvalProfile = approvalProfile.clone();
            } catch (CloneNotSupportedException e) {
                log.error("Approval Profiles should be clonable, but this one was not!", e);
            }
            currentApprovalProfileTypeName = this.approvalProfile.getApprovalProfileType().getClass().getCanonicalName();
            nrOfApprovalsProfileType = approvalProfile.getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals;
        }
        return approvalProfile;
    }
    
    private void reset() {
        currentApprovalProfileId = -1;
        approvalProfile = null;
        currentApprovalProfileTypeName = null;
        nrOfApprovalsProfileType = false;
        adminApprovalProfileType = false;
        propertiesList = null;
    }
    
    public String save() {
        try {
            final ApprovalProfile approvalProfile = getApprovalProfile();
            getEjbcaWebBean().getEjb().getApprovalProfileSession().changeApprovalProfile(getAdmin(), getSelectedApprovalProfileName(), approvalProfile);
            getEjbcaWebBean().getInformationMemory().approvalProfilesEdited();
            addInfoMessage("APPROVALPROFILESAVED");
            reset();
            return "done";  // Outcome defined in faces-config.xml
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit approval profile.");
        }
        return "";
    }
    
    public String cancel() {
        reset();
        return "done";  // Outcome defined in faces-config.xml
    }
    
    public void selectUpdate() {
        // NOOP: Only for page reload
    }
    
    
    // --------------------- Actions Requiring Approval ------------------------
    
    
    
    public List<SelectItem> getApprovalActionsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        
        Map<Integer, String> availableActions = ApprovalProfileType.getAvailableApprovableActions();
        Set<Entry<Integer, String> > entries = availableActions.entrySet();
        for(Entry<Integer, String> entry : entries) {
            ret.add(new SelectItem(entry.getKey(), getEjbcaWebBean().getText(entry.getValue())));
        }
        return ret;
    }
    public int[] getApprovalActions() throws AuthorizationDeniedException {
        ApprovalProfileType type = getApprovalProfile().getApprovalProfileType();
        if(type!=null) {
            return type.getActionsRequireApproval();
        }
        return new int[0];
    }
    public void setApprovalActions(int[] actions) {
        ApprovalProfile profile = getApprovalProfile();
        ApprovalProfileType profileType = profile.getApprovalProfileType();
        if(profileType != null) {
            profileType.setField(ApprovalProfileType.ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME, actions);
        }
        profile.setApprovalProfileType(profileType);
        approvalProfile = profile;
    }
    
    // --------------- Approval Profile Type -----------------------
    
    private String currentApprovalProfileTypeName = null;
    private boolean nrOfApprovalsProfileType = false;
    private boolean adminApprovalProfileType = false;
    
    public boolean getNrOfApprovalsProfileType() { return nrOfApprovalsProfileType; }
    public boolean getAdminApprovalProfileType() { return adminApprovalProfileType; }
    
    public String getCurrentApprovalProfileTypeName() {
        if(currentApprovalProfileTypeName == null) {
            currentApprovalProfileTypeName = getApprovalProfile().getApprovalProfileType().getClass().getCanonicalName();
        }
        return currentApprovalProfileTypeName;
    }
    
    public void setCurrentApprovalProfileTypeName(String typeName) {
        try {
            Class<ApprovalProfileType> c = (Class<ApprovalProfileType>) Class.forName(typeName);
            Object obj = c.newInstance();
            ApprovalProfileType profileType = (ApprovalProfileType) obj;
            profileType.init(null);
    
            ApprovalProfile profile = getApprovalProfile();
            profile.setApprovalProfileType(profileType);
            approvalProfile = profile;
            nrOfApprovalsProfileType = profileType instanceof ApprovalProfileNumberOfApprovals;
            adminApprovalProfileType = profileType instanceof ApprovalProfileByAdminRoles;
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            String msg = "Could not get an ApprovalProfileType from " + typeName + ". " + e.getLocalizedMessage();
            log.info(msg);
            super.addNonTranslatedErrorMessage(msg);
        }
        currentApprovalProfileTypeName = typeName;
    }
    
    public List<SelectItem> getApprovalProfileTypesAvailable() {
        getApprovalProfile();
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ServiceLoader<ApprovalProfileType> svcloader = ServiceLoader.load(ApprovalProfileType.class);
        for (ApprovalProfileType type : svcloader) {
            ret.add(new SelectItem(type.getClass().getCanonicalName(), type.getTypeName()));
        }
        return ret;
    }

    // ----------------- Approval Profile Type By Admins -------------- //
    
    public List<SelectItem> getAdminRolesAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ApprovalProfileType type = getApprovalProfile().getApprovalProfileType();
        if(type!=null && type instanceof ApprovalProfileByAdminRoles) {
            ApprovalProfileByAdminRoles adminProfileType = (ApprovalProfileByAdminRoles) type;
            Map<Integer, String> roles = adminProfileType.getAdminRolesNames(getAdmin(), getEjbcaWebBean().getEjb().getRoleManagementSession());
            Set<Entry<Integer, String>> entries = roles.entrySet();
            for(Entry<Integer, String> role : entries) {
                ret.add(new SelectItem(role.getValue(), role.getValue()));
            }
        }
        return ret;
    }
    
    
    // ------------ Number of approvals profile type ---------- //
    
    
    public void setNumberOfApprovals(String nrOfApprovals) {
        ApprovalProfileType type = getApprovalProfile().getApprovalProfileType();
        if(type instanceof ApprovalProfileNumberOfApprovals) {
            ApprovalProfileNumberOfApprovals nrOfApprovalsProfileType = (ApprovalProfileNumberOfApprovals) type;
            nrOfApprovalsProfileType.setNumberOfApprovals(Integer.parseInt(nrOfApprovals));
            getApprovalProfile().setApprovalProfileType(nrOfApprovalsProfileType);
        }
    }
    public String getNumberOfApprovals() {
        ApprovalProfileType type = getApprovalProfile().getApprovalProfileType();
        if(type instanceof ApprovalProfileNumberOfApprovals) {
            ApprovalProfileNumberOfApprovals nrOfApprovalsProfileType = (ApprovalProfileNumberOfApprovals) type;
            return Integer.toString(nrOfApprovalsProfileType.getNumberOfApprovals());
        }
        return "0";
    }
    public List<SelectItem> getNumberOfApprovalsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ApprovalProfileType type = getApprovalProfile().getApprovalProfileType();
        if(type!=null && type instanceof ApprovalProfileNumberOfApprovals) {
            if(approvalProfilesMBean.getViewOnly()) {
                ApprovalProfileNumberOfApprovals nrOfApprovalsProfileType = (ApprovalProfileNumberOfApprovals) type;
                String nrOfApprovals = Integer.toString(nrOfApprovalsProfileType.getNumberOfApprovals());
                ret.add(new SelectItem(nrOfApprovals, nrOfApprovals));
            } else {
                for(int i=0; i<10; i++) {
                    ret.add(new SelectItem(i, ""+i));
                }
            }
        }
        return ret;
    }
    
    
    
    // ---------------------- Properties ------------------
    
    private String addProperyKey = "";
    private String addProperyValue = "";
    private String addPropertyDescription = "";
    private int addPropertyMetaDataType = 0;
    private String addPropertyMetaData = "";
    
    private ListDataModel<ApprovalPropertyGuiInfo> propertiesList = null;

    public String getAddProperyKey() { return addProperyKey; }
    public void setAddProperyKey(String key) { addProperyKey = key; }
    
    public String getAddProperyValue() { return addProperyValue; }
    public void setAddProperyValue(String value) { addProperyValue = value; }
    
    public String getAddPropertyDescription() { return addPropertyDescription;}
    public void setAddPropertyDescription(String desc) { addPropertyDescription = desc; }
    
    public int getAddPropertyMetaDataType() { return addPropertyMetaDataType; }
    public void setAddPropertyMetaDataType(int type) { addPropertyMetaDataType=type; }
    public List<SelectItem> getMetadataTypesAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ret.add(new SelectItem(ApprovalProfileFieldObject.METADATATYPE_CHECKBOX, "Check boxes"));
        ret.add(new SelectItem(ApprovalProfileFieldObject.METADATATYPE_RADIOBUTTON, "Radio buttens"));
        ret.add(new SelectItem(ApprovalProfileFieldObject.METADATATYPE_TEXTBOX, "Text field"));
        return ret;
    } 
    
    public String getAddPropertyMetaData() { return addPropertyMetaData; }
    public void setAddPropertyMetaData(String metadata) { addPropertyMetaData = metadata; }
    
    public void deletePropertyAction() {
        final ApprovalPropertyGuiInfo approvalPropertyItem = (ApprovalPropertyGuiInfo) getPropertiesList().getRowData();
        ApprovalProfile profile = getApprovalProfile();
        profile.removeProperty(approvalPropertyItem.getPropertyKey());
        approvalProfile = profile;
        propertiesList = null;

    }
    
    public void addPropertyAction() {
        ArrayList<String> metadata = new ArrayList<>();
        if(getAddPropertyMetaDataType() == ApprovalProfileFieldObject.METADATATYPE_TEXTBOX) {
            metadata.add(getAddPropertyMetaData());
        } else {
            String[] metadataArray = getAddPropertyMetaData().split(";");
            metadata.addAll(Arrays.asList(metadataArray));
        }
        ApprovalProfileFieldObject fieldObj = new ApprovalProfileFieldObject(addProperyValue, addPropertyDescription, metadata, getAddPropertyMetaDataType());
        ApprovalProfile profile = getApprovalProfile();
        profile.setProperty(getAddProperyKey(), fieldObj);
        approvalProfile = profile;
        propertiesList = null;
        resetAddPropery();
    }
    
    public ListDataModel<ApprovalPropertyGuiInfo> getPropertiesList() {
        if (propertiesList == null) {
            final List<ApprovalPropertyGuiInfo> items = new ArrayList<ApprovalPropertyGuiInfo>();
            ApprovalProfile profile = getApprovalProfile();
            Map<String, Object> allFields = profile.getAllFields();
            Set<Entry<String, Object>> entries = allFields.entrySet();
            for(Entry<String, Object> entry : entries) {
                Object value = entry.getValue();
                if(entry.getValue() instanceof ApprovalProfileFieldObject) {
                    String key = entry.getKey();
                    ApprovalProfileFieldObject fieldObject = (ApprovalProfileFieldObject) value;
                    ApprovalPropertyGuiInfo item = new ApprovalPropertyGuiInfo(key, fieldObject);
                    items.add(item);
                }
            }
            propertiesList = new ListDataModel<ApprovalPropertyGuiInfo>(items);
        }
        return propertiesList;
    }
    
    private void resetAddPropery() {
        addProperyKey = "";
        addProperyValue = "";
        addPropertyDescription = "";
        addPropertyMetaDataType = 0;
        addPropertyMetaData = "";
    }
    
    
    

    
    
    
    /*
    
 // Actions ----------------------------------------------------------------------------------
    private void loadDynamicList() {
        
        // Set headers (optional).
        dynamicHeaders = new String[] {"Propery Key", "Property Value", "Property Description", "Propert MetaData Type", "MetaDataOptions"};
 
        // Set rows
        dynamicList = new ArrayList<List<String>>();
        
        ApprovalProfile profile = getApprovalProfile();
        Map<String, Object> allFields = profile.getAllFields();
        Set<Entry<String, Object>> entries = allFields.entrySet();
        for(Entry<String, Object> entry : entries) {
            Object value = entry.getValue();
            if(entry.getValue() instanceof ApprovalProfileFieldObject) {
                ArrayList<String> row = new ArrayList<String>();
                String key = entry.getKey();
                ApprovalProfileFieldObject fieldObject = (ApprovalProfileFieldObject) value;
                row.add(key);
                row.add(fieldObject.getKeyObject());
                row.add(fieldObject.getDescription());
                row.add(fieldObject.getMetaDataType()+"");
                StringBuilder options = new StringBuilder("");
                for(String option : fieldObject.getMetaData()) {
                    options.append(option + ", ");
                }
                options.deleteCharAt(options.length()-2);
                row.add(options.toString());
                dynamicList.add(row);
            }
        }
        
        
        //dynamicList.add(Arrays.asList(new String[] { "Super Admin Role", "Check Location", "See Skatteverket", "2"}));
 
    }
   
    
    
    

    //-------------- Properties  ------------------------------//
    
    private static List<List<String>> dynamicList; // Simulate fake DB.
    private static String[] dynamicHeaders; // Optional.
    private HtmlPanelGroup dynamicDataTableGroup; // Placeholder.
 
    // Actions -----------------------------------------------------------------------------------
 
    private void loadDynamicList() {
 
        // Set headers (optional).
        dynamicHeaders = new String[] {"Property", "Key"};
 
        // Set rows
        dynamicList = new ArrayList<List<String>>();
        dynamicList.add(Arrays.asList(new String[] { "1", "Europe" }));
        dynamicList.add(Arrays.asList(new String[] { "2", "Americas" }));
        dynamicList.add(Arrays.asList(new String[] { "3", "Asia" }));
        dynamicList.add(Arrays.asList(new String[] { "4", "Middle East and Africa"}));
 
    }
 
    private void populateDynamicDataTable() {
 
        // Context and Expression Factory
        FacesContext fCtx = FacesContext.getCurrentInstance();
        ELContext elCtx = fCtx.getELContext();
        ExpressionFactory ef = fCtx.getApplication().getExpressionFactory();
 
        // Create <h:dataTable value="#{datatableManagedBean.dynamicList}" var="dynamicRow">.
        HtmlDataTable dynamicDataTable = new HtmlDataTable();
        ValueExpression ve = ef.createValueExpression(elCtx,"#{datatableManagedBean.dynamicList}",List.class);
        dynamicDataTable.setValueExpression("value", ve);
        dynamicDataTable.setVar("dynamicRow");
 
        // Iterate over columns
        for (int i = 0; i < dynamicList.get(0).size(); i++) {
 
            // Create <h:column>.
            HtmlColumn column = new HtmlColumn();
            dynamicDataTable.getChildren().add(column);
 
            // Create <h:outputText value="dynamicHeaders[i]"> for <f:facet name="header"> of column.
            HtmlOutputText header = new HtmlOutputText();
            header.setValue(dynamicHeaders[i]);
            column.setHeader(header);
 
            // Create <h:outputText value="#{dynamicRow[" + i + "]}"> for the body of column.
            HtmlOutputText output = new HtmlOutputText();
            ve = ef.createValueExpression(elCtx, "#{dynamicRow[" + i + "]}", String.class);
            output.setValueExpression("value", ve);
            column.getChildren().add(output);
 
        }
 
        // Add the datatable to <h:panelGroup binding="#{datatableManagedBean.dynamicDataTableGroup}">.
        dynamicDataTableGroup = new HtmlPanelGroup();
        dynamicDataTableGroup.getChildren().add(dynamicDataTable);
 
    }
 
    // Getters -----------------------------------------------------------------------------------
 
    public HtmlPanelGroup getDynamicDataTableGroup() {
        // This will be called once in the first RESTORE VIEW phase.
        if (dynamicDataTableGroup == null) {
            loadDynamicList(); // Preload dynamic list.
            populateDynamicDataTable(); // Populate editable datatable.
        }
 
        return dynamicDataTableGroup;
    }
 
    public List<List<String>> getDynamicList() {
        return dynamicList;
    }
 
    // Setters -----------------------------------------------------------------------------------
 
    public void setDynamicDataTableGroup(HtmlPanelGroup dynamicDataTableGroup) {
        this.dynamicDataTableGroup = dynamicDataTableGroup;
    }
    */
}
