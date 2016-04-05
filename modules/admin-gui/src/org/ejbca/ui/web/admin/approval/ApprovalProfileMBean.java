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
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;

import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalProfileNumberOfApprovals;
import org.ejbca.core.model.approval.ApprovalProfileType;
import org.ejbca.ui.web.admin.BaseManagedBean;

public class ApprovalProfileMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -3751383340600251434L;
    
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

    
    // ------------ Number of approvals profile type ---------- //
    
    private boolean nrOfApprovalsProfileType = false;
    
    public boolean getNrOfApprovalsProfileType() {
        return nrOfApprovalsProfileType;
    }
    
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
                for(int i=0; i<10; i++)
                ret.add(new SelectItem(i, ""+i));
            }
        }
        return ret;
    }
    
    
    
    /*
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
