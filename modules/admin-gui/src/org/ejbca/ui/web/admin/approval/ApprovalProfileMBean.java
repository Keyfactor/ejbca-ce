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
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;

import javax.el.ELContext;
import javax.el.ExpressionFactory;
import javax.el.ValueExpression;
import javax.faces.component.html.HtmlColumn;
import javax.faces.component.html.HtmlDataTable;
import javax.faces.component.html.HtmlOutputText;
import javax.faces.component.html.HtmlPanelGroup;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalProfileByAdminRoles;
import org.ejbca.core.model.approval.ApprovalProfileNumberOfApprovals;
import org.ejbca.core.model.approval.ApprovalProfileType;
import org.ejbca.core.model.approval.ApprovalStep;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the approval profile pages.
 * @version $Id$
 *
 */
public class ApprovalProfileMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -3751383340600251434L;
    
    public class ApprovalStepGuiInfo {
        private int stepId;
        private String stepAuthorizationObject;
        private String metadataInstruction;
        private String metadataOptions;
        private int metadataOptionsType;
        private String metadataOptionTypeString;
        private int nrOfApprovals;
        private boolean canSeePreviousSteps;
        private String email;
        public ApprovalStepGuiInfo(final ApprovalStep step) {
            stepId = step.getStepId();
            stepAuthorizationObject = step.getStepAuthorizationObject();
            metadataInstruction = step.getMetadata().getInstruction();
            
            List<String> mtoptions = step.getMetadata().getOptions();
            StringBuilder optionsBuilder = new StringBuilder("");
            for(String option : mtoptions) {
                optionsBuilder.append(option + ", ");
            }
            optionsBuilder.deleteCharAt(optionsBuilder.length()-2);
            metadataOptions = optionsBuilder.toString();
            
            metadataOptionsType = step.getMetadata().getOptionsType();
            if(metadataOptionsType == ApprovalStep.METADATATYPE_CHECKBOX) {
                metadataOptionTypeString = "Check Boxes";
            } else if(metadataOptionsType == ApprovalStep.METADATATYPE_RADIOBUTTON) {
                metadataOptionTypeString = "Radio Buttons";
            } else if(metadataOptionsType == ApprovalStep.METADATATYPE_TEXTBOX) {
                metadataOptionTypeString = "Text Box";
            } else {
                metadataOptionTypeString = "Type unknown";
            }
            
            nrOfApprovals = step.getRequiredNumberOfApproval();
            canSeePreviousSteps = step.canSeePreviousSteps();
            email = step.getNotificationEmail();
        }
        
        public int getStepId() {return stepId; }
        public String getStepAuthorizationObject() { return stepAuthorizationObject; }
        public String getMetadataInstruction() { return metadataInstruction; }
        public String getMetadataOptions() { return metadataOptions; }
        public int getMetadataOptionsType() { return metadataOptionsType; }
        public String getMetadataOptionTypeString() {return metadataOptionTypeString;}
        public int getNrOfApprovals() { return nrOfApprovals; }
        public boolean getCanSeePreviousSteps() { return canSeePreviousSteps; }
        public String getEmail() { return email; }

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
        
        currentApprovalSteps = null;
        approvalStepsList = null;
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
    public int[] getApprovalActions() {
        return getApprovalProfile().getActionsRequireApproval();
    }
    public void setApprovalActions(int[] actions) {
        ApprovalProfile profile = getApprovalProfile();
        profile.setActionsRequireApproval(actions);
        approvalProfile = profile;
    }
    
    // --------------- Approval Profile Type -----------------------
    
    private String currentApprovalProfileTypeName = null;
    private boolean nrOfApprovalsProfileType = false;
    
    public boolean getNrOfApprovalsProfileType() { return nrOfApprovalsProfileType; }
    
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
            profileType.init();
            
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

    // -----------------None number of approvals Approval Profile Type -------------- //
    
    public List<SelectItem> getMainAuthorizationObjectOptions() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ApprovalProfileType type = getApprovalProfile().getApprovalProfileType();
        if(type!=null && type instanceof ApprovalProfileByAdminRoles) {
            ApprovalProfileByAdminRoles adminProfileType = (ApprovalProfileByAdminRoles) type;
            Map<Integer, String> roles = adminProfileType.getMainAuthorizationObjectOptions();
            Set<Entry<Integer, String>> entries = roles.entrySet();
            for(Entry<Integer, String> role : entries) {
                ret.add(new SelectItem(role.getValue(), role.getValue()));
            }
        }
        return ret;
    }
    
    
    // ------------ Number of approvals profile type ---------- //
    
    
    public void setNumberOfApprovals(String nrOfApprovals) {
        ApprovalProfile profile = getApprovalProfile();
        profile.setNumberOfApprovals(Integer.parseInt(nrOfApprovals));
        approvalProfile = profile;
    }
    public String getNumberOfApprovals() {
        int nrOfApprovals = getApprovalProfile().getNumberOfApprovals();
        return ""+nrOfApprovals;
    }
    public List<SelectItem> getNumberOfApprovalsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ApprovalProfileType type = getApprovalProfile().getApprovalProfileType();
        if(type!=null && type instanceof ApprovalProfileNumberOfApprovals) {
            if(approvalProfilesMBean.getViewOnly()) {
                String nrOfApprovals = Integer.toString(getApprovalProfile().getNumberOfApprovals());
                ret.add(new SelectItem(nrOfApprovals, nrOfApprovals));
            } else {
                for(int i=0; i<10; i++) {
                    ret.add(new SelectItem(i, ""+i));
                }
            }
        }
        return ret;
    }
    
    
    // ----------------------- Approval Steps ------------------------
    
    
    private Map<Integer, ApprovalStep> currentApprovalSteps = null;
    private ListDataModel<ApprovalStepGuiInfo> approvalStepsList = null;
    
    public ListDataModel<ApprovalStepGuiInfo> getApprovalStepsList() {
        if(approvalStepsList==null) {
            final ApprovalProfile profile = getApprovalProfile();
            if(currentApprovalSteps == null) {
                currentApprovalSteps = profile.getApprovalSteps();
            }
            ArrayList<ApprovalStepGuiInfo> approvalSteps = new ArrayList<ApprovalStepGuiInfo>();
            Map<Integer, ApprovalStep> steps = profile.getApprovalSteps();
            for(Integer stepid : steps.keySet()) {
                ApprovalStep step = steps.get(stepid);
                ApprovalStepGuiInfo stepGui = new ApprovalStepGuiInfo(step);
                approvalSteps.add(stepGui);
            }
            
            // Sort list by id
            Collections.sort(approvalSteps, new Comparator<ApprovalStepGuiInfo>() {
                @Override
                public int compare(final ApprovalStepGuiInfo a, final ApprovalStepGuiInfo b) {
                    if(a.getStepId() < b.getStepId()) {
                        return -1;
                    } else if(a.getStepId() < b.getStepId()) {
                        return 1;
                    } else {
                    return 0;
                    }
                }
            });
            
            
            approvalStepsList = new ListDataModel<ApprovalStepGuiInfo>(approvalSteps);
        }
        return approvalStepsList;
    }
    
    
    // ---------------------- Add new Approval Step ------------------
    
    
    private boolean addingNewStep = false;
    private String newStepAuthorizationObject = "";
    private String newStepMetadataInstruction = "";
    private String newStepMetadataOptions = "";
    private int newStepMetadataOptionsType = 1;
    private int newStepNrOfApprovals = 1;
    private boolean newStepCanSeePreviousSteps = false;
    private String newStepEmail = "";
    private List<String> newStepPreviousStepsDependency = new ArrayList<String>();
    
    public boolean getAddingNewStep() { return addingNewStep; }
    
    private int getNewStepId() {
        return getApprovalProfile().getNewStepId();
    }
    
    public String getNewStepAuthorizationObject() { return newStepAuthorizationObject; }
    public void setNewStepAuthorizationObject(String object) { newStepAuthorizationObject=object; }
    public String getNewStepMetadataInstruction() { return newStepMetadataInstruction; }
    public void setNewStepMetadataInstruction(String instruction) { newStepMetadataInstruction=instruction; }
    public String getNewStepMetadataOptions() { return newStepMetadataOptions; }
    public void setNewStepMetadataOptions(String options) { newStepMetadataOptions=options; }
    public int getNewStepMetadataOptionsType() { return newStepMetadataOptionsType; }
    public void setNewStepMetadataOptionsType(int type) { newStepMetadataOptionsType=type; }
    public List<SelectItem> getOptionTypesAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        ret.add(new SelectItem(ApprovalStep.METADATATYPE_CHECKBOX, "Check boxes"));
        ret.add(new SelectItem(ApprovalStep.METADATATYPE_RADIOBUTTON, "Radio buttons"));
        ret.add(new SelectItem(ApprovalStep.METADATATYPE_TEXTBOX, "Text field"));
        return ret;
    }
    public int getNewStepNrOfApprovals() { return newStepNrOfApprovals; }
    public void setNewStepNrOfApprovals(int nrOfApprovals) { newStepNrOfApprovals=nrOfApprovals; }
    public List<SelectItem> getNrOfApprovalsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for(int i=0; i<5; ++i) {
            ret.add(new SelectItem(i));
        }
        return ret;
    }
    public boolean getNewStepCanSeePreviousSteps() { return newStepCanSeePreviousSteps; }
    public void setNewStepCanSeePreviousSteps(boolean canSeePreviousSteps) { newStepCanSeePreviousSteps=canSeePreviousSteps; }
    public String getNewStepEmail() { return newStepEmail; }
    public void setNewStepEmail(String email) { newStepEmail=email; }
    public List<String> getNewStepPreviousStepsDependency() { return newStepPreviousStepsDependency; }
    public void setNewStepPreviousStepsDependency(final List<String> dependencyList) { newStepPreviousStepsDependency=dependencyList; }
    public List<SelectItem> getPreviousStepsAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for(Integer id : currentApprovalSteps.keySet()) {
            ret.add(new SelectItem(id));
        }
        return ret;
    }
    
    
    public void addNewStep() {
        String[] options = getNewStepMetadataOptions().split(";");
        ArrayList<String> optionsList = new ArrayList<String>();
        for(String option : options) {
            optionsList.add(option);
        }
        
        ArrayList<Integer> dependencyList = new ArrayList<Integer>();
        for(String id : getNewStepPreviousStepsDependency()) {
            dependencyList.add(new Integer(id));
        }
        ApprovalStep step = new ApprovalStep(getNewStepId(), getNewStepAuthorizationObject(), getNewStepMetadataInstruction(), 
                optionsList, getNewStepMetadataOptionsType(), getNewStepNrOfApprovals(), getNewStepCanSeePreviousSteps(), 
                getNewStepEmail(), dependencyList);
        getApprovalProfile().addApprovalStep(step);
        currentApprovalSteps.put(step.getStepId(), step);
        resetSteps();
    }
    
    private void resetSteps() {
        addingNewStep = false;
        
        newStepAuthorizationObject = "";
        newStepMetadataInstruction = "";
        newStepMetadataOptions = "";
        newStepMetadataOptionsType = 1;
        newStepNrOfApprovals = 1;
        newStepCanSeePreviousSteps = false;
        newStepEmail = "";
        newStepPreviousStepsDependency = new ArrayList<String>();
        
        approvalStepsList = null;
    }
    
 // Actions ----------------------------------------------------------------------------------
    
    private static List<ApprovalStepGuiInfo> dynamicList; // Simulate fake DB.
    private HtmlPanelGroup dynamicDataTableGroup; // Placeholder.
    
    private void loadDynamicList() {
        
        // Set headers (optional).
        //dynamicHeaders = new String[] {"Propery Key", "Property Value", "Property Description", "Propert MetaData Type", "MetaDataOptions"};
 
        // Set rows
        dynamicList = new ArrayList<ApprovalStepGuiInfo>();
        
        ApprovalProfile profile = getApprovalProfile();
        Map<Integer, ApprovalStep> steps = profile.getApprovalSteps();
        for(ApprovalStep step : steps.values()) {
            ApprovalStepGuiInfo stepgui = new ApprovalStepGuiInfo(step);
            //ArrayList<ApprovalStepGuiInfo> row = new ArrayList<ApprovalStepGuiInfo>();
            //row.add(stepgui);
            //dynamicList.add(row);
            dynamicList.add(stepgui);
        }
        //dynamicList.add(Arrays.asList(new String[] { "Super Admin Role", "Check Location", "See Skatteverket", "2"}));
    }
    
    private void populateDynamicDataTable() {
        
        // Context and Expression Factory
        FacesContext fCtx = FacesContext.getCurrentInstance();
        ELContext elCtx = fCtx.getELContext();
        ExpressionFactory ef = fCtx.getApplication().getExpressionFactory();
 
        // Create <h:dataTable value="#{datatableManagedBean.dynamicList}" var="dynamicRow">.
        HtmlDataTable dynamicDataTable = new HtmlDataTable();
        ValueExpression ve = ef.createValueExpression(elCtx,"#{approvalProfileMBean.dynamicList}",List.class);
        dynamicDataTable.setValueExpression("value", ve);
        dynamicDataTable.setVar("dynamicRow");
 
        // Iterate over columns
        for (int i = 0; i < dynamicList.size(); i++) {
 
            // Create <h:column>.
            HtmlColumn column = new HtmlColumn();
            dynamicDataTable.getChildren().add(column);
 
            // Create <h:outputText value="dynamicHeaders[i]"> for <f:facet name="header"> of column.
            //HtmlOutputText header = new HtmlOutputText();
            //header.setValue(dynamicHeaders[i]);
            //column.setHeader(header);
 
            // Create <h:outputText value="#{dynamicRow[" + i + "]}"> for the body of column.
            HtmlOutputText output = new HtmlOutputText();
            ve = ef.createValueExpression(elCtx, "#{dynamicRow.stepId}", String.class);
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
 
    public List<ApprovalStepGuiInfo> getDynamicList() {
        return dynamicList;
    }
 
    // Setters -----------------------------------------------------------------------------------
 
    public void setDynamicDataTableGroup(HtmlPanelGroup dynamicDataTableGroup) {
        this.dynamicDataTableGroup = dynamicDataTableGroup;
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
