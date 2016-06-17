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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleInformation;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfilesFactory;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.ui.web.admin.BaseManagedBean;

/**
 * JSF MBean backing the approval profile pages.
 * @version $Id$
 *
 */
@ViewScoped // Local variables will live as long as actions on the backed page return "" or void.
@ManagedBean(name="approvalProfileMBean")
public class ApprovalProfileMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -3751383340600251434L;

    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;

    @ManagedProperty(value = "#{approvalProfilesMBean}")
    private ApprovalProfilesMBean approvalProfilesMBean;

    private int currentApprovalProfileId = -1;
    private ApprovalProfile currentApprovalProfile = null;

    private ListDataModel<ApprovalStepGuiObject> steps = null;

    private String currentApprovalProfileTypeName = null;

    public ApprovalProfilesMBean getApprovalProfilesMBean() {
        return approvalProfilesMBean;
    }

    public void setApprovalProfilesMBean(ApprovalProfilesMBean approvalProfilesMBean) {
        this.approvalProfilesMBean = approvalProfilesMBean;
    }

    public Integer getSelectedApprovalProfileId() {
        return approvalProfilesMBean.getSelectedApprovalProfileId();
    }

    public String getSelectedApprovalProfileName() {
        return approvalProfileSession.getApprovalProfileName(getSelectedApprovalProfileId());
    }

    public ApprovalProfile getApprovalProfile() {
        if (currentApprovalProfileId != -1 && currentApprovalProfile != null && getSelectedApprovalProfileId().intValue() != currentApprovalProfileId) {
            reset();
        }
        if (currentApprovalProfile == null) {
            currentApprovalProfileId = getSelectedApprovalProfileId().intValue();
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(currentApprovalProfileId);
            this.currentApprovalProfile = approvalProfile.clone();
        }
        return currentApprovalProfile;
    }

    private void reset() {
        currentApprovalProfileId = -1;
        currentApprovalProfile = null;
        currentApprovalProfileTypeName = null;
        steps = null;

    }

    @SuppressWarnings("unchecked")
    public String save() {
        try {
            ApprovalProfile currentApprovalProfile = getApprovalProfile();
            ApprovalProfile newApprovalProfile;
            //Reinstance approval profile if we've changed type
            if (!currentApprovalProfile.getApprovalProfileIdentifier().equals(currentApprovalProfileTypeName)) {
                newApprovalProfile = ApprovalProfilesFactory.INSTANCE.getArcheType(currentApprovalProfileTypeName);
                newApprovalProfile.setProfileId(getSelectedApprovalProfileId());
                newApprovalProfile.setProfileName(getSelectedApprovalProfileName());
            } else {
                newApprovalProfile = currentApprovalProfile;
            }
            for (ApprovalStepGuiObject approvalSequenceGuiObject : steps) {
                int sequenceIdentifier = approvalSequenceGuiObject.getIdentifier();
                for (ApprovalPartitionProfileGuiObject approvalPartitionGuiObject : approvalSequenceGuiObject.getPartitionGuiObjects()) {
                    newApprovalProfile.addPropertiesToPartition(sequenceIdentifier, approvalPartitionGuiObject.getPartitionId(),
                            (List<DynamicUiProperty<? extends Serializable>>) approvalPartitionGuiObject.getProfilePropertyList().getWrappedData());
                }
            }
            approvalProfileSession.changeApprovalProfile(getAdmin(), newApprovalProfile);
            addInfoMessage("APPROVALPROFILESAVED");
            reset();
            return "done";
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit approval profiles.");
        }
        return "";
    }

    public String cancel() {
        reset();
        return "done";
    }
    
    public String addStep() {
        ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        updatedApprovalProfile.addStepFirst();
        steps = createStepListFromProfile(updatedApprovalProfile);
        return "";
    }
    
    public String deleteStep() {
        ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        updatedApprovalProfile.deleteStep(steps.getRowData().getIdentifier());
        steps = createStepListFromProfile(updatedApprovalProfile);
        return "";
    }
    
    public String addPartition() {
        ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        updatedApprovalProfile.addPartition(steps.getRowData().getIdentifier());
        steps = createStepListFromProfile(updatedApprovalProfile);
        return "";
    }
    
    public String deletePartition(int partitionId) {
        ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        updatedApprovalProfile.deletePartition(steps.getRowData().getIdentifier(), partitionId);
        steps = createStepListFromProfile(updatedApprovalProfile);
        return "";
    }

    public void selectUpdate() {
        // NOOP: Only for page reload
    }

    public String getCurrentApprovalProfileTypeName() {
        if (currentApprovalProfileTypeName == null) {
            currentApprovalProfileTypeName = getApprovalProfile().getApprovalProfileIdentifier();
        }
        return currentApprovalProfileTypeName;
    }

    public void setCurrentApprovalProfileTypeName(String typeName) {
        //Reload property list 
        steps = null;
        currentApprovalProfileTypeName = typeName;
    }

    public List<SelectItem> getApprovalProfileTypesAvailable() {
        getApprovalProfile();
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (ApprovalProfile type : ApprovalProfilesFactory.INSTANCE.getAllImplementations()) {
            ret.add(new SelectItem(type.getApprovalProfileIdentifier(), type.getApprovalProfileLabel()));
        }
        return ret;
    }

    /** @return a list of the current steps in the current Approval Profile object */
    public ListDataModel<ApprovalStepGuiObject> getSteps() {
        if (steps == null) {
            ApprovalProfile approvalProfile = getApprovalProfile();
            if (approvalProfile.getApprovalProfileIdentifier().equals(getCurrentApprovalProfileTypeName())) {
                steps = createStepListFromProfile(approvalProfile);   
            } else {
                //Else if we're switching, reset from the default
                ApprovalProfile archetype = ApprovalProfilesFactory.INSTANCE.getArcheType(getCurrentApprovalProfileTypeName());
                steps = createStepListFromProfile(archetype);  
            }
        }
        return steps;
    }
    
    private ListDataModel<ApprovalStepGuiObject> createStepListFromProfile(final ApprovalProfile approvalProfile) {
        List<ApprovalStepGuiObject> steps = new ArrayList<>();
        int ordinal = 0;
        //Use the internal ordering for sequences, if one is predefined
        ApprovalStep step = approvalProfile.getFirstStep();
        Map<Integer, List<DynamicUiProperty<? extends Serializable>>> partitionProperties = getPartitionProperties(step);
        steps.add(new ApprovalStepGuiObject(step, approvalProfile.getApprovalProfileIdentifier(), ordinal, partitionProperties));
        while (step.getNextStep() != null) {
            step = approvalProfile.getStep(step.getNextStep());
            partitionProperties = getPartitionProperties(step);
            steps.add(new ApprovalStepGuiObject(step, approvalProfile.getApprovalProfileIdentifier(), ++ordinal, partitionProperties));
        }
        return new ListDataModel<>(steps);
    }

    /**
     * Take an approval step and extract its partitions and respective properties, filling in with values from the database where required. 
     * 
     * @param step an approval step
     * @return a Map linking partitions IDs to lists of each partitions properties. 
     */
    private Map<Integer, List<DynamicUiProperty<? extends Serializable>>> getPartitionProperties(ApprovalStep step) {
        Map<Integer, List<DynamicUiProperty<? extends Serializable>>> partitionProperties = new LinkedHashMap<>();
        for(ApprovalPartition approvalPartition : step.getPartitions().values() ) {
            List<DynamicUiProperty<? extends Serializable>> propertyList = new ArrayList<>();
            for(DynamicUiProperty<? extends Serializable> property : approvalPartition.getPropertyList().values()) {
                DynamicUiProperty<? extends Serializable> propertyClone = new DynamicUiProperty<>(property);
                switch (propertyClone.getPropertyCallback()) {
                case ROLES:
                    List<RoleData> allAuthorizedRoles = roleAccessSession.getAllAuthorizedRoles(getAdmin());
                    List<RoleInformation> roleRepresentations = new ArrayList<>();
                    for(RoleData role : allAuthorizedRoles) {
                        RoleInformation identifierNamePair = new RoleInformation(role.getPrimaryKey(), role.getRoleName(), new ArrayList<>(role.getAccessUsers().values()));
                        roleRepresentations.add(identifierNamePair);
                    }                
                    if(!roleRepresentations.contains(propertyClone.getDefaultValue())) {
                        //Add the default, because it makes no sense why it wouldn't be there. Also, it may be a placeholder for something else. 
                        roleRepresentations.add(0, (RoleInformation) propertyClone.getDefaultValue());
                    }
                    propertyClone.setPossibleValues(roleRepresentations);
                    break;
                case NONE:
                    break;
                default:
                    break;
                }
                propertyList.add(propertyClone);
            }           
            partitionProperties.put(approvalPartition.getPartitionIdentifier(), propertyList);
        }
        return partitionProperties;
    }
    
    /**
     * @return true of the approval profile is of a type where sequences can be added 
     */
    public boolean isStepSizeFixed() {
        return ApprovalProfilesFactory.INSTANCE.getArcheType(getCurrentApprovalProfileTypeName()).isStepSizeFixed();
    }

}
