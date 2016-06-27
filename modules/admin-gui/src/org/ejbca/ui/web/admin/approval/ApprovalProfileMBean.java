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

    public ApprovalProfilesMBean getApprovalProfilesMBean() {
        return approvalProfilesMBean;
    }

    public void setApprovalProfilesMBean(ApprovalProfilesMBean approvalProfilesMBean) {
        this.approvalProfilesMBean = approvalProfilesMBean;
    }

    /** @return the select profile id from the list view or the one cached in this view (this will never change in the view) */
    public int getSelectedApprovalProfileId() {
        if (currentApprovalProfileId==-1) {
            final Integer id = approvalProfilesMBean.getSelectedApprovalProfileId();
            if (id!=null) {
                currentApprovalProfileId = id.intValue();
            }
        }
        return currentApprovalProfileId;
    }

    public String getSelectedApprovalProfileName() {
        return approvalProfileSession.getApprovalProfileName(getSelectedApprovalProfileId());
    }

    public ApprovalProfile getApprovalProfile() {
        if (currentApprovalProfile == null && getSelectedApprovalProfileId()!=-1) {
            final ApprovalProfile approvalProfile = approvalProfileSession.getApprovalProfile(getSelectedApprovalProfileId());
            if (approvalProfile!=null) {
                this.currentApprovalProfile = approvalProfile.clone();
            }
        }
        return currentApprovalProfile;
    }

    @SuppressWarnings("unchecked")
    public String save() {
        try {
            final ApprovalProfile approvalProfile = getApprovalProfile();
            for (final ApprovalStepGuiObject approvalSequenceGuiObject : steps) {
                final int sequenceIdentifier = approvalSequenceGuiObject.getIdentifier();
                for (final ApprovalPartitionProfileGuiObject approvalPartitionGuiObject : approvalSequenceGuiObject.getPartitionGuiObjects()) {
                    approvalProfile.addPropertiesToPartition(sequenceIdentifier, approvalPartitionGuiObject.getPartitionId(),
                            (List<DynamicUiProperty<? extends Serializable>>) approvalPartitionGuiObject.getProfilePropertyList().getWrappedData());
                }
            }
            approvalProfileSession.changeApprovalProfile(getAdmin(), approvalProfile);
            addInfoMessage("APPROVALPROFILESAVED");
            return "done";
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit approval profiles.");
        }
        return "";
    }

    public String cancel() {
        return "done";
    }
    
    public void addStep() {
        getApprovalProfile().addStepFirst();
        steps = null;
    }
    
    public void deleteStep() {
        getApprovalProfile().deleteStep(steps.getRowData().getIdentifier());
        steps = null;
    }
    
    public void addPartition() {
        getApprovalProfile().addPartition(steps.getRowData().getIdentifier());
        steps = null;
    }
    
    public void deletePartition(int partitionId) {
        getApprovalProfile().deletePartition(steps.getRowData().getIdentifier(), partitionId);
        steps = null;
    }

    public void selectUpdate() {
        // NOOP: Only for page reload
    }

    public String getCurrentApprovalProfileTypeName() {
        return getApprovalProfile().getApprovalProfileIdentifier();
    }

    public void setCurrentApprovalProfileTypeName(String typeName) {
        // Re-instantiate approval profile if we've changed type
        if (!getApprovalProfile().getApprovalProfileIdentifier().equals(typeName)) {
            final ApprovalProfile newApprovalProfile = ApprovalProfilesFactory.INSTANCE.getArcheType(typeName);
            newApprovalProfile.setProfileId(getSelectedApprovalProfileId());
            newApprovalProfile.setProfileName(getSelectedApprovalProfileName());
            currentApprovalProfile = newApprovalProfile;
            steps = null;
        }
    }

    public List<SelectItem> getApprovalProfileTypesAvailable() {
        final List<SelectItem> ret = new ArrayList<SelectItem>();
        for (final ApprovalProfile type : ApprovalProfilesFactory.INSTANCE.getAllImplementations()) {
            ret.add(new SelectItem(type.getApprovalProfileIdentifier(), type.getApprovalProfileLabel()));
        }
        return ret;
    }

    /** @return a list of the current steps in the current Approval Profile object */
    public ListDataModel<ApprovalStepGuiObject> getSteps() {
        if (steps == null) {
            final ApprovalProfile approvalProfile = getApprovalProfile();
            if (approvalProfile!=null) {
                steps = createStepListFromProfile(approvalProfile);   
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
    
    /** @return true of the approval profile is of a type where sequences can be added  */
    public boolean isStepSizeFixed() {
        return ApprovalProfilesFactory.INSTANCE.getArcheType(getCurrentApprovalProfileTypeName()).isStepSizeFixed();
    }

    public boolean isNotificationEnabled(final int partitionIdentifier) {
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(steps.getRowData().getIdentifier());
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        return approvalPartition!=null && approvalPartition.getProperty(ApprovalProfile.PROPERTY_NOTIFICATION_EMAIL_RECIPIENT) != null;
    }

    public void addNotification(final int partitionIdentifier) {
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(steps.getRowData().getIdentifier());
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        approvalProfile.addNotificationProperties(approvalPartition);
        steps = null;
    }

    public void removeNotification(final int partitionIdentifier) {
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(steps.getRowData().getIdentifier());
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        approvalProfile.removeNotificationProperties(approvalPartition);
        steps = null;
    }
}
