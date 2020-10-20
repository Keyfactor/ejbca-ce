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
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.faces.model.ListDataModel;
import javax.faces.model.SelectItem;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.RoleInformation;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.MultiLineString;
import org.cesecore.util.ui.PropertyValidationException;
import org.cesecore.util.ui.RadioButton;
import org.cesecore.util.ui.UrlString;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfilesFactory;
import org.ejbca.core.model.approval.profile.ApprovalStep;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.util.HTMLTools;
import org.ejbca.util.mail.MailSender;

/**
 * JSF MBean backing the approval profile pages.
 *
 */
@ViewScoped // Local variables will live as long as actions on the backed page return "" or void.
@ManagedBean(name="approvalProfileMBean")
public class ApprovalProfileMBean extends BaseManagedBean implements Serializable {

    private static final long serialVersionUID = -3751383340600251434L;
    private static final InternalResources intres = InternalResources.getInstance();
    private static final Logger log = Logger.getLogger(ApprovalProfileMBean.class);

    /**
     * This enum field represents the types of data fields that can be added to an approval partition dynamically.
     *
     */
    private enum FieldType {
        CHECKBOX(intres.getLocalizedMessage("approval.profile.metadata.field.checkbox")),
        INTEGER(intres.getLocalizedMessage("approval.profile.metadata.field.integer")),
        LONG(intres.getLocalizedMessage("approval.profile.metadata.field.long")),
        RADIOBUTTON(intres.getLocalizedMessage("approval.profile.metadata.field.radio.button")),
        TEXT(intres.getLocalizedMessage("approval.profile.metadata.field.freetext")),
        EXTURL(intres.getLocalizedMessage("approval.profile.metadata.field.exturl"));

       private static List<SelectItem> selectItems;
       private static Map<String, FieldType> nameLookupMap;
       private final String label;

       static {
           selectItems = new ArrayList<>();
           nameLookupMap = new HashMap<>();
           for(FieldType action : FieldType.values()) {
               selectItems.add(new SelectItem(action, action.getLabel()));
               nameLookupMap.put(action.name(), action);
           }
       }

       private FieldType(final String label) {
           this.label = label;

       }

       public String getLabel() {
           return label;
       }

       public static List<SelectItem> asSelectItems() {
           return selectItems;
       }

       public static FieldType getFromName(String name) {
           return nameLookupMap.get(name);
       }

    }

    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private RoleSessionLocal roleSession;
    @EJB
    private RoleMemberSessionLocal roleMemberSession;

    @ManagedProperty(value = "#{approvalProfilesMBean}")
    private ApprovalProfilesMBean approvalProfilesMBean;
    
    public ApprovalProfileMBean() {
        super(AccessRulesConstants.ROLE_ADMINISTRATOR, StandardRules.APPROVALPROFILEVIEW.resource());
    }
    
    private int currentApprovalProfileId = -1;
    private ApprovalProfile currentApprovalProfile = null;

    private ListDataModel<ApprovalStepGuiObject> steps = null;

    /**
     * The type of metadata field to add to a partition, if any.
     */
    private Map<Integer, String> fieldToAdd = new HashMap<>();
    private Map<Integer, String> fieldLabel = new HashMap<>();

   public ApprovalProfilesMBean getApprovalProfilesMBean() {
        return approvalProfilesMBean;
    }

    public void setApprovalProfilesMBean(ApprovalProfilesMBean approvalProfilesMBean) {
        this.approvalProfilesMBean = approvalProfilesMBean;
    }
    /** @return the selected profile id from the list view or the one cached in this view (this will never change in the view) */
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

    public String getRequestExpirationPeriod() {
        final long millis = getApprovalProfile().getRequestExpirationPeriod();
        final SimpleTime time = SimpleTime.getInstance(millis);
        return time.toString(SimpleTime.TYPE_DAYS);
    }

    public void setRequestExpirationPeriod(String expirationPeriod) {
        final SimpleTime time = SimpleTime.getInstance(expirationPeriod);
        getApprovalProfile().setRequestExpirationPeriod(time.getLong());
    }

    public String getApprovalExpirationPeriod() {
        final long millis = getApprovalProfile().getApprovalExpirationPeriod();
        final SimpleTime time = SimpleTime.getInstance(millis);
        return time.toString(SimpleTime.TYPE_DAYS);
    }

    public void setApprovalExpirationPeriod(String expirationPeriod) {
        final SimpleTime time = SimpleTime.getInstance(expirationPeriod);
        getApprovalProfile().setApprovalExpirationPeriod(time.getLong());
    }

    public String getMaxExtensionTime() {
        final long millis = getApprovalProfile().getMaxExtensionTime();
        final SimpleTime time = SimpleTime.getInstance(millis);
        return time.toString(SimpleTime.TYPE_DAYS);
    }

    public boolean getAllowSelfEdit() {
        return getApprovalProfile().getAllowSelfEdit();
    }

    public void setAllowSelfEdit(boolean allowSelfEdit) {
       getApprovalProfile().setAllowSelfEdit(allowSelfEdit);
    }

    public void setMaxExtensionTime(final String maxExtensionTime) {
        final SimpleTime time = SimpleTime.getInstance(maxExtensionTime);
        getApprovalProfile().setMaxExtensionTime(time.getLong());
    }

    @SuppressWarnings("unchecked")
    public String save() {
        try {
            final ApprovalProfile approvalProfile = getApprovalProfile();
            List<Integer> stepOrder = new ArrayList<>();
            for (final ApprovalStepGuiObject approvalSequenceGuiObject : steps) {
                final int sequenceIdentifier = approvalSequenceGuiObject.getIdentifier();
                for (final ApprovalPartitionProfileGuiObject approvalPartitionGuiObject : approvalSequenceGuiObject.getPartitionGuiObjects()) {
                    approvalProfile.addPropertiesToPartition(sequenceIdentifier, approvalPartitionGuiObject.getPartitionId(),
                            (List<DynamicUiProperty<? extends Serializable>>) approvalPartitionGuiObject.getProfilePropertyList().getWrappedData());
                }
                stepOrder.add(sequenceIdentifier);
            }
            approvalProfileSession.changeApprovalProfile(getAdmin(), approvalProfile);
            addInfoMessage("APPROVALPROFILESAVED");
            return "done";
        } catch (AuthorizationDeniedException e) {
            addNonTranslatedErrorMessage("Not authorized to edit approval profiles.");
        }
        return "";
    }

    /**
     * Saves the current approval profile to a temporary variable managed by this bean. Should be
     * used to save the current state before the UI is refreshed. This prevents data entry in UI
     * controls to be discarded, causing poor user experience. To permanently save the approval
     * profile, see {@link #save}. In comparison, this method does not require any authorisation,
     * and will not throw any exceptions, nor show any error messages to the user.
     */
    @SuppressWarnings("unchecked")
    public void saveTemporary() {
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final List<Integer> stepOrder = new ArrayList<>();
        for (final ApprovalStepGuiObject step : steps) {
            for (final ApprovalPartitionProfileGuiObject partition : step.getPartitionGuiObjects()) {
                final int stepId = step.getIdentifier();
                final int partitionId = partition.getPartitionId();
                final Object guiObject = partition.getProfilePropertyList().getWrappedData();
                approvalProfile.addPropertiesToPartition(stepId, partitionId, (List<DynamicUiProperty<? extends Serializable>>) guiObject);
            }
            stepOrder.add(step.getIdentifier());
        }
        steps = createStepListFromProfile(approvalProfile);
    }

    public String cancel() {
        return "done";
    }

    /**
     * Adds the currently selected field to the partition specified by the parameter. The step that the partition resides in is retrieved from
     * the steps class member.
     *
     * @param partitionId the ID of the partition to add the field to
     * @return an empty string to keep the scope.
     */
    public String addField(int partitionId) {
        final Integer currentStep = steps.getRowData().getIdentifier();

        saveTemporary();

        ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        DynamicUiProperty<? extends Serializable> property;
        String fieldLabel = this.fieldLabel.get(partitionId);
        FieldType fieldType = FieldType.getFromName(fieldToAdd.get(partitionId));
        switch (fieldType) {
        case TEXT:
            property = new DynamicUiProperty<>(fieldLabel, new MultiLineString(""));
            break;
        case RADIOBUTTON:
            property = new DynamicUiProperty<>(fieldLabel, null, new ArrayList<RadioButton>());
            property.setType(RadioButton.class);
            break;
        case CHECKBOX:
            property = new DynamicUiProperty<>(fieldLabel, Boolean.FALSE);
            break;
        case INTEGER:
            property = new DynamicUiProperty<>(fieldLabel, Integer.valueOf(0));
            break;
        case LONG:
            property = new DynamicUiProperty<>(fieldLabel, Long.valueOf(0L));
            break;
        case EXTURL:
            property = new DynamicUiProperty<>(fieldLabel, new UrlString(""));
            break;
        default:
            return "";
        }

        if (updatedApprovalProfile.getStep(currentStep).getPartition(partitionId).getProperty(fieldLabel) != null) {
            addErrorMessage("APPROVAL_PROFILE_FIELD_EXISTS");
        } else {
            updatedApprovalProfile.addPropertyToPartition(currentStep, partitionId, property);
            steps = createStepListFromProfile(updatedApprovalProfile);
            this.fieldLabel = new HashMap<>();
            fieldToAdd = new HashMap<>();
        }

        return "";
    }

    /**
     * A special method for adding rows to radio button arrays. The ID of the partition is required, but the step identity and the radio button
     * field identity can be derived from class members.
     *
     * @param partitionId the ID of the partition that the radio button resides in
     * @param label the label for the new row
     * @return an empty string to keep the scope.
     */
    public String addRowToRadioButton(int partitionId, String label) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        final ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        final List<ApprovalPartitionProfileGuiObject> guiPartitions = steps.getRowData().getPartitionGuiObjects();
        for (ApprovalPartitionProfileGuiObject approvalPartitionProfileGuiObject : guiPartitions) {
            //find the right partition
            if (approvalPartitionProfileGuiObject.getPartitionId() == partitionId) {
                @SuppressWarnings("unchecked")
                DynamicUiProperty<RadioButton> radioButtonProperty = (DynamicUiProperty<RadioButton>) approvalPartitionProfileGuiObject
                        .getProfilePropertyList().getRowData();
                Collection<RadioButton> possibleValues = radioButtonProperty.getPossibleValues();
                RadioButton newRadio = new RadioButton(label);
                if(possibleValues.contains(newRadio)) {
                    addErrorMessage("APPROVAL_PROFILE_FIELD_RADIO_EXISTS");
                    return "";
                }
                if (possibleValues.size() == 0) {
                    radioButtonProperty.setDefaultValue(newRadio);
                }
                possibleValues.add(newRadio);
                radioButtonProperty.setPossibleValues(possibleValues);
                saveTemporary();
                updatedApprovalProfile.addPropertyToPartition(currentStep, partitionId, radioButtonProperty);
                steps = createStepListFromProfile(updatedApprovalProfile);
                break;
            }
        }
        return "";
    }

    /**
     * Similar to the above, the below method removes a row from a radio button array.
     *
     * @param partitionId the ID of the partition that the radio button resides in
     * @param encodedRadioButton the encoded radio button
     * @return an empty string to keep the scope.
     */
    public String removeRowFromRadioButton(int partitionId, String encodedRadioButton) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        final ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        final RadioButton radioButton = DynamicUiProperty.getAsObject(encodedRadioButton, RadioButton.class);
        final List<ApprovalPartitionProfileGuiObject> guiPartitions = steps.getRowData().getPartitionGuiObjects();
        for(ApprovalPartitionProfileGuiObject approvalPartitionProfileGuiObject : guiPartitions) {
            //find the right partition
            if(approvalPartitionProfileGuiObject.getPartitionId() == partitionId) {
                @SuppressWarnings("unchecked")
                DynamicUiProperty<RadioButton> radioButtonProperty = (DynamicUiProperty<RadioButton>) approvalPartitionProfileGuiObject.getProfilePropertyList().getRowData();
                List<RadioButton> oldValues = new ArrayList<>(radioButtonProperty.getPossibleValues());
                List<RadioButton> prunedValues = new ArrayList<>();
                for(RadioButton dynamicRadioButton : oldValues) {
                    if(!dynamicRadioButton.equals(radioButton)) {
                        prunedValues.add(dynamicRadioButton);
                    }
                }
                if(radioButtonProperty.getDefaultValue().equals(radioButton) && !prunedValues.isEmpty()) {
                    radioButtonProperty.setDefaultValue(prunedValues.get(0));
                }
                radioButtonProperty.setPossibleValues(prunedValues);
                saveTemporary();
                updatedApprovalProfile.addPropertyToPartition(currentStep, partitionId, radioButtonProperty);
                steps = createStepListFromProfile(updatedApprovalProfile);
                break;
            }
        }
        return "";
    }

    public String removeField(int partitionId, String propertyName) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        ApprovalProfile updatedApprovalProfile = getApprovalProfile();
        updatedApprovalProfile.removePropertyFromPartition(currentStep, partitionId, propertyName);
        steps = createStepListFromProfile(updatedApprovalProfile);
        return "";
    }

    public void addStep() {
        saveTemporary();
        getApprovalProfile().addStepLast();
        steps = null;
    }

    public void moveStepDown() {
        final Integer currentStep = steps.getRowData().getIdentifier();
        final Integer nextStep = steps.getRowData().getNextStep();
        saveTemporary();
        getApprovalProfile().switchStepOrder(currentStep, nextStep);
        steps = null;
    }

    public void moveStepUp() {
        final Integer currentStep = steps.getRowData().getIdentifier();
        final Integer previousStep = steps.getRowData().getPreviousStep();
        saveTemporary();
        getApprovalProfile().switchStepOrder(previousStep, currentStep);
        steps = null;
    }

    public void deleteStep() {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        getApprovalProfile().deleteStep(currentStep);
        steps = null;
    }

    public void addPartition() {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        getApprovalProfile().addPartition(currentStep);
        steps = null;
    }

    public void deletePartition(int partitionId) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        getApprovalProfile().deletePartition(currentStep, partitionId);
        steps = null;
    }

    public boolean isPropertyPredefined(int partitionId, String propertyName) {
        ApprovalProfile approvalProfile = getApprovalProfile();
        return approvalProfile.isPropertyPredefined(steps.getRowData().getIdentifier(), partitionId, propertyName);
    }

    public void selectUpdate() {
        // NOOP: Only for page reload
    }

    public String getCurrentApprovalProfileTypeName() {
        return getApprovalProfile().getApprovalProfileTypeIdentifier();
    }

    public void setCurrentApprovalProfileTypeName(String typeName) {
        // Re-instantiate approval profile if we've changed type
        if (!getApprovalProfile().getApprovalProfileTypeIdentifier().equals(typeName)) {
            final ApprovalProfile newApprovalProfile = ApprovalProfilesFactory.INSTANCE.getArcheType(typeName);
            newApprovalProfile.setProfileId(getSelectedApprovalProfileId());
            newApprovalProfile.setProfileName(getSelectedApprovalProfileName());
            currentApprovalProfile = newApprovalProfile;
            steps = null;
        }
    }

    public List<SelectItem> getApprovalProfileTypesAvailable() {
        final List<SelectItem> ret = new ArrayList<>();
        for (final ApprovalProfile type : ApprovalProfilesFactory.INSTANCE.getAllImplementations()) {
            ret.add(new SelectItem(type.getApprovalProfileTypeIdentifier(), type.getApprovalProfileLabel()));
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
        int ordinal = 1;
        //Use the internal ordering for sequences, if one is predefined
        ApprovalStep step = approvalProfile.getFirstStep();
        Map<Integer, List<DynamicUiProperty<? extends Serializable>>> partitionProperties = getPartitionProperties(step);
        steps.add(new ApprovalStepGuiObject(step, approvalProfile.getApprovalProfileTypeIdentifier(), ordinal, partitionProperties));
        while (step.getNextStep() != null) {
            step = approvalProfile.getStep(step.getNextStep());
            partitionProperties = getPartitionProperties(step);
            steps.add(new ApprovalStepGuiObject(step, approvalProfile.getApprovalProfileTypeIdentifier(), ++ordinal, partitionProperties));
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
                    final List<Role> allAuthorizedRoles = roleSession.getAuthorizedRoles(getAdmin());
                    final List<RoleInformation> roleRepresentations = new ArrayList<>();
                    for (final Role role : allAuthorizedRoles) {
                        if (AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVEENDENTITY)
                                || AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVECAACTION)) {
                            try {
                                final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(getAdmin(), role.getRoleId());
                                roleRepresentations.add(RoleInformation.fromRoleMembers(role.getRoleId(), role.getNameSpace(), role.getRoleName(), roleMembers));
                            } catch (AuthorizationDeniedException e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Not authorized to members of authorized role '"+role.getRoleNameFull()+"' (?):" + e.getMessage());
                                }
                            }
                        }
                    }
                    if(!roleRepresentations.contains(propertyClone.getDefaultValue())) {
                        //Add the default, because it makes no sense why it wouldn't be there. Also, it may be a placeholder for something else.
                        roleRepresentations.add(0, (RoleInformation) propertyClone.getDefaultValue());
                    }
                    propertyClone.setPossibleValues(roleRepresentations);
                    updateEncodedValues(propertyClone, property);
                    break;
                case ROLES_VIEW:
                    final List<Role> allAuthorizedRolesForViewing = roleSession.getAuthorizedRoles(getAdmin());
                    final List<RoleInformation> viewingRoleRepresentations = new ArrayList<>();
                    for (final Role role : allAuthorizedRolesForViewing) {
                        if (AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_VIEWAPPROVALS)
                                || AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVEENDENTITY)
                                || AccessRulesHelper.hasAccessToResource(role.getAccessRules(), AccessRulesConstants.REGULAR_APPROVECAACTION)) {
                            try {
                                final List<RoleMember> roleMembers = roleMemberSession.getRoleMembersByRoleId(getAdmin(), role.getRoleId());
                                viewingRoleRepresentations.add(RoleInformation.fromRoleMembers(role.getRoleId(), role.getNameSpace(), role.getRoleName(), roleMembers));
                            } catch (AuthorizationDeniedException e) {
                                if (log.isDebugEnabled()) {
                                    log.debug("Not authorized to members of authorized role '"+role.getRoleNameFull()+"' (?):" + e.getMessage());
                                }
                            }
                        }
                    }
                    if(!viewingRoleRepresentations.contains(propertyClone.getDefaultValue())) {
                        viewingRoleRepresentations.add(0, (RoleInformation) propertyClone.getDefaultValue());
                    }
                    propertyClone.setPossibleValues(viewingRoleRepresentations);
                    updateEncodedValues(propertyClone, property);
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

    /**
     * @return true if it's possible to add fields to the partitions of this profile
     */
    public boolean arePartitionsFixed() {
        return ApprovalProfilesFactory.INSTANCE.getArcheType(getCurrentApprovalProfileTypeName()).arePartitionsFixed();
    }


    public List<SelectItem> getFieldsAvailable() {
        return FieldType.asSelectItems();
    }

    public Map<Integer, String> getFieldToAdd() {
        return fieldToAdd;
    }


    public Map<Integer, String> getFieldLabel() {
        return fieldLabel;
    }


    // Notifications

    public boolean isNotificationEnabled(final int partitionIdentifier) {
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(steps.getRowData().getIdentifier());
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        return approvalProfile.isNotificationEnabled(approvalPartition);
    }
    
    /** Returns true if any form of notifications are enabled, and e-mail is NOT configured in the application server. */
    public boolean isNotificationsEnabledWithoutEmail(final int partitionIdentifier) {
        return (isNotificationEnabled(partitionIdentifier) || isUserNotificationEnabled(partitionIdentifier)) && !MailSender.isMailConfigured();
    }

    public void addNotification(final int partitionIdentifier) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(currentStep);
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        // Configure some nice defaults
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final HttpServletRequest httpServletRequest = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest());
        // Escape value taken from the request, just to be sure there can be no XSS
        final String hostnameFromRequest = HTMLTools.htmlescape(httpServletRequest.getServerName());
        final String baseUrl = globalConfiguration.getBaseUrl(HTMLTools.htmlescape(httpServletRequest.getScheme()), hostnameFromRequest, httpServletRequest.getServerPort());
        final String defaultSubject = "[AR-${approvalRequest.ID}-${approvalRequest.STEP_ID}-${approvalRequest.PARTITION_ID}] " +
                "Approval Request to ${approvalRequest.TYPE} is now in state ${approvalRequest.WORKFLOWSTATE}";
        final String defaultBody = "Approval Request to ${approvalRequest.TYPE} from ${approvalRequest.REQUESTOR} is now in state ${approvalRequest.WORKFLOWSTATE}.\n" +
                "\n" +
                "Direct link to the request: " + baseUrl + "ra/managerequest.xhtml?id=${approvalRequest.ID}";
        approvalProfile.addNotificationProperties(approvalPartition, "approval-admin-group@example.org supervisor@example.org", "no-reply@"+hostnameFromRequest, defaultSubject, defaultBody);
        steps = null;
    }

    public void removeNotification(final int partitionIdentifier) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(currentStep);
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        approvalProfile.removeNotificationProperties(approvalPartition);
        steps = null;
    }

    // User Notification

    public boolean isUserNotificationEnabled(final int partitionIdentifier) {
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(steps.getRowData().getIdentifier());
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        return approvalProfile.isUserNotificationEnabled(approvalPartition);
    }

    public void addUserNotification(final int partitionIdentifier) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(currentStep);
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        // Configure some nice defaults
        final GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        final HttpServletRequest httpServletRequest = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest());
        // Escape value taken from the request, just to be sure there can be no XSS
        final String hostnameFromRequest = HTMLTools.htmlescape(httpServletRequest.getServerName());
        final String baseUrl = globalConfiguration.getBaseUrl(HTMLTools.htmlescape(httpServletRequest.getScheme()), hostnameFromRequest, httpServletRequest.getServerPort());
        final String defaultSubject = "[AR-${approvalRequest.ID}-${approvalRequest.STEP_ID}-${approvalRequest.PARTITION_ID}] " +
                "Approval Request to ${approvalRequest.TYPE} is now in state ${approvalRequest.WORKFLOWSTATE}";
        final String defaultBody = "Approval Request to ${approvalRequest.TYPE} from ${approvalRequest.REQUESTOR} is now in state ${approvalRequest.WORKFLOWSTATE}.\n" +
                "\n" +
                "Direct link to view request status: " + baseUrl + "ra/enrollwithrequestid.xhtml?requestId=${approvalRequest.ID}";
        approvalProfile.addUserNotificationProperties(approvalPartition, "no-reply@"+hostnameFromRequest, defaultSubject, defaultBody);
        steps = null;
    }

    public void removeUserNotification(final int partitionIdentifier) {
        final Integer currentStep = steps.getRowData().getIdentifier();
        saveTemporary();
        final ApprovalProfile approvalProfile = getApprovalProfile();
        final ApprovalStep approvalStep = approvalProfile.getStep(currentStep);
        final ApprovalPartition approvalPartition = approvalStep.getPartition(partitionIdentifier);
        approvalProfile.removeUserNotificationProperties(approvalPartition);
        steps = null;
    }

    /**
     * Updates the encoded values of propertyClone if
     * there has been a change in the role members of the
     * any of the roles which were selected in the list box
     * before the change.
     * Uses property identifier as a base for comparison.
     *
     * @param propertyClone updated property
     * @param property current property
     */
    private void updateEncodedValues(
            final DynamicUiProperty<? extends Serializable> propertyClone,
            final DynamicUiProperty<? extends Serializable> property) {

        List<Integer> currentIds = new ArrayList<>();

        for (final String value : property.getEncodedValues()) {
            RoleInformation roleInfo = DynamicUiProperty.getAsObject(value, RoleInformation.class);
            currentIds.add(roleInfo.getIdentifier());
        }

        List<String> finalListOfEncodedValues = new ArrayList<>();

        for (final Serializable value : propertyClone.getPossibleValues()) {
            RoleInformation roleInformation = (RoleInformation) value;

            if (currentIds.contains(roleInformation.getIdentifier())) {
                finalListOfEncodedValues.add(property.getAsEncodedValue(property.getType().cast(value)));
            }
        }

        // Here we update the propertyClone set of encoded values.
        try {
            propertyClone.setEncodedValues(finalListOfEncodedValues);
        } catch (PropertyValidationException e) {
            log.error("Invalid propery value while setting the encoded values for property clone!" + e);
        }
    }

}
