/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.approval.profile;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.profiles.ProfileBase;
import org.cesecore.roles.RoleInformation;
import org.cesecore.util.ProfileID;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.MultiLineString;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataVO;

/**
 *
 * Implementation of the ProfileBase class, common functionality for all approval type profiles.
 *
 * @version $Id$
 *
 */
public abstract class ApprovalProfileBase extends ProfileBase implements ApprovalProfile, Cloneable {

    private static final Logger log = Logger.getLogger(ApprovalProfileBase.class);

    private static final long serialVersionUID = 1L;

    private static final int NO_SEQUENCES = -1;

    private static final String STEPS_KEY = "steps";
    private static final String FIRST_STEP_KEY = "firstStep";

    /**
     * The sequences of this approval profile, as mapped by their sequences
     */
    private transient Map<Integer, ApprovalStep> steps = new HashMap<>();



    public ApprovalProfileBase() {
        //Public constructor needed deserialization
        super();
    }

    public ApprovalProfileBase(final String name) {
        super(name);
        data.put(PROPERTY_REQUEST_EXPIRATION_PERIOD, EjbcaConfiguration.getApprovalDefaultRequestValidity());
        data.put(PROPERTY_APPROVAL_EXPIRATION_PERIOD, EjbcaConfiguration.getApprovalDefaultApprovalValidity());
        data.put(PROPERTY_MAX_EXTENSION_TIME, EjbcaConfiguration.getApprovalDefaultMaxExtensionTime());

    }

    @Override
    public String getProfileType() {
        return TYPE_NAME;
    }

    @Override
    public long getRequestExpirationPeriod() {
        final Object value = data.get(PROPERTY_REQUEST_EXPIRATION_PERIOD);
        if(value == null) {
            return EjbcaConfiguration.getApprovalDefaultRequestValidity();
        }
        return (long) value;
    }

    @Override
    public void setRequestExpirationPeriod(final long expirationPeriod) {
        data.put(PROPERTY_REQUEST_EXPIRATION_PERIOD, expirationPeriod);
    }

    @Override
    public long getApprovalExpirationPeriod() {
        final Object value = data.get(PROPERTY_APPROVAL_EXPIRATION_PERIOD);
        if(value == null) {
            return EjbcaConfiguration.getApprovalDefaultApprovalValidity();
        }
        return (long) value;
    }

    @Override
    public void setApprovalExpirationPeriod(final long expirationPeriod) {
        data.put(PROPERTY_APPROVAL_EXPIRATION_PERIOD, expirationPeriod);
    }

    @Override
    public long getMaxExtensionTime() {
        final Object value = data.get(PROPERTY_MAX_EXTENSION_TIME);
        if(value == null) {
            return EjbcaConfiguration.getApprovalDefaultMaxExtensionTime();
        }
        return (long) value;
    }

    @Override
    public void setMaxExtensionTime(final long maxExtensionTime) {
        data.put(PROPERTY_MAX_EXTENSION_TIME, maxExtensionTime);
    }

    @Override
    public boolean getAllowSelfEdit() {
        final Object value = data.get(PROPERTY_ALLOW_SELF_EDIT);
        if (value == null) {
            return false;
        }
        return (boolean) value;
    }

    @Override
    public void setAllowSelfEdit(boolean allowSelfEdit) {
        data.put(PROPERTY_ALLOW_SELF_EDIT, allowSelfEdit);
    }

    @Override
    public ApprovalProfile clone() {
        getType();
        ApprovalProfile clone;
        try {
            clone = (ApprovalProfile) getType().newInstance();
        } catch (InstantiationException | IllegalAccessException e) {
            throw new IllegalStateException("Could not instansiate class of type " + getType().getCanonicalName());
        }
        clone.setProfileName(getProfileName());
        clone.setProfileId(getProfileId());

        // We need to make a deep copy of the hashmap here
        LinkedHashMap<Object, Object> dataMap = new LinkedHashMap<>(data.size());
        for (final Entry<Object, Object> entry : data.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof ArrayList<?>) {
                // We need to make a clone of this object, but the stored immutables can still be referenced
                value = ((ArrayList<?>) value).clone();
            }
            dataMap.put(entry.getKey(), value);
        }
        clone.setDataMap(dataMap);
        Map<Integer, ApprovalStep> stepClone = new HashMap<>();
        for (ApprovalStep approvalStep : getSteps().values()) {
            stepClone.put(approvalStep.getStepIdentifier(), new ApprovalStep(approvalStep));
        }
        clone.setSteps(stepClone);
        clone.setFirstStep(getFirstStepId());
        return clone;
    }

    @Override
    public int compareTo(final ApprovalProfile approvalProfile) {
        if (approvalProfile == null) { return 1; }
        final String name = getProfileName();
        if (name == null) { return -1; }
        return name.compareToIgnoreCase(approvalProfile.getProfileName());
    }

    @Override
    public void setSteps(Map<Integer, ApprovalStep> stepsToBeEncoded) {
        this.steps = null;
        data.put(STEPS_KEY, encodeSteps(stepsToBeEncoded.values()));
    }

    @Override
    public ApprovalPartition addPartition(int stepIdentifier) {
        ApprovalPartition result = getStep(stepIdentifier).addPartition();
        //Pass a deep copy
        result = addConstantProperties(new ApprovalPartition(result));
        getStep(stepIdentifier).addPartition(result);
        saveTransientObjects();
        return result;
    }

    /**
     * Add whatever constant properties specified by the implementation.
     *
     * @param approvalPartition an approval partition
     * @return a copy of the partition with the constant values.
     */
    protected abstract ApprovalPartition addConstantProperties(ApprovalPartition approvalPartition);

    @Override
    public boolean isNotificationEnabled(final ApprovalPartition approvalPartition) {
        return approvalPartition!=null && approvalPartition.getProperty(ApprovalProfile.PROPERTY_NOTIFICATION_EMAIL_RECIPIENT) != null;
    }

    @Override
    public ApprovalPartition addNotificationProperties(final ApprovalPartition approvalPartition, String recipient, String sender, String subject, String body) {
        // TODO: It would be nice with the email-address type
        approvalPartition.addProperty(new DynamicUiProperty<>(PROPERTY_NOTIFICATION_EMAIL_RECIPIENT, recipient));
        approvalPartition.addProperty(new DynamicUiProperty<>(PROPERTY_NOTIFICATION_EMAIL_SENDER, sender));
        approvalPartition.addProperty(new DynamicUiProperty<>(PROPERTY_NOTIFICATION_EMAIL_MESSAGE_SUBJECT, subject));
        approvalPartition.addProperty(new DynamicUiProperty<>(PROPERTY_NOTIFICATION_EMAIL_MESSAGE_BODY, new MultiLineString(body)));
        return approvalPartition;
    }

    @Override
    public boolean isUserNotificationEnabled(final ApprovalPartition approvalPartition) {
        return approvalPartition!=null && approvalPartition.getProperty(ApprovalProfile.PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_SUBJECT) != null;
    }

    @Override
    public ApprovalPartition addUserNotificationProperties(final ApprovalPartition approvalPartition, String sender, String subject, String body) {
        // TODO: It would be nice with the email-address type
        approvalPartition.addProperty(new DynamicUiProperty<>(PROPERTY_USER_NOTIFICATION_EMAIL_SENDER, sender));
        approvalPartition.addProperty(new DynamicUiProperty<>(PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_SUBJECT, subject));
        approvalPartition.addProperty(new DynamicUiProperty<>(PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_BODY, new MultiLineString(body)));
        return approvalPartition;
    }

    @Override
    public final Set<String> getHiddenProperties() {
        Set<String> result = new HashSet<>(Arrays.asList(PROPERTY_NOTIFICATION_EMAIL_RECIPIENT, PROPERTY_NOTIFICATION_EMAIL_SENDER,
                PROPERTY_NOTIFICATION_EMAIL_MESSAGE_SUBJECT, PROPERTY_NOTIFICATION_EMAIL_MESSAGE_BODY,
                PROPERTY_USER_NOTIFICATION_EMAIL_SENDER,
                PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_SUBJECT, PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_BODY
                ));
        result.addAll(Arrays.asList(getImplementationHiddenProperties()));
        return result;
    }

    /**
     * Allows implementations to specify their own list of hidden properties
     *
     * @return a list of property keys.
     */
    protected abstract String[] getImplementationHiddenProperties();

    @Override
    public ApprovalPartition removeNotificationProperties(final ApprovalPartition approvalPartition) {
        approvalPartition.removeProperty(PROPERTY_NOTIFICATION_EMAIL_RECIPIENT);
        approvalPartition.removeProperty(PROPERTY_NOTIFICATION_EMAIL_SENDER);
        approvalPartition.removeProperty(PROPERTY_NOTIFICATION_EMAIL_MESSAGE_SUBJECT);
        approvalPartition.removeProperty(PROPERTY_NOTIFICATION_EMAIL_MESSAGE_BODY);
        return approvalPartition;
    }

    @Override
    public ApprovalPartition removeUserNotificationProperties(final ApprovalPartition approvalPartition) {
        approvalPartition.removeProperty(PROPERTY_USER_NOTIFICATION_EMAIL_SENDER);
        approvalPartition.removeProperty(PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_SUBJECT);
        approvalPartition.removeProperty(PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_BODY);
        return approvalPartition;
    }

    @Override
    public void addPropertyToPartition(int stepId, int partitionId, DynamicUiProperty<? extends Serializable> property) throws NoSuchApprovalStepException {
        ApprovalStep step = getSteps().get(stepId);
        if (step == null) {
            throw new NoSuchApprovalStepException("Approval step with ID: " + stepId + " not found.");
        }
        step.setPropertyToPartition(partitionId, property);
        saveTransientObjects();
    }

    @Override
    public void removePropertyFromPartition(final int stepId, final int partitionId, final String propertyName) {
        ApprovalStep step = getSteps().get(stepId);
        if (step == null) {
            throw new NoSuchApprovalStepException("Approval step with ID: " + stepId + " not found.");
        }
        step.removePropertyFromPartition(partitionId, propertyName);
        saveTransientObjects();
    }

    @Override
    public void addPropertiesToPartition(Integer stepId, int partitionId, Collection<DynamicUiProperty<? extends Serializable>> properties)
            throws NoSuchApprovalStepException {
        for (final DynamicUiProperty<? extends Serializable> property : properties) {
            addPropertyToPartition(stepId, partitionId, property);
        }
        saveTransientObjects();
    }

    @Override
    public Map<Integer, ApprovalStep> getSteps() {
        if(steps == null || steps.isEmpty()) {
            loadStepsFromMap();
        }
        return steps;
    }

    @Override
    public void addStep(ApprovalStep step) throws NonModifiableApprovalProfileException {
        if (isStepSizeFixed()) {
            //No operation, and method should not have been called without a prior check.
            throw new NonModifiableApprovalProfileException(
                    "Attempted adding a step to an approval profile implementation which does not support it.");
        } else {
            getSteps().put(step.getStepIdentifier(), step);
            if (log.isDebugEnabled() && !StringUtils.isEmpty(getProfileName())) {
                //This method may be called from the factory when creating archetypes, so don't debug log that case.
                log.debug("Added step with ID " + step.getStepIdentifier() + " to profile " + getProfileName());
            }
            //All steps must have one partition minimum. This will also add standard fields from the underlying profile implementation
            if (step.getPartitions().size() == 0) {
                addPartition(step.getStepIdentifier());
            }
        }
        saveTransientObjects();
    }

    @Override
    public ApprovalStep addStepFirst() {
        int identifier;
        do {
            identifier = ProfileID.getRandomIdNumber();
        } while(getSteps().containsKey(identifier));
        ApprovalStep newStep = new ApprovalStep(identifier);
        addStep(newStep);
        if (getSteps().size() == 1) {
            setFirstStep(newStep.getStepIdentifier());
            return newStep;
        }
        //Set the order.
        ApprovalStep previousFirstStep = steps.get(getFirstStepId());
        setFirstStep(newStep.getStepIdentifier());
        newStep.setNextStep(previousFirstStep.getStepIdentifier());
        previousFirstStep.setPreviousStep(newStep.getStepIdentifier());
        saveTransientObjects();
        return newStep;
    }

    @Override
    public ApprovalStep addStepLast() {
        int identifier;
        do {
            identifier = ProfileID.getRandomIdNumber();
        } while(getSteps().containsKey(identifier));
        ApprovalStep newStep = new ApprovalStep(identifier);
        addStep(newStep);
        //Find the last step and set this one last
        ApprovalStep step = steps.get(getFirstStepId());
        while(step.getNextStep() != null) {
            step = steps.get(step.getNextStep());
        }
        step.setNextStep(newStep.getStepIdentifier());
        newStep.setPreviousStep(step.getStepIdentifier());
        saveTransientObjects();
        return newStep;
    }

    @Override
    public void deleteStep(final int approvalStepIdentifier) {
        if(isStepSizeFixed()) {
            throw new NonModifiableApprovalProfileException("Cannot delete an approval step in a profile with fixed step size");
        }
        ApprovalStep stepToDelete = getStep(approvalStepIdentifier);
        ApprovalStep previousStep = getStep(stepToDelete.getPreviousStep());
        ApprovalStep nextStep = getStep(stepToDelete.getNextStep());
        if(previousStep == null) {
            // Handle deleting the last sequence, in which case there is no next step. In this case we can't set "first step" here,
            // but in the end of this method if there are no steps we initialize, which will recreate the first step in a default manner.
            if (nextStep != null) {
                //This step was first, so set the next one first
                setFirstStep(nextStep.getStepIdentifier());
            }
        }
        if(nextStep == null && previousStep != null) {
            //This was the last step, so make sure the previous step knows it's now last
            previousStep.setNextStep(null);
        }
        if(nextStep != null && previousStep != null) {
            previousStep.setNextStep(nextStep.getStepIdentifier());
            nextStep.setPreviousStep(previousStep.getStepIdentifier());
        }
        getSteps().remove(approvalStepIdentifier);
        if (getSteps().isEmpty()) {
            // We have removed all steps, re-initialize to default
            initialize();
        }
        saveTransientObjects();
    }

    @Override
    public void deletePartition(final int approvalStepIdentifier, final int partitionIdentifier) {
        if(isStepSizeFixed()) {
            throw new NonModifiableApprovalProfileException("Cannot delete an approval step in a profile with fixed step size");
        }
        ApprovalStep approvalStep = getStep(approvalStepIdentifier);
        approvalStep.removePartition(partitionIdentifier);
        saveTransientObjects();
    }


    @Override
    public ApprovalStep getStep(Integer identifier) {
        if(identifier == null) {
            return null;
        }
        return getSteps().get(identifier);

    }

    private int getFirstStepId() {
        Object value = data.get(FIRST_STEP_KEY);
        if(value == null) {
        	return NO_SEQUENCES;
        }
        return (int) value;

    }

    @Override
    public ApprovalStep getFirstStep() {
        return getSteps().get(getFirstStepId());
    }

    @Override
    public void setFirstStep(int firstStep) {
        data.put(FIRST_STEP_KEY, firstStep);
    }

    @Override
    protected void saveTransientObjects() {
        //Here we return all sequences to be persisted.
        Map<Object, Object> transientObjects = new HashMap<>();
        if (getSteps() != null) {
            transientObjects.put(STEPS_KEY, encodeSteps(getSteps().values()));
        }
        transientObjects.put(FIRST_STEP_KEY, getFirstStepId());
        data.putAll(transientObjects);
    }

    @Override
    protected void loadTransientObjects() {
        loadStepsFromMap();
    }

    private  List<String> encodeSteps(Collection<ApprovalStep> stepsToEncode) {
        List<String> stepsToSave =  new ArrayList<>();
        for(ApprovalStep step : stepsToEncode) {
            stepsToSave.add(step.getEncoded());
        }
        return stepsToSave;
    }

    /**
     * Retrieves the transient steps object from the underlying datamap.
     */
    private void loadStepsFromMap() {
        @SuppressWarnings("unchecked")
        ArrayList<String> loadedSteps = (ArrayList<String>) data.get(STEPS_KEY);
        steps = new HashMap<>();
        if (loadedSteps != null && loadedSteps.size() > 0) {
            for(String encodedStep : loadedSteps) {
                ApprovalStep step = new ApprovalStep(encodedStep);
                steps.put(step.getStepIdentifier(), step);
            }
        }
    }

    @Override
    public boolean isApprovalAuthorized(Collection<Approval> approvalsPerformed, Approval approval) throws AuthenticationFailedException {
        ApprovalStep previousStep = getFirstStep();
        ApprovalStep relevantStep = getStep(approval.getStepId());
        while(previousStep != null) {
            if(!previousStep.equals(relevantStep)) {
                if(!isStepSatisfied(previousStep, approvalsPerformed)) {
                    return false;
                } else {
                    previousStep = getStep(previousStep.getNextStep());
                }
            } else {
              //Verify that all previous steps are good
                ApprovalPartition approvalPartition = relevantStep.getPartition(approval.getPartitionId());
                if(approvalPartition == null) {
                    return false;
                }
                return canApprovePartition(approval.getAdmin(), approvalPartition);

            }
        }
        return false;
    }

    /**
     * @return true if the list of approvals validates the given step
     * @throws AuthenticationFailedException if the authentication token in the approval doesn't check out
     */
    protected boolean isStepSatisfied(final ApprovalStep approvalStep, final Collection<Approval> approvalsPerformed)
            throws AuthenticationFailedException {
        PARTITION_LOOP: for (ApprovalPartition partition : approvalStep.getPartitions().values()) {
            for (Approval approval : approvalsPerformed) {
                if (approval.getStepId() == approvalStep.getStepIdentifier() && partition.getPartitionIdentifier() == approval.getPartitionId()) {
                    //While we already have checked the credentials of all partitions, doing so is cheap and a good double check.
                    if (canApprovePartition(approval.getAdmin(), partition)) {
                        continue PARTITION_LOOP;
                    }
                }
            }
            //If we've gotten to the bottom of a partition without satisfying it's conditions, we're done
            return false;
        }
        //If we've made it through all the partitions
        return true;
    }

    @Override
    public int getNumberOfApprovalsRequired(final int stepIdentifier, final int partitionIdentifier) {
    	if (log.isTraceEnabled()) {
    	    log.trace(">getNumberOfApprovalsRequired: "+stepIdentifier+", "+partitionIdentifier);
    	}
        final DynamicUiProperty<? extends Serializable> numberOfRequiredApprovals = getStep(stepIdentifier).getPartition(partitionIdentifier).getProperty(PROPERTY_NUMBER_OF_REQUIRED_APPROVALS);
        if (numberOfRequiredApprovals==null) {
            if (log.isTraceEnabled()) {
                log.trace("<getNumberOfApprovalsRequired: 1");
            }
            return 1;   // Default to 1 required approval per partition
        }
        final int ret = (Integer) numberOfRequiredApprovals.getValue();
        if (log.isTraceEnabled()) {
            log.trace("<getNumberOfApprovalsRequired: "+ret);
        }
        return ret;
    }

    @Override
    public int getRemainingApprovalsInPartition(final Collection<Approval> approvalsPerformed, final int stepIdentifier, final int partitionIdentifier) {
        int partitionApprovalsRequired = getNumberOfApprovalsRequired(stepIdentifier, partitionIdentifier);
        int partitionApprovalsPerformed = 0;
        for (Approval approval : approvalsPerformed) {
            if (!approval.isApproved()) {
                return -1;
            }
            if (approval.getStepId() == stepIdentifier && approval.getPartitionId() == partitionIdentifier) {
                partitionApprovalsPerformed++;
            }
        }
        // Don't return a negative number, could happen if the partition has been approved multiple times
        int diff = partitionApprovalsRequired - partitionApprovalsPerformed;
        return diff < 0 ? 0 : diff;
    }

    @Override
    public int getNumberOfSteps() {
        return getSteps().size();
    }

    @Override
    public boolean isPropertyPredefined(int stepIdentifier, int partitionIdentifier, String propertyName) {
        return Arrays.asList( PROPERTY_NOTIFICATION_EMAIL_RECIPIENT, PROPERTY_NOTIFICATION_EMAIL_SENDER,
                PROPERTY_NOTIFICATION_EMAIL_MESSAGE_SUBJECT, PROPERTY_NOTIFICATION_EMAIL_MESSAGE_BODY,
                PROPERTY_USER_NOTIFICATION_EMAIL_SENDER,
                PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_SUBJECT, PROPERTY_USER_NOTIFICATION_EMAIL_MESSAGE_BODY
                ).contains(propertyName);
    }

    @Override
    public void switchStepOrder(Integer firstStepIdentifier, Integer secondStepIdentifier) {
        if(firstStepIdentifier == null || secondStepIdentifier == null) {
            return;
        }
        ApprovalStep firstStep = getStep(firstStepIdentifier);
        ApprovalStep secondStep = getStep(secondStepIdentifier);
        Integer firstStepPrevious = firstStep.getPreviousStep();
        Integer secondStepNext = secondStep.getNextStep();
        if(firstStepPrevious != null) {
            ApprovalStep previousStep = getStep(firstStepPrevious);
            previousStep.setNextStep(secondStepIdentifier);
        }
        secondStep.setPreviousStep(firstStepPrevious);
        secondStep.setNextStep(firstStepIdentifier);
        if(secondStepNext != null) {
            ApprovalStep nextStep = getStep(secondStepNext);
            nextStep.setPreviousStep(firstStepIdentifier);
        }
        firstStep.setPreviousStep(secondStepIdentifier);
        firstStep.setNextStep(secondStepNext);
        if(getFirstStepId() == firstStepIdentifier) {
            setFirstStep(secondStepIdentifier);
        }
        saveTransientObjects();
    }

    @Override
    public boolean updateCAIds(final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        final Map<Integer,ApprovalStep> steps = getSteps();
        for (final ApprovalStep step : new ArrayList<>(steps.values())) {
            final Map<Integer,ApprovalPartition> partitions = step.getPartitions();
            for (final ApprovalPartition partition : new ArrayList<>(partitions.values())) {
                // Check if the role user aspect datas need updating
                final DynamicUiProperty<? extends Serializable> prop = partition.getProperty(PartitionedApprovalProfile.PROPERTY_ROLES_WITH_APPROVAL_RIGHTS);
                if (prop != null) {
                    @SuppressWarnings("unchecked")
                    final List<RoleInformation> values = (List<RoleInformation>)prop.getValues();
                    boolean propertyChanged = false;
                    for (final RoleInformation role : values) {
                        final List<AccessUserAspectData> userAspects = role.getAccessUserAspects();
                        for (final AccessUserAspectData userAspect : userAspects) {
                            if (userAspect.getCaId() == fromId) {
                                userAspect.setCaId(toId);
                                propertyChanged = true;
                            }
                        }
                    }
                    if (propertyChanged) {
                        // Update the property
                        addPropertyToPartition(step.getStepIdentifier(), partition.getPartitionIdentifier(), prop);
                        changed = true;
                    }
                }
            }
        }
        return changed;
    }

    @Override
    public List<ApprovalStep> getStepList() {
        final List<ApprovalStep> approvalSteps = new ArrayList<>();
        for (ApprovalStep step = getFirstStep(); step != null; step = getStep(step.getNextStep())) {
            approvalSteps.add(step);
        }
        return approvalSteps;
    }
}
