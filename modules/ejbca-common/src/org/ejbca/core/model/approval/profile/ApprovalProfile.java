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
package org.ejbca.core.model.approval.profile;

import java.io.Serializable;
import java.util.Collection;
import java.util.Map;
import java.util.Set;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.profiles.Profile;

/**
 * An interface for approval profiles types. 
 * 
 * @version $Id$
 */
public interface ApprovalProfile extends Profile, Serializable, Cloneable {

    public static final String TYPE_NAME = "APPROVAL_PROFILE";

    final String PROPERTY_NOTIFICATION_EMAIL_RECIPIENT = "notification_email_recipient";
    final String PROPERTY_NOTIFICATION_EMAIL_SENDER = "notification_email_sender";
    final String PROPERTY_NOTIFICATION_EMAIL_MESSAGE_SUBJECT = "notification_email_msg_subject";
    final String PROPERTY_NOTIFICATION_EMAIL_MESSAGE_BODY = "notification_email_msg_body";
    /** Key for the data value marking the number of approvals required. */
    final String PROPERTY_NUMBER_OF_REQUIRED_APPROVALS = "number_of_required_approvals";

    /**
     * 
     * @return the type as a human readable name.
     */
    String getApprovalProfileLabel();
    
    String getApprovalProfileIdentifier();

    long getDefaultRequestExpirationPeriod();

    long getDefaultApprovalExpirationPeriod();


    /**
    * Clone has to be implemented instead of a copy constructor due to the fact that we'll be referring to implementations by this interface only. 
    * 
    * @return a deep copied clone of this profile
    */
    ApprovalProfile clone();
    
    /**
     * Method to give an approval implementation a chance to skip out if it's not configured to perform any actions. 
     * 
     * @return true if approval is relevant and should be used.
     */
    boolean isApprovalRequired();
    
    /**
     * @param approvalsPerformed a Collection of approvals already performed. 
     * 
     * @return true if this approval profile's criteria are fulfilled, allowing the approval to pass 
     * @throws AuthenticationFailedException if any of the authentication tokens in the approval collection were faulty
     */
    boolean canApprovalExecute(final Collection<Approval> approvalsPerformed) throws ApprovalException, AuthenticationFailedException;
    
    /**
     * 
     * @param approvalsPerformed the approvals performed against this profile
     * @return the number of remaining approvals 
     */
    int getRemainingApprovals(final Collection<Approval> approvalsPerformed);
        
    /**
     * @return true if the amount of sequences of this profile is fixed, false if it's dynamic
     */
    boolean isStepSizeFixed();
    
    /** 
     * @return true if it's possible to add fields to the partitions of this profile 
     */
    boolean arePartitionsFixed();
    
    Map<Integer, ApprovalStep> getSteps();
    
    /**
     * Adds a step without modifying any order. Without setting order, this step will not be handled. 
     * 
     * @param step an ApprovalStep
     */
    void addStep(final ApprovalStep step);
    
    /**
     * Creates a new step and adds it first. 
     * 
     * @return the new step
     */
    ApprovalStep addStepFirst();
    
    /**
     * Deletes a step and attaches the steps before and after to each other in order. 
     * 
     * @param approvalStepIdentifier the identifier of the approval step
     */
    void deleteStep(final int approvalStepIdentifier);
    
    void setSteps(final Map<Integer, ApprovalStep> steps);
    
    /**
    * Adds a property to a specific partition in a specific sequence in this approval profile, for display in the UI. If the property already
    * exists, it will be overwritten
    * 
    * @param stepId the identifier of the step
    * @param partitionId the ID of a partition in the step
    * @param property a DynamicUiProperty
     * @throws NoSuchApprovalStepException if the step specified by stepId wasn't found.
    */
    void addPropertyToPartition(final int stepId, final int partitionId, final DynamicUiProperty<? extends Serializable> property) throws NoSuchApprovalStepException;
    
    /**
     * Removes a property from a partition. Will do nothing if property was predefined in the template. 
     * 
     * @param stepId the identifier of the step 
     * @param partitionId the ID of a partition in the step
     * @param propertyName the name of the property.
     */
    void removePropertyFromPartition(final int stepId, final int partitionId, final String propertyName);
    
    /**
     * Adds a partition to this sequence
     * 
     * @param stepIdentifier the identifier of the sequence
     * 
     * @return the partition, with a generated ID
     */
     ApprovalPartition addPartition(final int stepIdentifier);
    
    /**
     * 
     * @param stepId the identifier of the step
     * @param partitionId the ID of a partition in the step
     * @param properties a list of DynamicUiProperties
     * @throws NoSuchApprovalStepException if the step identified by stepId didn't exist
     */
    void addPropertiesToPartition(final Integer stepId, final int partitionId, final Collection< DynamicUiProperty<? extends Serializable>> properties) throws NoSuchApprovalStepException;
        
    /**
     * Identifier of the sequence to read first. 
     * 
     * @param firstSequence
     */
    void setFirstStep(final int firstStep);
    
    /**
     * @param identifier a step identifier
     * @return the sequence with the given identifier, or null if not found. 
     */
    ApprovalStep getStep(final Integer identifier);
    
    /** 
     * @return the first step
     */
    ApprovalStep getFirstStep();
    
    /**
     * Deletes a partition from a step
     * 
     * @param approvalStepIdentifier the ID of the step
     * @param partitionIdentifier the ID of the partition
     */
    void deletePartition(final int approvalStepIdentifier, final int partitionIdentifier);

    /**
     * Returns true if the approval is authorized for the step and partition it covers, and that all preceding steps are satisfied. 
     * 
     * @param approvalsPerformed the already registered approvals 
     * @param approval the new approval
     * @return true if the given approval is authorized 
     * @throws AuthenticationFailedException if the authentication token in the approval wasn't valid
     */
    boolean isApprovalAuthorized(final Collection<Approval> approvalsPerformed, final Approval approval) throws AuthenticationFailedException;
    
    /**
     * @return the number of steps in this profile
     */
    int getNumberOfSteps();
    
    /**
     * 
     * @param approvalsPerformed a list of performed approvals
     * @return the ordinal of the step currently being evaluated, given the performed approvals
     * @throws AuthenticationFailedException if the authentication of the approvals failed 
     */
    int getOrdinalOfStepBeingEvaluated(final Collection<Approval> approvalsPerformed) throws AuthenticationFailedException;
    
    /**
     * Returns the first step which hasn't been fully evaluated by the given collection of approvals, or null if all steps 
     * have been evaluated. 
     * 
     * @param approvalsPerformed approvalsPerformed a list of performed approvals
     * @return the step currently being evaluated, given the performed approvals, or null if all steps have been evaluated. 
     * @throws AuthenticationFailedException if the authentication of the approvals failed 
     */
    ApprovalStep getStepBeingEvaluated(final Collection<Approval> approvalsPerformed) throws AuthenticationFailedException;
    
    /**
     * Tests if an administrator can approve a particular partition 
     * 
     * @param authenticationToken an authentication token
     * @param approvalPartition an approval partition from an approval step
     * @return true if administrator has approval rights
     * @throws AuthenticationFailedException if the authentication token in the approval doesn't check out
     */
    boolean canApprovePartition(final AuthenticationToken authenticationToken, final ApprovalPartition approvalPartition) throws AuthenticationFailedException;
     
    /**
     * Tests if an administrator can view a particular partition. Approval rights automatically count as view rights. 
     * 
     * @param authenticationToken an authentication token
     * @param approvalPartition an approval partition from an approval step
     * @return true if administrator has view or approval rights
     * @throws AuthenticationFailedException if the authentication token in the approval doesn't check out
     */
    boolean canViewPartition(final AuthenticationToken authenticationToken, final ApprovalPartition approvalPartition) throws AuthenticationFailedException;

    /**
     * @return a set of properties to hide at the approval screen. 
     */
    Set<String> getHiddenProperties();

    /** @return true if notifications is configured in the specified partition */
    boolean isNotificationEnabled(ApprovalPartition approvalPartition);

    /** Add notification properties */
    ApprovalPartition addNotificationProperties(ApprovalPartition approvalPartition, String recipient, String sender, String subject, String body);

    /** Remove notification properties */
    ApprovalPartition removeNotificationProperties(ApprovalPartition approvalPartition);

    /**
     * Allows for querying a partition of a certain property was defined procedurally.
     * 
     * @param stepIdentifier the identifier of the step 
     * @param partitionIdentifier the identifier of the partition
     * @param propertyName the name of the property
     * @return true if the property is considered predefined.
     */
    boolean isPropertyPredefined(int stepIdentifier, int partitionIdentifier, final String propertyName);

    /** @return the number of required approvals of the specified partition. Defaults to 1. */
    int getNumberOfApprovalsRequired(int stepIdentifier, int partitionIdentifier);

    /** @return the number of required approvals of the specified partition that has not yet been approved. */
    int getRemainingApprovalsInPartition(Collection<Approval> approvalsPerformed, int stepIdentifier, int partitionIdentifier);
}
