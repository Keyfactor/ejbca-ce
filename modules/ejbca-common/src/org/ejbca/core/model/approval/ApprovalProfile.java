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
package org.ejbca.core.model.approval;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * A class handling approval profiles
 * @version $Id$
 *
 */
public class ApprovalProfile extends UpgradeableDataHashMap implements Serializable, Cloneable{
    
    private static final long serialVersionUID = 250315209409187525L;
    private static final Logger log = Logger.getLogger(ApprovalProfile.class);

    public static final String TYPE = "APPROVAL_PROFILE";
    
    public static final float LATEST_VERSION = 1;
    
    public static final String PROFILENAME      = "profileName";
    public static final String PROFILETYPE      = "ProfileType";
    public static final String APPROVALPROFILETYPE    = "ApprovalProfileType";
    public static final String ACTIONS_REQUIRE_APPROVAL = "actionsRequireApprovals";
    public static final String REQUEST_EXPIRATION_PERIOD = "requestExpirationPeriod";
    public static final String APPROVAL_EXPIRATION_PERIOD = "approvalExpirationPeriod";
    
    // Nr of approvals profile
    public static final String NUMBER_OF_APPROVALS_PROPERTY_NAME = "numberOfApprovals";
    
    // None number of approvals profile
    public static final String APPROVALSTEPS = "approvalSteps"; // Holds a Map<ApprovalStepID, ApprovalStep>
    public static final String ISAPPROVALSTEPSORDERED = "isApprovalStepsOrdered"; // whether or not the steps are ordered
    public static final String APPROVALSTEPSORDER = "approvalStepsOrder"; // An ordered list of step IDs
    
    private int lastApprovalStepId;
    
    public ApprovalProfile() {
        super();
    }
    
    public ApprovalProfile(final String name) {
        super();
        init(name, null, true);
    }
    
    public ApprovalProfile(final String name, final ApprovalProfileType profileType, final boolean orderedApprovalSteps) {
        super();
        init(name, profileType, orderedApprovalSteps);
    }
    
    private void init(final String name, final ApprovalProfileType type, final boolean orderedApprovalSteps) {
        
        data.put(PROFILENAME, name);
        data.put(PROFILETYPE, TYPE);
        
        ApprovalProfileType profileType = type;
        if(profileType==null) {
            profileType = new ApprovalProfileNumberOfApprovals();
        }
        data.put(APPROVALPROFILETYPE, profileType);
        data.put(REQUEST_EXPIRATION_PERIOD, profileType.getDefaultRequestExpirationPeriod());
        data.put(APPROVAL_EXPIRATION_PERIOD, profileType.getDefaultApprovalExpirationPeriod());

        data.put(APPROVALSTEPS, new HashMap<Integer, ApprovalStep>());
        lastApprovalStepId = 0;
        data.put(ISAPPROVALSTEPSORDERED, orderedApprovalSteps);
        if(orderedApprovalSteps) {
            data.put(APPROVALSTEPSORDER, new ArrayList<Integer>());
        }
        
    }
    
    public String getProfileName() {
        return (String) data.get(PROFILENAME);
    }

    public ApprovalProfileType getApprovalProfileType() {
        return (ApprovalProfileType) data.get(APPROVALPROFILETYPE);
    }
    public void setApprovalProfileType(ApprovalProfileType type) {
        data.put(APPROVALPROFILETYPE, type);
    }
    
    public long getRequestExpirationPeriod() {
        return (long) data.get(REQUEST_EXPIRATION_PERIOD);
    }
    public void setRequestExpirationPeriod(final long expirationPeriod) {
        data.put(REQUEST_EXPIRATION_PERIOD, expirationPeriod);
    }

    public long getApprovalExpirationPeriod() {
        return (long) data.get(APPROVAL_EXPIRATION_PERIOD);
    }
    public void setApprovalExpirationPeriod(final long expirationPeriod) {
        data.put(APPROVAL_EXPIRATION_PERIOD, expirationPeriod);
    }

    
    public boolean getIsApprovalStepsOrdered() {
        return (Boolean)data.get(ISAPPROVALSTEPSORDERED);
    }
    public void setIsApprovalStepsOrdered(final boolean ordered) {
        data.put(ISAPPROVALSTEPSORDERED, ordered);
    }
    
    public List<Integer> getApprovalStepsOrder() {
        return (List<Integer>)data.get(APPROVALSTEPSORDER);
    }
    
    public int[] getActionsRequireApproval() {
        if(!data.containsKey(ACTIONS_REQUIRE_APPROVAL)) {
            data.put(ACTIONS_REQUIRE_APPROVAL, new int[0]);
        }
        return (int[]) data.get(ACTIONS_REQUIRE_APPROVAL);
    }
    
    public void setActionsRequireApproval(final int[] actions) {
        data.put(ACTIONS_REQUIRE_APPROVAL, actions);
    }
    
    
    // ------------------- Approval Steps ------------------------ //
    
    
    public int getNewStepId() {
        int newID = lastApprovalStepId+1;
        final List<Integer> order = getApprovalStepsOrder();
        while(order.contains(Integer.valueOf(newID))) {
            newID++;
        }
        
        return newID;
    }
    
    public Map<Integer, ApprovalStep> getApprovalSteps() {
        if(data.get(APPROVALSTEPS)==null) {
            data.put(APPROVALSTEPS, new HashMap<Integer, ApprovalStep>());
        }
        return (Map<Integer, ApprovalStep>) data.get(APPROVALSTEPS);
    }
    
    public ApprovalStep getApprovalStep(final int stepId) {
        Map<Integer, ApprovalStep> steps = getApprovalSteps();
        return steps.get(Integer.valueOf(stepId));
    }
    
    public void addApprovalStep(final ApprovalStep step) {
        Map<Integer, ApprovalStep> steps = getApprovalSteps();
        steps.put(Integer.valueOf(step.getStepId()), step);
        data.put(APPROVALSTEPS, steps);
        if(getIsApprovalStepsOrdered()) {
            List<Integer> order = getApprovalStepsOrder();
            if(!order.contains(Integer.valueOf(step.getStepId()))) {
                order.add(step.getStepId());
                data.put(APPROVALSTEPSORDER, order);
                lastApprovalStepId = step.getStepId();
            }
        }
        
    }
    
    public void removeApprovalStep(final ApprovalStep step) {
        if(step!=null) {
            removeApprovalStep(step.getStepId());
        }
    }
    
    public void removeApprovalStep(final int stepId) {
        Map<Integer, ApprovalStep> steps = getApprovalSteps();
        if(steps.containsKey(Integer.valueOf(stepId))) {
            steps.remove(Integer.valueOf(stepId));
            List<Integer> order = getApprovalStepsOrder();
            final int stepIndex = order.indexOf(Integer.valueOf(stepId));
            order.remove(stepIndex);
            data.put(APPROVALSTEPS, steps);
            data.put(APPROVALSTEPSORDER, order);
        }
    }
    
    public void moveApprovalStepUp(final int stepId) {
        if(stepId > 0) { 
            List<Integer> orderedSteps = getApprovalStepsOrder();
            final int index = orderedSteps.indexOf(Integer.valueOf(stepId));
            orderedSteps.remove(index);
            orderedSteps.add(index-1, Integer.valueOf(stepId));
            data.put(APPROVALSTEPSORDER, orderedSteps);
        }
    }
    
    public void moveApprovalStepDown(final int stepId) {
        if(stepId > 1) {
            List<Integer> orderedSteps = getApprovalStepsOrder();
            final int index = orderedSteps.indexOf(Integer.valueOf(stepId));
            orderedSteps.remove(index);
            orderedSteps.add(index+1, stepId);
            data.put(APPROVALSTEPSORDER, orderedSteps);
        }
    }
    
    
    // ---------------- Nr of Approvals -------------------------- //
    
    
    public void setNumberOfApprovals(int nrOfApprovals) {
        if(getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals) {
            data.put(NUMBER_OF_APPROVALS_PROPERTY_NAME, nrOfApprovals);
        }
    }
    
    public int getNumberOfApprovals() {
        if(getApprovalProfileType() instanceof ApprovalProfileNumberOfApprovals) {
            if(!data.containsKey(NUMBER_OF_APPROVALS_PROPERTY_NAME)) {
                data.put(NUMBER_OF_APPROVALS_PROPERTY_NAME, 0);
            }
            return (int) data.get(NUMBER_OF_APPROVALS_PROPERTY_NAME);
        }
        return 0;
    }
    
    @Override
    public ApprovalProfile clone() throws CloneNotSupportedException {
        final ApprovalProfile clone = new ApprovalProfile(getProfileName()+"-(Clone)");
        // We need to make a deep copy of the hashmap here
        clone.data = new LinkedHashMap<>(data.size());
        for (final Entry<Object,Object> entry : data.entrySet()) {
                Object value = entry.getValue();
                if (value instanceof ArrayList<?>) {
                        // We need to make a clone of this object, but the stored immutables can still be referenced
                        value = ((ArrayList<?>)value).clone();
                }
                clone.data.put(entry.getKey(), value);
        }
        return clone;
    }
    

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    @Override
    public void upgrade() {}
}
