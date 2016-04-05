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

import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
//import org.ejbca.core.model.util.EjbLocalHelper;

public class ApprovalProfileNumberOfApprovals extends ApprovalProfileType {
    


    private static final long serialVersionUID = 6432620040542676563L;

    public static final String NUMBER_OF_APPROVALS_PROPERTY_NAME = "numberOfApprovals";

    
    public ApprovalProfileNumberOfApprovals() {
        super();
        init(null);
    }
    
    public ApprovalProfileNumberOfApprovals(final Map<String, Object> fields) {
        super();
        init(fields);
    }
    
    @Override
    public int getTypeID() {
        // TODO Auto-generated method stub
        return 0;
    }

    @Override
    public String getTypeName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public void init(final Map<String, Object> fields) {
        //EjbLocalHelper localHelper = new EjbLocalHelper();
        //internalKeyBindingMgmtSession = localHelper.getInternalKeyBindingMgmtSession();
        
        this.fields.put(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME, new int[0]);
        this.fields.put(NUMBER_OF_APPROVALS_PROPERTY_NAME, 0);
        if(fields!=null) {
            if(fields.containsKey(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME)) {
                int[] actions = (int[]) fields.get(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME);
                this.fields.put(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME, actions);
            }
            if(fields.containsKey(NUMBER_OF_APPROVALS_PROPERTY_NAME)) {
                int numberOfApprovals = (int) fields.get(NUMBER_OF_APPROVALS_PROPERTY_NAME);
                this.fields.put(NUMBER_OF_APPROVALS_PROPERTY_NAME, numberOfApprovals);
            }
        }
    }

    @Override
    public boolean isAdminAllowedToApprove(AuthenticationToken admin) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isProfileFulfilled() {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public Map<String, Object> getAllFields() {
        return this.fields;
    }
    
    public void setNumberOfApprovals(int nrOfApprovals) {
        fields.put(NUMBER_OF_APPROVALS_PROPERTY_NAME, nrOfApprovals);
    }
    
    public int getNumberOfApprovals() {
        return (int) fields.get(NUMBER_OF_APPROVALS_PROPERTY_NAME);
    }

}
