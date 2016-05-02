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

import java.util.HashMap;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * The approval profile where the number of approvals is all that matters.
 * 
 * @version $Id$
 */
public class ApprovalProfileNumberOfApprovals extends ApprovalProfileType {
    
    private static final long serialVersionUID = 6432620040542676563L;
    
    //private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();


    
    public ApprovalProfileNumberOfApprovals() {
        super();
        init();
    }

    @Override
    public String getTypeName() {
        return "Approval Profile by Number of Approvals";
    }

    @Override
    public void init() {
        super.init();
    }
    
    public long getDefaultRequestExpirationPeriod() {
        // TODO return a real value, tex, the value in conf/ejbca.properties
        return 0;
    }
    
    public long getDefaultApprovalExpirationPeriod() {
        // TODO return a real value, tex, the value in conf/ejbca.properties
        return 0;
    }
    
    @Override
    public boolean isAdminAllowedToApprove(AuthenticationToken admin, ApprovalProfile approvalProfile) throws AuthorizationDeniedException {
        return true;
    }

    @Override
    public boolean isAdminAllowedToApproveStep(AuthenticationToken admin, ApprovalStep approvalStep, ApprovalProfile approvalProfile)  throws AuthorizationDeniedException {
        return isAdminAllowedToApprove(admin, approvalProfile);
    }

    @Override
    public Map<Integer, String> getMainAuthorizationObjectOptions() {
        return new HashMap<Integer, String>();
    }
}
