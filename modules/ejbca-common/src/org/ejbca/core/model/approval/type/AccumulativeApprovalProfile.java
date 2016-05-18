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
package org.ejbca.core.model.approval.type;

import java.util.HashMap;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.approval.ApprovalProfile;
import org.ejbca.core.model.approval.ApprovalStep;

/**
 * This approval archetype represents the legacy method of approvals, i.e where a fixed number of administrators need to approve a request for it to 
 * pass.
 * 
 * @version $Id$
 */
public class AccumulativeApprovalProfile extends ApprovalProfileType {
    
    private static final long serialVersionUID = 6432620040542676563L;
    
    
    public AccumulativeApprovalProfile() {
        super();
        init();
    }

    @Override
    public String getTypeName() {
        return "Accumulative Approvals";
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
