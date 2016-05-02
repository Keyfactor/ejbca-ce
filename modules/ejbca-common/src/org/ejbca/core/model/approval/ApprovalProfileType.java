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
import java.util.HashMap;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;

/**
 * A base class for approval profiles types. Any new approval profile type 
 * should inherit this class. The most important functions to implement in 
 * the new types are the methods that decide whether an admin is authorized 
 * to approve or not
 * 
 * @version $Id$
 */
public abstract class ApprovalProfileType implements Serializable {

    private static final long serialVersionUID = -4107580498745140912L;
    
    public abstract String getTypeName();
    
    public void init() {}
    
    
    public abstract boolean isAdminAllowedToApprove(AuthenticationToken admin, ApprovalProfile approvalProfile)  throws AuthorizationDeniedException;
    
    public abstract boolean isAdminAllowedToApproveStep(AuthenticationToken admin, ApprovalStep approvalstep, 
            ApprovalProfile approvalProfile)  throws AuthorizationDeniedException;
    
    public abstract long getDefaultRequestExpirationPeriod();
    
    public abstract long getDefaultApprovalExpirationPeriod();

    /**
     * @return Options for how to decided which admins are authorized
     */
    public abstract Map<Integer, String> getMainAuthorizationObjectOptions();
    
    public static Map<Integer, String> getAvailableApprovableActions() {
        Map<Integer, String> actions = new  HashMap<Integer, String>();
        int[] availableApprovalActions_ids = CAInfo.AVAILABLE_APPROVALSETTINGS;
        String[] availableApprovalActions_text = CAInfo.AVAILABLE_APPROVALSETTINGS_TEXTS;
        
        for (int i=0; i<availableApprovalActions_ids.length; i++) {
                actions.put(availableApprovalActions_ids[i], availableApprovalActions_text[i]);
            }
        return actions;
    }
}
