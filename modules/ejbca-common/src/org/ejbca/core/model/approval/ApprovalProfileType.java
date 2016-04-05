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
import org.cesecore.certificates.ca.CAInfo;

public abstract class ApprovalProfileType implements Serializable {

    private static final long serialVersionUID = -4107580498745140912L;
    
    public static final String ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME = "actionsRequireApprovals";

    protected Map<String, Object> fields = new HashMap<String, Object>();
    
    public abstract int getTypeID();
    
    public abstract String getTypeName();
    
    public abstract void init(Map<String, Object> fields);
    
    public abstract Map<String, Object> getAllFields();
    
    public abstract boolean isAdminAllowedToApprove(AuthenticationToken admin);
    
    public abstract boolean isProfileFulfilled();
    
    public Object getField(String key) {
        return fields.get(key);
    }
    
    public void setField(String key, Object value) {
        fields.put(key, value);
    }
    
    public int[] getActionsRequireApproval() {
        Object ret = fields.get(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME);
        if(ret==null) {
            return new int[0];
        }
        return (int[]) ret;
        
    }
    
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
