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

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.management.RoleManagementSessionLocal;

public class ApprovalProfileByAdminRoles extends ApprovalProfileType {

    private static final long serialVersionUID = 6991912129797327010L;

    
    public ApprovalProfileByAdminRoles() {}
    
    @Override
    public int getTypeID() {
        // TODO Auto-generated method stub
        return 1;
    }

    @Override
    public String getTypeName() {
        return this.getClass().getSimpleName();
    }

    @Override
    public void init(Map<String, Object> fields) {
        
        this.fields.put(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME, new int[0]);
        if(fields!=null) {
            if(fields.containsKey(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME)) {
                this.fields.put(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME, fields.get(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME));
            }
        
            //Set<Entry<String, Object>> entries = fields.entrySet();
            //for(Entry<String, Object> entry : entries) {
            //    if(StringUtils.startsWith(entry.getKey(), ADMIN_PROPERTY_PREFIX)) {
            //        this.fields.put(entry.getKey(), entry.getValue());
            //    }
            //}
        }
    }

    @Override
    public int[] getActionsRequireApproval() {
        Object ret = fields.get(ACTIONS_REQUIRE_APPROVAL_PROPERTY_NAME);
        if(ret==null) {
            return new int[0];
        }
        return (int[]) ret;
    }

    @Override
    public void setField(String key, Object value) {
        //if(!StringUtils.startsWith(key, ADMIN_PROPERTY_PREFIX)) {
        //    key = ADMIN_PROPERTY_PREFIX + key;
        //}
        fields.put(key, value);
    }
    
    @Override
    public Map<String, Object> getAllFields() {
        // TODO Auto-generated method stub
        return null;
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

    public Map<Integer, String> getAdminRolesNames(AuthenticationToken admin, RoleManagementSessionLocal roleManagementSession) {
        HashMap<Integer, String> ret = new HashMap<Integer, String>();
        Collection<RoleData> roles = roleManagementSession.getAllRolesAuthorizedToEdit(admin);
        for(RoleData role : roles) {
            ret.put(role.getPrimaryKey(), role.getRoleName());
        }
        return ret;
    }

}
