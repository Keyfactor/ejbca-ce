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

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.util.EjbRemoteHelper;

public class ApprovalProfileByAdminRoles extends ApprovalProfileType {

    private static final long serialVersionUID = 6991912129797327010L;

    public ApprovalProfileByAdminRoles() {}

    @Override
    public String getTypeName() {
        return "Approval Profile by Administrator Roles";
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
    public boolean isAdminAllowedToApprove(final AuthenticationToken admin, final ApprovalProfile approvalProfile) throws AuthorizationDeniedException {
        
        RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        
        final ArrayList<String> authorizedRoles = getAuthorizedRoleNames(approvalProfile);
        for(String roleName : authorizedRoles) {
            final RoleData role = roleAccessSession.findRole(roleName);
            if(isAdminInRole(admin, role)) {
                return true;
            }
        }
        throw new AuthorizationDeniedException("Administrator does not belong to any of the authorized administrator roles");
    }

    @Override
    public boolean isAdminAllowedToApproveStep(final AuthenticationToken admin, final ApprovalStep approvalStep, 
            final ApprovalProfile approvalProfile) throws AuthorizationDeniedException {
        
        RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        if(approvalStep==null || approvalProfile==null) {
            throw new AuthorizationDeniedException("An approval step or an approval profile is not set");
        }
        final String roleName = approvalStep.getStepAuthorizationObject();
        final RoleData role = roleAccessSession.findRole(roleName);
        if(isAdminInRole(admin, role)) {
            return true;
        }
        throw new AuthorizationDeniedException("Administrator does not belong to dministrator role " + roleName);
    }
    
    private ArrayList<String> getAuthorizedRoleNames(ApprovalProfile approvalProfile) {
        ArrayList<String> authorizedRoleNames = new ArrayList<String>();
        if(approvalProfile != null) {
            Map<Integer, ApprovalStep> steps = approvalProfile.getApprovalSteps();
            for(ApprovalStep step: steps.values()) {
                String adminRole = step.getStepAuthorizationObject();
                authorizedRoleNames.add(adminRole);
            }
        }
        return authorizedRoleNames;
    }
    
    private boolean isAdminInRole(AuthenticationToken admin, RoleData role) {
        Collection<AccessUserAspectData> accessUsers = role.getAccessUsers().values();
        for (AccessUserAspectData accessUser : accessUsers) {
            // If aspect is of the correct token type
            if (admin.matchTokenType(accessUser.getTokenType())) {
                // And the two principals match (done inside to save on cycles)
                try {
                    if (admin.matches(accessUser)) {
                        return true;
                    }
                } catch (AuthenticationFailedException e) {  }
            }
        }
        return false;
    }


    @Override
    public Map<Integer, String> getMainAuthorizationObjectOptions() {
        RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
        HashMap<Integer, String> ret = new HashMap<Integer, String>();
        Collection<RoleData> roles = roleAccessSession.getAllRoles();
        for(RoleData role : roles) {
            ret.put(role.getPrimaryKey(), role.getRoleName());
        }
        return ret;
    }

}
