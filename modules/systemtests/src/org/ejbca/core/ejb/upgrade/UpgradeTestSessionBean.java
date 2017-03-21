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
package org.ejbca.core.ejb.upgrade;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;

/**
 * SSB helping with setup from tests of upgrade functionality.
 * 
 * @version $Id$
 */
@SuppressWarnings("deprecation")
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UpgradeTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class UpgradeTestSessionBean implements UpgradeTestSessionRemote {

    //private static final Logger log = Logger.getLogger(UpgradeTestSessionBean.class);
    private AuthenticationToken alwaysAllowToken = new AlwaysAllowLocalAuthenticationToken(UpgradeTestSessionBean.class.getSimpleName());

    @EJB
    private RoleAccessSessionLocal roleAccessSession;
    @EJB
    private RoleManagementSessionLocal roleManagementSession;
    
    @Override
    public void createRole(final String roleName, final List<AccessRuleData> accessRules, final List<AccessUserAspectData> accessUserAspectDatas) {
        try {
            AdminGroupData adminGroupData = roleManagementSession.create(alwaysAllowToken, roleName);
            if (accessRules!=null) {
                adminGroupData = roleManagementSession.addAccessRulesToRole(alwaysAllowToken, adminGroupData, accessRules);
            }
            if (accessUserAspectDatas!=null) {
                roleManagementSession.addSubjectsToRole(alwaysAllowToken, adminGroupData, accessUserAspectDatas);
            }
        } catch (RoleNotFoundException | RoleExistsException e) {
            throw new EJBException(e);
        }
    }

    @Override
    public void deleteRole(final String roleName) {
        roleManagementSession.deleteIfPresentNoAuth(alwaysAllowToken, roleName);
    }

    @Override
    public List<AccessRuleData> getAccessRuleDatas(String readOnlyRoleName) {
        final AdminGroupData adminGroupData = roleAccessSession.findRole(readOnlyRoleName);
        return new ArrayList<>(adminGroupData.getAccessRules().values());
    }
}
