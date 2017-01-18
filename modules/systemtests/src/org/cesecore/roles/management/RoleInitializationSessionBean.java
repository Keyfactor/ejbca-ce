/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.roles.management;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleInitializationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleInitializationSessionBean implements RoleInitializationSessionRemote {

    private static final Logger log = Logger.getLogger(RoleInitializationSessionBean.class);
    
	@EJB
	private RoleManagementSessionLocal roleMgmg;
	
	@Override
    public void initializeAccessWithCert(AuthenticationToken authenticationToken, String roleName, Certificate certificate) throws RoleExistsException, RoleNotFoundException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">initializeAccessWithCert: " + authenticationToken.toString() + ", " + roleName);
        }
        // Create a role
        AdminGroupData role = roleMgmg.create(authenticationToken, roleName);

        // Create a user aspect that matches the authentication token, and add that to the role.
        List<AccessUserAspectData> accessUsers = new ArrayList<AccessUserAspectData>();
        accessUsers.add(new AccessUserAspectData(role.getRoleName(), CertTools.getIssuerDN(certificate).hashCode(),
                X500PrincipalAccessMatchValue.WITH_COMMONNAME, AccessMatchType.TYPE_EQUALCASE, CertTools.getPartFromDN(
                        CertTools.getSubjectDN(certificate), "CN")));
        roleMgmg.addSubjectsToRole(authenticationToken, role, accessUsers);

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.ROLE_ROOT.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleMgmg.addAccessRulesToRole(authenticationToken, role, accessRules);
        if (log.isTraceEnabled()) {
            log.trace("<initializeAccessWithCert: " + authenticationToken.toString() + ", " + roleName);
        }
    }

}
