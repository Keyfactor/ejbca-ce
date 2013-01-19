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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.roles.RoleNotFoundException;

/**
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RoleInitializationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RoleInitializationSessionBean implements RoleInitializationSessionRemote {

	@EJB
	private RoleManagementSessionLocal roleMgmg;
	
	@Override
    public void initializeAccessWithCert(AuthenticationToken authenticationToken, String roleName, Certificate certificate) throws RoleExistsException, RoleNotFoundException {
		roleMgmg.initializeAccessWithCert(authenticationToken, roleName, certificate);
    }


}
