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
package org.cesecore.authorization.user;

import java.util.Collection;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;

/**
 * Test bean giving remote access to local-only interface of AccessUserAspectManagerSessionBean
 * 
 * Based on cesecore version:
 *      AccessUserAspectManagerTestSessionBean.java 937 2011-07-14 15:57:25Z mikek
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AccessUserAspectManagerTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AccessUserAspectManagerTestSessionBean implements AccessUserAspectManagerTestSessionRemote {

    @EJB
    private AccessUserAspectManagerSessionLocal accessUserAspectSession;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void persistAccessUserAspect(AccessUserAspect accessUserAspectData) {
    	accessUserAspectSession.persistAccessUserAspect(accessUserAspectData);
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public AccessUserAspectData create(final RoleData role, final int caId,
            final X500PrincipalAccessMatchValue matchWith, final AccessMatchType matchType, final String matchValue) throws AccessUserAspectExistsException {
    	return accessUserAspectSession.create(role, caId, matchWith, matchType, matchValue);
    }

    @Override
    public AccessUserAspect find(int primaryKey) {
    	return accessUserAspectSession.find(primaryKey);
    }
    

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void remove(AccessUserAspectData userAspect) {
    	accessUserAspectSession.remove(userAspect);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void remove(Collection<AccessUserAspectData> userAspects) {
    	accessUserAspectSession.remove(userAspects);
    }

}
