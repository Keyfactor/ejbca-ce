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
package org.ejbca.core.ejb.approval;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.cesecore.profiles.ProfileData;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ApprovalSessionProxyRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class ApprovalProfileProxySessionBean implements ApprovalProfileProxySessionRemote {

    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    
    @Override
    public List<ProfileData> findByApprovalProfileName(String profileName) {
        return approvalProfileSession.findByApprovalProfileName(profileName);
    }

}
