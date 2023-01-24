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
package org.ejbca.core.ejb.ra;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EndEntityManagementProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EndEntityManagementProxySessionBean implements EndEntityManagementProxySessionRemote {

    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @Override
    public int decRequestCounter(String username) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException,
            WaitingForApprovalException {
        return endEntityManagementSession.decRequestCounter(username);
    }

    @Override
    public void deleteUsersByCertificateProfileId(int certificateProfileId) {
        Query query = entityManager.createQuery("DELETE FROM UserData u WHERE u.certificateProfileId=:certificateProfileId ");
        query.setParameter("certificateProfileId", certificateProfileId);
        query.executeUpdate();
    }

    @Override
    public void deleteUsersByEndEntityProfileId(int endEntityProfileId) {
        Query query = entityManager.createQuery("DELETE FROM UserData u WHERE u.endEntityProfileId=:endEntityProfileId ");
        query.setParameter("endEntityProfileId", endEntityProfileId);
        query.executeUpdate();
    }
}
