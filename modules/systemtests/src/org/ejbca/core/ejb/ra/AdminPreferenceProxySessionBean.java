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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.config.CesecoreConfiguration;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionDefault;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.Query;

@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminPreferenceProxySessionBean extends AdminPreferenceSessionDefault implements AdminPreferenceProxySessionRemote {
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    @Override
    public void deleteAdminPreferences(AuthenticationToken token) {
        final String id = makeAdminPreferenceId(token);
        Query query = entityManager.createQuery("DELETE FROM AdminPreferencesData ap WHERE ap.id=:id ");
        query.setParameter("id", id);
        query.executeUpdate();
    }

}
