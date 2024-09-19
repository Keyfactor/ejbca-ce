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
package org.ejbca.core.ejb.authentication.cli;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.cesecore.config.CesecoreConfiguration;
import org.ejbca.core.ejb.ra.UserData;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CliAuthenticationSystemTestHelperSessionBean implements CliAuthenticationSystemTestHelperSessionRemote {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @Override
    public void createUser(String username, String password) {
        UserData defaultCliUserData = new UserData(username, password, false, "UID="
                + username, 0, null, null, null, 0, 0, 0, 0, null);
        entityManager.persist(defaultCliUserData);
    }
}
