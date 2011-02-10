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
package org.cesecore.core.ejb.authorization;

import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationTreeUpdateData;
import org.ejbca.core.model.InternalResources;

/**
 * Bean to handle the AuthorizationTreeUpdateData entity.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AuthorizationTreeUpdateDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AuthorizationTreeUpdateDataSessionBean implements AuthorizationTreeUpdateDataSessionLocal, AuthorizationTreeUpdateDataSessionRemote {

    private static final Logger LOG = Logger.getLogger(AuthorizationTreeUpdateDataSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources INTRES = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    /**
     * Cache this local bean, because it will cause many many database lookups
     * otherwise
     */
    private AuthorizationTreeUpdateData authTreeData = null;

    @Override
    public AuthorizationTreeUpdateData getAuthorizationTreeUpdateData() {
        if (authTreeData == null) {
            authTreeData = AuthorizationTreeUpdateData.findByPrimeKey(entityManager,
                    AuthorizationTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
            if (authTreeData == null) {
                try {
                    final AuthorizationTreeUpdateData temp = new AuthorizationTreeUpdateData();
                    entityManager.persist(temp);
                    authTreeData = temp;
                } catch (Exception e) {
                    final String msg = INTRES.getLocalizedMessage("authorization.errorcreateauthtree");
                    LOG.error(msg, e);
                    throw new EJBException(e);
                }
            }
        }
        return authTreeData;
    }

    @Override
    public void signalForAuthorizationTreeUpdate() {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">signalForAuthorizationTreeUpdate");
        }
        getAuthorizationTreeUpdateData().incrementAuthorizationTreeUpdateNumber();
        if (LOG.isTraceEnabled()) {
            LOG.trace("<signalForAuthorizationTreeUpdate");
        }
    }
}
