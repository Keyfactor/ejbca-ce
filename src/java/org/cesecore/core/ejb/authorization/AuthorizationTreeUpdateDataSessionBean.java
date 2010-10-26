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
 * @version
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "AuthorizationTreeUpdateDataSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AuthorizationTreeUpdateDataSessionBean implements AuthorizationTreeUpdateDataSessionLocal, AuthorizationTreeUpdateDataSessionRemote {

    private static final Logger log = Logger.getLogger(AuthorizationTreeUpdateDataSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    /**
     * Cache this local bean, because it will cause many many database lookups
     * otherwise
     */
    private AuthorizationTreeUpdateData authorizationTreeUpdateData = null;

    /**
     * Returns a reference to the AuthorizationTreeUpdateData
     */
    public AuthorizationTreeUpdateData getAuthorizationTreeUpdateData() {
        if (authorizationTreeUpdateData == null) {
            authorizationTreeUpdateData = AuthorizationTreeUpdateData.findByPrimeKey(entityManager,
                    AuthorizationTreeUpdateData.AUTHORIZATIONTREEUPDATEDATA);
            if (authorizationTreeUpdateData == null) {
                try {
                    AuthorizationTreeUpdateData temp = new AuthorizationTreeUpdateData();
                    entityManager.persist(temp);
                    authorizationTreeUpdateData = temp;
                } catch (Exception e) {
                    String msg = intres.getLocalizedMessage("authorization.errorcreateauthtree");
                    log.error(msg, e);
                    throw new EJBException(e);
                }
            }
        }
        return authorizationTreeUpdateData;
    }

    /**
     * Method incrementing the authorization tree update number and thereby
     * signaling to other beans that they should reconstruct their access trees.
     */
    public void signalForAuthorizationTreeUpdate() {
        if (log.isTraceEnabled()) {
            log.trace(">signalForAuthorizationTreeUpdate");
        }
        getAuthorizationTreeUpdateData().incrementAuthorizationTreeUpdateNumber();
        if (log.isTraceEnabled()) {
            log.trace("<signalForAuthorizationTreeUpdate");
        }
    }

}
