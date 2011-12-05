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
package org.ejbca.core.ejb.config;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;

/**
 * This bean exists to act as a remote proxy for testing purposes
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "GlobalConfigurationProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class GlobalConfigurationProxySessionBean implements GlobalConfigurationProxySessionRemote {

    private static final Logger log = Logger.getLogger(GlobalConfigurationProxySessionBean.class);
    
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    
    @Override
    public void saveGlobalConfigurationRemote(final AuthenticationToken admin, final GlobalConfiguration globconf) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">saveGlobalConfigurationRemote()");
        }
        if (EjbcaConfiguration.getIsInProductionMode()) {
            throw new EJBException("Configuration can not be altered in production mode.");
        } else {
            globalConfigurationSession.saveGlobalConfiguration(admin, globconf);
        }
        if (log.isTraceEnabled()) {
            log.trace("<saveGlobalConfigurationRemote()");
        }
    }
}
