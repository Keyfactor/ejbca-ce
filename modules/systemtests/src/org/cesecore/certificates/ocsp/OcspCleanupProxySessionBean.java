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
package org.cesecore.certificates.ocsp;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.ocsp.OcspResponseCleanupSessionLocal;

import javax.ejb.EJB;
import javax.ejb.ScheduleExpression;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

/**
 * Provide access to OcspCleanupSessionLocal methods for convenient call
 * with EjbRemoteHelper in Ocsp related system tests.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspCleanupProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class OcspCleanupProxySessionBean implements OcspCleanupProxySessionRemote {

    @EJB
    private OcspResponseCleanupSessionLocal ocspCleanupSessionLocal;

    @Override
    public void start() {
        ocspCleanupSessionLocal.start();
    }

    @Override
    public void start(ScheduleExpression expression) {
        ocspCleanupSessionLocal.start(expression);
    }

    @Override
    public void stop() {
        ocspCleanupSessionLocal.stop();
    }

    @Override
    public void restart() {
        ocspCleanupSessionLocal.restart();
    }

    @Override
    public boolean hasTimers() {
        return ocspCleanupSessionLocal.hasTimers();
    }
}
