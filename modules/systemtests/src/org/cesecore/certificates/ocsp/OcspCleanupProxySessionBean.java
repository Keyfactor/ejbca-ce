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

import org.ejbca.core.ejb.ocsp.OcspResponseCleanupSessionLocal;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

/**
 * Provide access to OcspCleanupSessionLocal methods for convenient call
 * with EjbRemoteHelper in Ocsp related system tests.
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class OcspCleanupProxySessionBean implements OcspCleanupProxySessionRemote {

    @EJB
    private OcspResponseCleanupSessionLocal ocspCleanupSessionLocal;

    @Override
    public void start() {
        ocspCleanupSessionLocal.start();
    }

    @Override
    public void start(String hours, String minutes, String seconds) {
        ocspCleanupSessionLocal.start(hours, minutes, seconds);
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
