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
package org.cesecore.audit.log;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.FlushModeType;
import jakarta.persistence.PersistenceContext;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.config.CesecoreConfiguration;

/**
 * Dummy bean to test that log is not saved when an Exception is thrown.
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class TxFailureLoggerOperationSessionBean implements TxFailureLoggerOperationSessionRemote {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager em;

    @EJB
    private SecurityEventsLoggerSessionLocal securityLog;

    public void willLaunchExceptionAfterLog() throws Exception{
        em.setFlushMode(FlushModeType.COMMIT);
        log();
        em.flush();
    }

    public void log() throws Exception {
        securityLog.log(EventTypes.LOG_SIGN, EventStatus.SUCCESS, ModuleTypes.SECURITY_AUDIT, ServiceTypes.CORE, "TxFailureUser", null, null, null, (String)null);
        throw new Exception("Forced Exception to test that the previous will not be saved");
    }

}
