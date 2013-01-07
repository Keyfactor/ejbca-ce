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

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.FlushModeType;
import javax.persistence.PersistenceContext;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;

/**
 * Dummy bean to test that log is not saved when an Exception is thrown.
 *
 * Based on cesecore version:
 *      TxFailureLoggerOperationSessionBean.java 897 2011-06-20 11:17:25Z johane
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "TxFailureLoggerOperationSessionRemote")
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
