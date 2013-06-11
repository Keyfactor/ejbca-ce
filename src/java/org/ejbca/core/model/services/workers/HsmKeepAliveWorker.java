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
package org.ejbca.core.model.services.workers;

import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TimeZone;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionLocal;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Worker that keeps HSM sessions active.
 * 
 * @version $Id$
 *
 */
public class HsmKeepAliveWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(HsmKeepAliveWorker.class);

    @Override
    public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // Health checking will be done in three steps: 
        if (log.isDebugEnabled()) {
            log.debug("Performing HSM Keepalive operation.");
        }
        final SecurityEventsLoggerSessionLocal auditSession = (SecurityEventsLoggerSessionLocal) ejbs.get(SecurityEventsLoggerSessionLocal.class);
        // 1. If audit logging is engaged, perform a logging operation.
        if (auditSession.isAuditLogSigningEnabled()) {
            if (log.isDebugEnabled()) {
                log.debug("Performing a test logging operation.");
            }        
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("timestamp", FastDateFormat.getInstance(ValidityDate.ISO8601_DATE_FORMAT, TimeZone.getTimeZone("GMT")).format(new Date()));
            auditSession.log(EjbcaEventTypes.LOGGING_TEST, EventStatus.SUCCESS, EjbcaModuleTypes.SERVICE, ServiceTypes.CORE,
                    HsmKeepAliveWorker.class.getSimpleName(), null, null, null, details);
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Audit logging not enabled, skipping test logging operation");
            }
        }

        // 2. Call on CAAdminSessionBean.healthCheck(), the slots connected to all CAs alive
        final CAAdminSessionLocal caAdminSession = (CAAdminSessionLocal) ejbs.get(CAAdminSessionLocal.class);
        if (log.isDebugEnabled()) {
            log.debug("Performing keepalive on all CA crypto tokens.");
        }
        caAdminSession.healthCheck();
        // 3. Call on OcspResponseGeneratorSessionBean.healthCheck()
        final OcspResponseGeneratorSessionLocal ocspResponseGeneratorSession = (OcspResponseGeneratorSessionLocal) ejbs
                .get(OcspResponseGeneratorSessionLocal.class);
        if (log.isDebugEnabled()) {
            log.debug("Performing keepalive on all OCSP signing crypto tokens.");
        }
        ocspResponseGeneratorSession.healthCheck();
    }

}
