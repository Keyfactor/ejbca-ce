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
package org.ejbca.core.model.services.workers;

import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;

/**
 * Service that revokes pre-certificates whose certificates didn't get issued.
 *
 * @version $Id$
 */
public class IncompleteIssuanceRevocationWorker extends BaseWorker {

    private static final Logger log = Logger.getLogger(IncompleteIssuanceRevocationWorker.class);

    public static final String PROP_MAX_ISSUANCE_TIME = "worker.maxIssuanceTime";
    public static final String PROP_MAX_ISSUANCE_TIMEUNIT = "worker.maxIssuancceTimeUnit";

    public static final String DEFAULT_MAX_ISSUANCE_TIME = "30";
    public static final String DEFAULT_MAX_ISSUANCE_TIMEUNIT = IWorker.UNIT_MINUTES;

    /**
     * Semaphore making sure not two identical services run at the same time.
     * This must be decided by serviceName, since we can configure one of these
     * services for every publisher.
     */
    private static HashMap<String, Boolean> runmap = new HashMap<>();

    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // This worker should always be able to run
    }

    /**
     * Checks if there are any half-issued certificates, and revokes them.
     *
     * @see org.ejbca.core.model.services.IWorker#work()
     */
    @Override
    public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        log.trace(">work");
        final RevocationSessionLocal revocationSession = ((RevocationSessionLocal)ejbs.get(RevocationSessionLocal.class));
        // A semaphore used to not run parallel processing jobs
        boolean running = false;
        synchronized (runmap) {
            Boolean b = runmap.get(this.serviceName);
            if (b != null) {
                running = b.booleanValue();
            }
            if (!running) {
                runmap.put(this.serviceName, Boolean.TRUE);
            }
        }
        final ServiceExecutionResult ret;
        if (!running) {
            try {
                int numRevokedCerts = 0;
                while (true) {
                    int revoked = revocationSession.revokeIncompletelyIssuedCertsBatched(admin, getMaxIssuanceTimeMillis());
                    if (revoked == 0) {
                        break;
                    }
                    numRevokedCerts += revoked;
                }
                return new ServiceExecutionResult(Result.SUCCESS, "Incomplete Issuance Revocation Service revoked " + numRevokedCerts + " certificates");
            } catch (AuthorizationDeniedException e) {
                return new ServiceExecutionResult(Result.FAILURE, "Internal error in service '" + serviceName + "'. Always allow token was denied access");
            } finally {
                synchronized (runmap) {
                    runmap.put(this.serviceName, Boolean.FALSE);
                }
            }
        } else {
            final String msg = InternalEjbcaResources.getInstance().getLocalizedMessage("services.alreadyrunninginvm", IncompleteIssuanceRevocationWorker.class.getName());
            log.info(msg);
            ret = new ServiceExecutionResult(Result.NO_ACTION, msg);
        }
        log.trace("<work");
        return ret;
    }

    private long getMaxIssuanceTimeMillis() throws ServiceExecutionFailedException {
        return getTimeBeforeExpire(IncompleteIssuanceRevocationWorker.PROP_MAX_ISSUANCE_TIMEUNIT, IncompleteIssuanceRevocationWorker.PROP_MAX_ISSUANCE_TIME);
    }


}
