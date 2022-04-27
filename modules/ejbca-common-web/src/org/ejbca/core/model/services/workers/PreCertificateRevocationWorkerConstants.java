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

import org.ejbca.core.model.services.IWorker;

/**
 * Constants for PreCertificateRevocationWorker. This is a separate class, to make the constants
 * available in code in community edition.
 */
public class PreCertificateRevocationWorkerConstants {

    public static final String WORKER_CLASS = "org.ejbca.core.model.services.workers.PreCertificateRevocationWorker";

    public static final String PROP_MAX_ISSUANCE_TIME = "worker.maxIssuanceTime";
    public static final String PROP_MAX_ISSUANCE_TIMEUNIT = "worker.maxIssuancceTimeUnit";

    public static final String DEFAULT_MAX_ISSUANCE_TIME = "30";
    public static final String DEFAULT_MAX_ISSUANCE_TIMEUNIT = IWorker.UNIT_MINUTES;

}
