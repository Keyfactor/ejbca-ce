package org.ejbca.core.model.services.workers;

import org.ejbca.core.model.services.IWorker;

public final class DatabaseMaintenanceWorkerConstants {

    public static final String WORKER_CLASS = "org.ejbca.core.model.services.workers.DatabaseMaintenanceWorker";
    public static final String DEFAULT_DELAY_TIMEUNIT = IWorker.UNIT_DAYS;
    public static final int DEFAULT_DELAY_TIMEVALUE = 30;
    public static final int DEFAULT_BATCH_SIZE = 100;
    public static final String PROP_DELAY_TIMEUNIT = "delayTimeUnit";
    public static final String PROP_DELAY_TIMEVALUE = "delayTimeValue";
    public static final String PROP_DELETE_EXPIRED_CERTIFICATES = "deleteExpiredCertificates";
    public static final String PROP_DELETE_EXPIRED_CRLS = "deleteExpiredCrls";
    public static final String PROP_BATCH_SIZE = "batchSize";

    private DatabaseMaintenanceWorkerConstants() {
    }
}
