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
package org.ejbca.ui.web.admin.services.servicetypes;

import org.cesecore.util.PropertyTools;
import org.ejbca.core.model.services.workers.DatabaseMaintenanceWorker;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

/**
 * Database maintenance worker.
 */
public class DatabaseMaintenanceWorkerType extends BaseWorkerType {

    private static final long serialVersionUID = 1L;

    public static final String NAME = "DATABASEMAINTENANCEWORKER";
    private static final String WORKER_SUB_PAGE = "databasemaintenanceworker.xhtml";

    private String delayTimeUnit  = DatabaseMaintenanceWorker.DEFAULT_DELAY_TIMEUNIT;
    private int delayTimeValue = DatabaseMaintenanceWorker.DEFAULT_DELAY_TIMEVALUE;
    private boolean deleteExpiredCertificates = true;
    private boolean deleteExpiredCrls = true;
    private int batchSize = DatabaseMaintenanceWorker.DEFAULT_BATCH_SIZE;

    public DatabaseMaintenanceWorkerType() {
        super(WORKER_SUB_PAGE, NAME, true, DatabaseMaintenanceWorker.class.getName());
        // No action available for this worker
        deleteAllCompatibleActionTypes();
        addCompatibleActionTypeName(NoActionType.NAME);
        // Only periodical interval available for this worker
        addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
    }

    @Override
    public Properties getProperties(final ArrayList<String> errorMessages) throws IOException {
        Properties ret = super.getProperties(errorMessages);
        ret.setProperty(DatabaseMaintenanceWorker.PROP_DELAY_TIMEUNIT, delayTimeUnit);
        ret.setProperty(DatabaseMaintenanceWorker.PROP_DELAY_TIMEVALUE, Integer.toString(delayTimeValue));
        ret.setProperty(DatabaseMaintenanceWorker.PROP_DELETE_EXPIRED_CERTIFICATES, Boolean.toString(deleteExpiredCertificates));
        ret.setProperty(DatabaseMaintenanceWorker.PROP_DELETE_EXPIRED_CRLS, Boolean.toString(deleteExpiredCrls));
        ret.setProperty(DatabaseMaintenanceWorker.PROP_BATCH_SIZE, Integer.toString(batchSize));
        return ret;
    }

    @Override
    public void setProperties(final Properties properties) throws IOException {
        super.setProperties(properties);
        delayTimeValue = PropertyTools.get(properties, DatabaseMaintenanceWorker.PROP_DELAY_TIMEVALUE, delayTimeValue);
        delayTimeUnit = properties.getProperty(DatabaseMaintenanceWorker.PROP_DELAY_TIMEUNIT, delayTimeUnit);
        deleteExpiredCertificates = PropertyTools.get(properties, DatabaseMaintenanceWorker.PROP_DELETE_EXPIRED_CERTIFICATES, deleteExpiredCertificates);
        deleteExpiredCrls = PropertyTools.get(properties, DatabaseMaintenanceWorker.PROP_DELETE_EXPIRED_CRLS, deleteExpiredCrls);
        batchSize = PropertyTools.get(properties, DatabaseMaintenanceWorker.PROP_BATCH_SIZE, batchSize);
    }

    public String getDelayTimeUnit() {
        return delayTimeUnit;
    }

    public void setDelayTimeUnit(final String delayTimeUnit) {
        this.delayTimeUnit = delayTimeUnit;
    }

    public int getDelayTimeValue() {
        return delayTimeValue;
    }

    public void setDelayTimeValue(final int delayTimeValue) {
        this.delayTimeValue = delayTimeValue;
    }

    public boolean isDeleteExpiredCertificates() {
        return deleteExpiredCertificates;
    }

    public void setDeleteExpiredCertificates(final boolean deleteExpiredCertificates) {
        this.deleteExpiredCertificates = deleteExpiredCertificates;
    }

    public boolean isDeleteExpiredCrls() {
        return deleteExpiredCrls;
    }

    public void setDeleteExpiredCrls(final boolean deleteExpiredCrls) {
        this.deleteExpiredCrls = deleteExpiredCrls;
    }

    public int getBatchSize() {
        return batchSize;
    }

    public void setBatchSize(final int batchSize) {
        this.batchSize = batchSize;
    }
}
