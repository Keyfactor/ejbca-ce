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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.workers.PreCertificateRevocationWorkerConstants;

/**
 * See PreCertificateRevocationWorker (available in Enterprise Edition only)
 */
public class PreCertificateRevocationWorkerType extends BaseWorkerType {

    public static final String NAME = "PRECERTIFICATEREVOCATIONWORKER";

    private static final long serialVersionUID = 1;

    private static final String PRECERTIFICATEREVOCATIONWORKER_SUB_PAGE = "precertificaterevocationworker.xhtml";
    
    private int maxCertAge = 60;
    private String maxIssuanceTimeUnit = IWorker.UNIT_MINUTES;

    public PreCertificateRevocationWorkerType() {
        super(PRECERTIFICATEREVOCATIONWORKER_SUB_PAGE, NAME, true, PreCertificateRevocationWorkerConstants.WORKER_CLASS);
        // No action available for this worker
        deleteAllCompatibleActionTypes();
        addCompatibleActionTypeName(NoActionType.NAME);
        addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
    }

    /** @return The maximum issuance time before the certificate is considered failed, and revoked */
    public int getMaxIssuanceTime() {
        return maxCertAge;
    }

    /** Sets the maximum issuance time before the certificate is considered failed, and revoked */
    public void setMaxIssuanceTime(int maxCertAge) {
        this.maxCertAge = maxCertAge;
    }

    public String getMaxIssuanceTimeUnit() {
        return maxIssuanceTimeUnit;
    }

    public void setMaxIssuanceTimeUnit(final String maxIssuanceTimeUnit) {
        this.maxIssuanceTimeUnit = maxIssuanceTimeUnit;
    }

    @Override
    public Properties getProperties(final ArrayList<String> errorMessages) throws IOException {
        Properties ret = super.getProperties(errorMessages);
        ret.setProperty(PreCertificateRevocationWorkerConstants.PROP_MAX_ISSUANCE_TIME, String.valueOf(maxCertAge));
        ret.setProperty(PreCertificateRevocationWorkerConstants.PROP_MAX_ISSUANCE_TIMEUNIT, maxIssuanceTimeUnit);
        return ret;
    }

    @Override
    public void setProperties(Properties properties) throws IOException {
        super.setProperties(properties);
        maxCertAge = Integer.valueOf(properties.getProperty(PreCertificateRevocationWorkerConstants.PROP_MAX_ISSUANCE_TIME, String.valueOf(maxCertAge)));
        maxIssuanceTimeUnit = properties.getProperty(PreCertificateRevocationWorkerConstants.PROP_MAX_ISSUANCE_TIMEUNIT, maxIssuanceTimeUnit);
    }

}
