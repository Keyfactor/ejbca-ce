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

import org.ejbca.core.model.services.workers.CRLDownloadWorker;

/**
 * Web UI backing object for configuration of the CRLDownloadWorker.
 * 
 * @version $Id$
 */
public class CRLDownloadWorkerType extends BaseWorkerType {
    
    private static final long serialVersionUID = 1L;
    
    public static final String NAME = "CRLDOWNLOADWORKER";
    
    private boolean ignoreNextUpdate = false;
    private String maxDownloadSize = String.valueOf(CRLDownloadWorker.DEFAULT_MAX_DOWNLOAD_SIZE);

    public CRLDownloadWorkerType() {
        super("crldownloadworker.jsp", NAME, true, CRLDownloadWorker.class.getName());
        // No action available for this worker
        addCompatibleActionTypeName(NoActionType.NAME);     
        // Only periodical interval available for this worker
        addCompatibleIntervalTypeName(PeriodicalIntervalType.NAME);
    }

    /** @return true if the nextUpdate field of the CRL should be ignored and the CRL should always be downloaded to see if there is a newer version. */
    public boolean isIgnoreNextUpdate() {
        return ignoreNextUpdate;
    }

    /** Set to true if the nextUpdate field of the CRL should be ignored and the CRL should always be downloaded to see if there is a newer version. */
    public void setIgnoreNextUpdate(final boolean ignoreNextUpdate) {
        this.ignoreNextUpdate = ignoreNextUpdate;
    }

    /** @return the size of the largest CRL that we will try to download. */
    public String getMaxDownloadSize() {
        return maxDownloadSize;
    }

    /** Set the size of the largest CRL that we will try to download. */
    public void setMaxDownloadSize(String maxDownloadSize) {
        this.maxDownloadSize = maxDownloadSize;
    }

    @Override
    public Properties getProperties(final ArrayList<String> errorMessages) throws IOException {
        Properties ret = super.getProperties(errorMessages);
        ret.setProperty(CRLDownloadWorker.PROP_IGNORE_NEXT_UPDATE, Boolean.toString(ignoreNextUpdate));
        try {
            final int i = Integer.parseInt(maxDownloadSize);
            if (i>1024) {
                ret.setProperty(CRLDownloadWorker.PROP_MAX_DOWNLOAD_SIZE, maxDownloadSize);
            } else {
                maxDownloadSize = String.valueOf(CRLDownloadWorker.DEFAULT_MAX_DOWNLOAD_SIZE);
            }
        } catch (NumberFormatException e) {
            errorMessages.add("Invalid maximum download size.");
        }
        return ret;
    }
    
    @Override
    public void setProperties(Properties properties) throws IOException {
        super.setProperties(properties);
        ignoreNextUpdate = Boolean.valueOf(properties.getProperty(CRLDownloadWorker.PROP_IGNORE_NEXT_UPDATE, Boolean.valueOf(ignoreNextUpdate).toString()));
        maxDownloadSize = properties.getProperty(CRLDownloadWorker.PROP_MAX_DOWNLOAD_SIZE, maxDownloadSize);
    }
}
