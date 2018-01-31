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
package org.ejbca.configdump;

import java.io.Serializable;
import java.util.List;

/**
 * Holds information about the status of a Configdump export operation.
 * @version $Id$
 */
public final class ConfigdumpExportResult implements Serializable {
    
    private static final long serialVersionUID = 1L;
    
    private final List<String> reportedErrors;
    
    public ConfigdumpExportResult(final List<String> reportedErrors) {
        this.reportedErrors = reportedErrors;
    }
    
    public List<String> getReportedErrors() {
        return reportedErrors;
    }
    
    public boolean isSuccessful() {
        return reportedErrors.isEmpty();
    }
    
}
