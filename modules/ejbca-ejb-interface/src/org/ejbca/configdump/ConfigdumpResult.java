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
package org.ejbca.configdump;

import java.io.Serializable;
import java.util.List;

/**
 * Base class for the result of a Configdump operation (import/export).
 * @see ConfigdumpExportResult
 * @see ConfigdumpImportResult
 * @version $Id$
 */
public abstract class ConfigdumpResult implements Serializable {
    private static final long serialVersionUID = 1L;
    private final List<String> reportedErrors;
    private final List<String> reportedWarnings;

    public ConfigdumpResult(final List<String> reportedErrors, final List<String> reportedWarnings) {
        this.reportedErrors = reportedErrors;
        this.reportedWarnings = reportedWarnings;
    }
    
    public List<String> getReportedErrors() {
        return reportedErrors;
    }
    
    public List<String> getReportedWarnings() {
        return reportedWarnings;
    }
    
    public boolean isSuccessful() {
        return reportedErrors.isEmpty();
    }
}
