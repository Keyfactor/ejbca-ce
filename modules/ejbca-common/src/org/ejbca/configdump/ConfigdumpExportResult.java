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

import java.util.List;
import java.util.Optional;

/**
 * Holds information about the status of a Configdump export operation.
 * @version $Id$
 */
public final class ConfigdumpExportResult extends ConfigdumpResult {
    
    private static final long serialVersionUID = 1L;
    private byte[] output = null;
    private boolean nothingExported = false;
    
    public ConfigdumpExportResult(final List<String> reportedErrors, final List<String> reportedWarnings) {
        super(reportedErrors, reportedWarnings);
    }

    public ConfigdumpExportResult(final List<String> reportedErrors, final List<String> reportedWarnings, byte[] output, boolean nothingExported) {
        this(reportedErrors, reportedWarnings);
        this.output = output;
        this.nothingExported = nothingExported;
    }

    public Optional<byte[]> getOutput() {
        return Optional.ofNullable(output);
    }

    public boolean isNothingExported() {
        return nothingExported;
    }
    
}
