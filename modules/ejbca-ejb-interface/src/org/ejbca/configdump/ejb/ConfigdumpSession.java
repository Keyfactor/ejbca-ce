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
package org.ejbca.configdump.ejb;

import java.io.IOException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.ejbca.configdump.ConfigDumpSetting;
import org.ejbca.configdump.ConfigdumpException;
import org.ejbca.configdump.ConfigdumpExportResult;

/**
 * Interface for exporting (and the future, importing) data with Configdump.
 * 
 * @version $Id$
 */
public interface ConfigdumpSession {
    
    static final String CONFIGDUMP_MODULE = "configdump-ejb";
    
    /**
     * Exports EJBCA data, except for keys and certificates, to a set of YAML files.
     * One YAML file is created per "item" in the database (e.g. a certificate profile).
     * @param admin Authentication token of the requesting admin (for the Configdump CLI, this is a CLI authentication token).
     * @param setting Settings such as export directory, and items to include in the export
     * @return Result object. In case errors are set to be ignored, then this contains a list of errors.
     * @throws ConfigdumpException If an error occurs, which was not ignored.
     * @throws IOException On failure to create the YAML files etc.
     */
    ConfigdumpExportResult performExport(final AuthenticationToken admin, final ConfigDumpSetting setting) throws ConfigdumpException, IOException;

}
