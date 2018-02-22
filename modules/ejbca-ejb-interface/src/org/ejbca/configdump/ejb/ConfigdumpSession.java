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
 * Configdump is an internal PrimeKey tool.
 * 
 * @version $Id$
 */
public interface ConfigdumpSession {
    
    static final String CONFIGDUMP_MODULE = "configdump-ejb";
    
    ConfigdumpExportResult performExport(final AuthenticationToken admin, final ConfigDumpSetting setting) throws ConfigdumpException, IOException;

}
