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

import org.ejbca.configdump.ConfigdumpException;

/**
 * Configdump is an internal PrimeKey tool.
 * 
 * @version $Id$
 */
public interface ConfigdumpSession {
    
    static final String CONFIGDUMP_MODULE = "configdump-ejb";
    
    void performExport() throws ConfigdumpException, IOException;

}
