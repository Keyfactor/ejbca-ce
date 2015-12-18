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
package org.ejbca.statedump.ejb;

import java.io.IOException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Statedump is an internal PrimeKey tool.
 * 
 * @version $Id$
 */
public interface StatedumpSession {
    
    static final String STATEDUMP_MODULE = "statedump-ejb";

    /**
     * Performs a dry run import (nothing is done) of a statedump, and returns an object with lists of
     * all conflicts due to already existing items and items that need a password to be specified.  
     * 
     * @param admin The authentication token. Must have / access, and of course access to create each item to import.
     * @param options Options. Must specify a location.
     * @return Result object with lists of conflicts and items that need a password.
     * @throws AuthorizationDeniedException
     * @throws IOException If the files in the dump are malformed.
     */
    StatedumpImportResult performDryRun(AuthenticationToken admin, StatedumpImportOptions options) throws AuthorizationDeniedException, IOException;
    
    /**
     * Performs an import of a statedump.  
     * 
     * @param admin The authentication token. Must have / access, and of course access to create each item to import.
     * @param options Options. Specifies location, lists of items to overwrite / not overwrite, passwords and other options.
     * @return Result object with lists of conflicts and items that need a password.
     * @throws AuthorizationDeniedException
     * @throws IOException If the files in the dump are malformed.
     */
    StatedumpImportResult performImport(AuthenticationToken admin, StatedumpImportOptions options) throws AuthorizationDeniedException, IOException;

}
