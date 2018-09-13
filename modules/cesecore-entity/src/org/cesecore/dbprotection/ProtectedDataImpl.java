/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.dbprotection;


/** Interface that is inherited by actual implementations used to provide database integrity protection.
 * 
 * @version $Id$
 */
public interface ProtectedDataImpl {

    /** Sets the table name if the entity being protected */
    void setTableName(final String table);

    /** Creates and sets the actual database integrity protection, or does nothing */
    void protectData(ProtectedData obj);

    /** Reads and verifies the actual database integrity protection, or does nothing */
    void verifyData(ProtectedData obj);
	
    String calculateProtection(final ProtectedData obj);

    /**
     * Throws DatabaseProtectionException if erroronverifyfail is enabled in databaseprotection.properties
     * and logs a "row protection failed" message on ERROR level.
     * @throws the exception given as parameter if erroronverifyfail is enabled
     */
    void onDataVerificationError(final DatabaseProtectionException e);

}
