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

    /** Creates and sets the actual database integrity protection, or does nothing 
     * @throws DatabaseProtectionException if database protection is enabled, and the audit log does not function*/
    void protectData(ProtectedData obj) throws DatabaseProtectionException;

    /** Reads and verifies the actual database integrity protection, or does nothing 
     * @throws DatabaseProtectionException */
    void verifyData(ProtectedData obj) throws DatabaseProtectionException;

    /**
     * Verifies that <code>protectedData</code> is correct. Otherwise, it throws a <code>DatabaseProtectionException</code>.
     * @param unProtectedData The unprotected data that is to be signed
     * @param protectedData The signed value from the database
     * @param beanName The name of the Java bean
     * @param rowId The String representation of the database row.
     * @throws DatabaseProtectionException If the unProtectedData is not correct.
     */
    void verifyData(final String unProtectedData, final String protectedData, final String beanName, final String rowId) throws DatabaseProtectionException;

    /**
     * 
     * @param obj
     * @return
     * @throws DatabaseProtectionException if database protection is enabled, and the audit log does not function
     */
    String calculateProtection(final ProtectedData obj) throws DatabaseProtectionException;

    /**
     * @param rowVersion The version to use
     * @param unProtectedData The concatenated value that is to be protected
     * @return The protected String that is to be stored in the database or to be compared with the stored value.
     */
    String getProtectedData(final Integer rowVersion, final String unProtectedData) throws DatabaseProtectionException;

    /**
     * Throws DatabaseProtectionException if erroronverifyfail is enabled in databaseprotection.properties
     * and logs a "row protection failed" message on ERROR level.
     * @throws DatabaseProtectionException if database protection and erroronverifyfail is enabled, and the audit log does not function
     * @throws the exception given as parameter if erroronverifyfail is enabled
     */
    void onDataVerificationError(final DatabaseProtectionException e) throws DatabaseProtectionException;

}
