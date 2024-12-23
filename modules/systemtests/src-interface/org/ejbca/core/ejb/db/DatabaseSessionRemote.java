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
package org.ejbca.core.ejb.db;

import jakarta.ejb.Remote;

/**
 * Remote interface to allow access to local methods from system tests
 * 
 * @version $Id$
 *
 */
@Remote
public interface DatabaseSessionRemote {

    /**
     * Removes all records in a number of tables and stores them locally.
     * Removes and returns the content of the database except for the following tables:
     *   AuditRecordData
     *   CAData
     *   CRLData
     *   CertificateData
     *   CryptoTokenData
     *   GlobalConfigurationData
     *   RoleData
     *   RoleMemberData
     *   UserData
     *
     * @return
     */
    DatabaseContent clearTables(boolean clearProtectedTables);


    /**
     * Restores all records in the tables that were cleared.
     */
    void restoreTables(DatabaseContent databaseContent);

}
