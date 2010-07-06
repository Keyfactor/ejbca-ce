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
package org.ejbca.core.ejb.ra.userdatasource;

import javax.ejb.Remote;

/**
 * Remote interface for UserDataSourceSession.
 */
@Remote
public interface UserDataSourceSessionRemote {
    /**
     * Main method used to fetch userdata from the given user data sources See
     * BaseUserDataSource class for further documentation about function Checks
     * that the administrator is authorized to fetch userdata.
     * 
     * @param userdatasourceids
     *            a Collection (Integer) of userdatasource Ids.
     * @return Collection of UserDataSourceVO, empty if no userdata could be
     *         found.
     * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
     */
    public java.util.Collection fetch(org.ejbca.core.model.log.Admin admin, java.util.Collection userdatasourceids, java.lang.String searchstring)
            throws org.ejbca.core.model.authorization.AuthorizationDeniedException, org.ejbca.core.model.ra.userdatasource.UserDataSourceException,
            java.rmi.RemoteException;

    /**
     * method used to remove userdata from the given user data sources. This
     * functionality is optianal of a user data implementation and is not
     * certain it is implemented See BaseUserDataSource class for further
     * documentation about function Checks that the administrator is authorized
     * to remove userdata.
     * 
     * @param userdatasourceids
     *            a Collection (Integer) of userdatasource Ids.
     * @return true if the user was remove successfully from at least one of the
     *         user data sources.
     * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
     */
    public boolean removeUserData(org.ejbca.core.model.log.Admin admin, java.util.Collection userdatasourceids, java.lang.String searchstring,
            boolean removeMultipleMatch) throws org.ejbca.core.model.authorization.AuthorizationDeniedException,
            org.ejbca.core.model.ra.userdatasource.MultipleMatchException, org.ejbca.core.model.ra.userdatasource.UserDataSourceException,
            java.rmi.RemoteException;

    /**
     * Test the connection to a user data source
     * 
     * @param userdatasourceid
     *            the id of the userdatasource to test.
     * @see org.ejbca.core.model.ra.userdatasource.BaseUserDataSource
     */
    public void testConnection(org.ejbca.core.model.log.Admin admin, int userdatasourceid)
            throws org.ejbca.core.model.ra.userdatasource.UserDataSourceConnectionException, java.rmi.RemoteException;

    /**
     * Adds a user data source to the database.
     * 
     * @throws UserDataSourceExistsException
     *             if user data source already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addUserDataSource(org.ejbca.core.model.log.Admin admin, java.lang.String name,
            org.ejbca.core.model.ra.userdatasource.BaseUserDataSource userdatasource)
            throws org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException, java.rmi.RemoteException;

    /**
     * Adds a user data source to the database. Used for importing and exporting
     * profiles from xml-files.
     * 
     * @throws UserDataSourceExistsException
     *             if user data source already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void addUserDataSource(org.ejbca.core.model.log.Admin admin, int id, java.lang.String name,
            org.ejbca.core.model.ra.userdatasource.BaseUserDataSource userdatasource)
            throws org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException, java.rmi.RemoteException;

    /**
     * Updates user data source data
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void changeUserDataSource(org.ejbca.core.model.log.Admin admin, java.lang.String name,
            org.ejbca.core.model.ra.userdatasource.BaseUserDataSource userdatasource) throws java.rmi.RemoteException;

    /**
     * Adds a user data source with the same content as the original.
     * 
     * @throws UserDataSourceExistsException
     * @throws UserDataSourceExistsException
     *             if user data source already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void cloneUserDataSource(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname)
            throws org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException, java.rmi.RemoteException;

    /**
     * Removes a user data source from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public boolean removeUserDataSource(org.ejbca.core.model.log.Admin admin, java.lang.String name) throws java.rmi.RemoteException;

    /**
     * Renames a user data source
     * 
     * @throws UserDataSourceExistsException
     *             if user data source already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public void renameUserDataSource(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname)
            throws org.ejbca.core.model.ra.userdatasource.UserDataSourceExistsException, java.rmi.RemoteException;

    /**
     * Retrives a Collection of id:s (Integer) to authorized user data sources.
     * 
     * @param indicates
     *            if sources with anyca set should be included
     * @return Collection of id:s (Integer)
     */
    public java.util.Collection getAuthorizedUserDataSourceIds(org.ejbca.core.model.log.Admin admin, boolean includeAnyCA) throws java.rmi.RemoteException;

    /**
     * Method creating a hashmap mapping user data source id (Integer) to user
     * data source name (String).
     */
    public java.util.HashMap getUserDataSourceIdToNameMap(org.ejbca.core.model.log.Admin admin) throws java.rmi.RemoteException;

    /**
     * Retrives a named user data source.
     */
    public org.ejbca.core.model.ra.userdatasource.BaseUserDataSource getUserDataSource(org.ejbca.core.model.log.Admin admin, java.lang.String name)
            throws java.rmi.RemoteException;

    /**
     * Finds a user data source by id.
     */
    public org.ejbca.core.model.ra.userdatasource.BaseUserDataSource getUserDataSource(org.ejbca.core.model.log.Admin admin, int id)
            throws java.rmi.RemoteException;

    /**
     * Help method used by user data source proxys to indicate if it is time to
     * update it's data.
     */
    public int getUserDataSourceUpdateCount(org.ejbca.core.model.log.Admin admin, int userdatasourceid) throws java.rmi.RemoteException;

    /**
     * Returns a user data source id, given it's user data source name
     * 
     * @return the id or 0 if the user data source cannot be found.
     */
    public int getUserDataSourceId(org.ejbca.core.model.log.Admin admin, java.lang.String name) throws java.rmi.RemoteException;

    /**
     * Returns a user data source name given its id.
     * 
     * @return the name or null if id doesnt exists
     * @throws EJBException
     *             if a communication or other error occurs.
     */
    public java.lang.String getUserDataSourceName(org.ejbca.core.model.log.Admin admin, int id) throws java.rmi.RemoteException;
}
