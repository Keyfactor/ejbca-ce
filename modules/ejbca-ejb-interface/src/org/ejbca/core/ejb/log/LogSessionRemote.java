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
package org.ejbca.core.ejb.log;

/**
 * Remote interface for LogSession.
 */
public interface LogSessionRemote {

    public java.util.Collection getAvailableLogDevices() throws java.rmi.RemoteException;

    /**
     * Replace existing devices with a new one. Used for testing, since the
     * JUnit has to inject a mock xxxLogDevice.
     */
    public void setTestDevice(java.lang.Class implClass, java.lang.String name) throws java.rmi.RemoteException;

    /**
     * Replace existing devices with a new one in this LogSessionBean. Used for
     * testing, since the JUnit has to inject a mock xxxLogDevice.
     */
    public void restoreTestDevice() throws java.rmi.RemoteException;

    /**
     * Replace existing devices with a new one in this beans LogSession
     * reference. Used for testing, since the JUnit has to inject a mock
     * ProtectedLogDevice in both the instance accessed remotly and also the
     * local instance accessed by this bean to be able to use the container
     * managed transations.
     */
    public void setTestDeviceOnLogSession(java.lang.Class implClass, java.lang.String name) throws java.rmi.RemoteException;

    /**
     * Replace existing devices with the original ones in this beans LogSession
     * reference. Used for testing, since the JUnit has to inject a mock
     * ProtectedLogDevice in both the instance accessed remotly and also the
     * local instance accessed by this bean to be able to use the container
     * managed transations.
     */
    public void restoreTestDeviceOnLogSession() throws java.rmi.RemoteException;

    /**
     * Session beans main function. Takes care of the logging functionality.
     * 
     * @param admin
     *            the administrator performing the event.
     * @param time
     *            the time the event occured.
     * @param username
     *            the name of the user involved or null if no user is involved.
     * @param certificate
     *            the certificate involved in the event or null if no
     *            certificate is involved.
     * @param event
     *            id of the event, should be one of the
     *            org.ejbca.core.model.log.LogConstants.EVENT_ constants.
     * @param comment
     *            comment of the event.
     */
    public void log(org.ejbca.core.model.log.Admin admin, int caid, int module, java.util.Date time, java.lang.String username,
            java.security.cert.Certificate certificate, int event, java.lang.String comment) throws java.rmi.RemoteException;

    /**
     * Same as above but with the difference of CAid which is taken from the
     * issuerdn of given certificate.
     */
    public void log(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate caid, int module, java.util.Date time, java.lang.String username,
            java.security.cert.Certificate certificate, int event, java.lang.String comment) throws java.rmi.RemoteException;

    /**
     * Overloaded function that also logs an exception See function above for
     * more documentation.
     * 
     * @param exception
     *            the exception that has occured
     */
    public void log(org.ejbca.core.model.log.Admin admin, int caid, int module, java.util.Date time, java.lang.String username,
            java.security.cert.Certificate certificate, int event, java.lang.String comment, java.lang.Exception exception) throws java.rmi.RemoteException;

    /**
     * Same as above but with the difference of CAid which is taken from the
     * issuerdn of given certificate.
     */
    public void log(org.ejbca.core.model.log.Admin admin, java.security.cert.Certificate caid, int module, java.util.Date time, java.lang.String username,
            java.security.cert.Certificate certificate, int event, java.lang.String comment, java.lang.Exception exception) throws java.rmi.RemoteException;

    /**
     * Method to export log records according to a customized query on the log
     * db data. The parameter query should be a legal Query object.
     * 
     * @param query
     *            a number of statments compiled by query class to a SQL
     *            'WHERE'-clause statment.
     * @param viewlogprivileges
     *            is a sql query string returned by a LogAuthorization object.
     * @param logexporter
     *            is the obbject that converts the result set into the desired
     *            log format
     * @return an exported byte array. Maximum number of exported entries is
     *         defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT, returns null if
     *         there is nothing to export
     * @throws IllegalQueryException
     *             when query parameters internal rules isn't fullfilled.
     * @throws Exception
     *             differs depending on the ILogExporter implementation
     * @see org.ejbca.util.query.Query
     */
    public byte[] export(java.lang.String deviceName, org.ejbca.core.model.log.Admin admin, org.ejbca.util.query.Query query,
            java.lang.String viewlogprivileges, java.lang.String capriviledges, org.ejbca.core.model.log.ILogExporter logexporter, int maxResults)
            throws org.ejbca.util.query.IllegalQueryException, java.lang.Exception, java.rmi.RemoteException;

    /**
     * Method to execute a customized query on the log db data. The parameter
     * query should be a legal Query object.
     * 
     * @param query
     *            a number of statments compiled by query class to a SQL
     *            'WHERE'-clause statment.
     * @param viewlogprivileges
     *            is a sql query string returned by a LogAuthorization object.
     * @return a collection of LogEntry. Maximum size of Collection is defined i
     *         LogConstants.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException
     *             when query parameters internal rules isn't fullfilled.
     * @see org.ejbca.util.query.Query
     */
    public java.util.Collection query(java.lang.String deviceName, org.ejbca.util.query.Query query, java.lang.String viewlogprivileges,
            java.lang.String capriviledges, int maxResults) throws org.ejbca.util.query.IllegalQueryException, java.rmi.RemoteException;

    /**
     * Loads the log configuration from the database.
     * 
     * @return the logconfiguration
     */
    public org.ejbca.core.model.log.LogConfiguration loadLogConfiguration(int caid) throws java.rmi.RemoteException;

    /**
     * Saves the log configuration to the database.
     * 
     * @param logconfiguration
     *            the logconfiguration to save.
     */
    public void saveLogConfiguration(org.ejbca.core.model.log.Admin admin, int caid, org.ejbca.core.model.log.LogConfiguration logconfiguration)
            throws java.rmi.RemoteException;

    /**
     * Methods for testing that a log-row is never rolled back if the rest of
     * the transaction is.
     */
    public void testRollbackInternal(long rollbackTestTime) throws java.rmi.RemoteException;
}
