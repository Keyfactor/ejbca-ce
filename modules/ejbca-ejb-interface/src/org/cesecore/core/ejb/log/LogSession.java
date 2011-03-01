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
package org.cesecore.core.ejb.log;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;

import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.ILogExporter;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Interface for log session bean
 * 
 * @version $Id$
 */
public interface LogSession {

	/** @return a list of configured LogDevices. */
    Collection<String> getAvailableLogDevices();

    /** @return a list of configured LogDevices that can be used to retrieve LogEntries. */
    Collection<String> getAvailableQueryLogDevices();
    
    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param time the time the event occurred.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the org.ejbca.core.model.log.LogConstants.EVENT_ constants.
     * @param comment comment of the event.
     */
    void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment);

    /**
     * Same as above but with the difference of CAid which is taken from the
     * IssuerDN of given certificate.
     */
    void log(Admin admin, Certificate caid, int module, Date time, String username, Certificate certificate, int event, String comment);

    /**
     * Overloaded function that also logs an exception.
     * @param exception the exception that has occurred
     */
    void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception);

    /**
     * Overloaded function that also logs an exception. Takes the CAid from the
     * IssuerDN of given certificate.
     */
    void log(Admin admin, Certificate caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception);

    /**
     * Method to export log records according to a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @param logexporter is the obbject that converts the result set into the desired log format 
     * @return an exported byte array. Maximum number of exported entries is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT, returns null if there is nothing to export
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @throws Exception differs depending on the ILogExporter implementation
     * @see org.ejbca.util.query.Query
     */
    byte[] export(String deviceName, Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter,
            int maxResults) throws IllegalQueryException, Exception;

    /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statements compiled by query class to a SQL 'WHERE'-clause statement.
     * @param viewlogprivileges is a SQL query string returned by a LogAuthorization object.
     * @return a collection of LogEntry. Maximum size of Collection is defined i LogConstants.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fulfilled.
     * @see org.ejbca.util.query.Query
     */
    Collection<LogEntry> query(String deviceName, Query query, String viewlogprivileges, String capriviledges, int maxResults)
            throws IllegalQueryException;

    /** Save LogConfiguration with audit trail. */
	void saveLogConfiguration(Admin admin, int caid, LogConfiguration logconfiguration);
}
