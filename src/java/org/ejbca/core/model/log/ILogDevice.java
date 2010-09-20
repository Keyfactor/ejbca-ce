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

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;

import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Interface used by EJBCA external log devices such as Log4j.
 * @version $Id$
 */
public interface ILogDevice extends Serializable {

	public final String PROPERTY_DEVICENAME = "deviceName";
	
    /**
     * Log information.
     * 
     * If the log device uses database, the device is responsible for starting a new transaction and committing the log data before returning.
     * 
     * @param admininfo contains information about the administrator performing the event.
     * @param caid the id of the catch (connected to the event.
     * @param module indicates the module using the bean.
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the org.ejbca.core.model.log.LogConstants.EVENT_ constants.
     * @param comment comment of the event.
     * @param exception the exception that has occurred (can be null)
     */
    public void log(Admin admininfo, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception);
    
    /**
     * Method to export log records according to a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statements compiled by query class to a SQL 'WHERE'-clause statement.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @param logexporter is the object that converts the result set into the desired log format 
     * @param maxResults maximum number of exported entries
     * @return an exported byte array. returns null if there is nothing to export
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @throws Exception differs depending on the ILogExporter implementation
     * @see org.ejbca.util.query.Query
     */
    public byte[] export(Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter, int maxResults) throws IllegalQueryException, Exception;
    	
    /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     *
     * @param query a number of statements compiled by query class to a SQL 'WHERE'-clause statement.
     * @param viewlogprivileges is a SQL query string returned by a LogAuthorization object.
     * @param maxResults Maximum size of the returned Collection
     * @return a collection of LogEntry.
     * @throws IllegalQueryException when query parameters internal rules isn't fulfilled.
     * @see org.ejbca.util.query.Query
     */
    public Collection<LogEntry> query(Query query, String viewlogprivileges, String capriviledges, int maxResults) throws IllegalQueryException;

	/**
	 * @return true if this device uses the internal log configuration framework
	 */
	public boolean getAllowConfigurableEvents();

	/**
	 * @return the name the device
	 */
	public String getDeviceName();
}
