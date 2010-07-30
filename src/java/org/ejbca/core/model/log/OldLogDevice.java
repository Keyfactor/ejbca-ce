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

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.log.OldLogSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Implements a log device using the old logging system, implements the Singleton pattern.
 * @version $Id$
 */
public class OldLogDevice implements ILogDevice, Serializable {
	
	public final static String DEFAULT_DEVICE_NAME = "OldLogDevice";
	
	/** Internal localization of logs and errors */
	private static final InternalResources intres = InternalResources.getInstance();

	private static final Logger log = Logger.getLogger(OldLogDevice.class);
	
	private OldLogSession oldLogSession;

	/**
	 * A handle to the unique Singleton instance.
	 */
	private static ILogDevice instance;

    private String deviceName = null;

    /**
	 * Initializes
	 */
	protected OldLogDevice(String name) throws Exception {
		resetDevice(name);
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public void resetDevice(String name) {
		deviceName = name;
		EjbLocalHelper ejb = new EjbLocalHelper();
		try {
			oldLogSession = ejb.getOldLogSession();
		} catch (CreateException e) {
			throw new EJBException();
		}
	}

	/**
	 * Creates (if needed) the log device and returns the object.
	 *
	 * @param prop Arguments needed for the eventual creation of the object
	 * @return An instance of the log device.
	 */
	public static synchronized ILogDevice instance(String name) throws Exception {
		if (instance == null) {
			instance = new OldLogDevice(name);
		}
		return instance;
	}
	
    /**
     * Log everything in the database using the log entity bean
     */
	public void log(Admin admin, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception) {
		if (exception != null) {
			comment += ", Exception: " + exception.getMessage();
		}
		boolean successfulLog = false;
    	int tries = 0;
    	do {
    		try {
    			oldLogSession.log(admin, caid, module, time, username, certificate, event, comment, exception);
    			successfulLog = true;
    		} catch (Throwable e) {
    			tries++;
    			if(tries == 3){
        			// We are losing a db audit entry in this case.
    				String msg = intres.getLocalizedMessage("log.errormissingentry");            	
    				log.error(msg,e);
    			}else{
    				String msg = intres.getLocalizedMessage("log.warningduplicatekey");            	
    				log.warn(msg);
    			}
    			
    		}
    	} while (!successfulLog && tries < 3);
    }

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public String getDeviceName() {
		return deviceName;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public byte[] export(Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter, int maxResults) throws IllegalQueryException, Exception {
		byte[] ret = null;
		if (query != null) {
			Collection logentries = query(query, viewlogprivileges, capriviledges, maxResults);
			if (log.isDebugEnabled()) {
				log.debug("Found "+logentries.size()+" entries when exporting");    		
			}
			logexporter.setEntries(logentries);
			ret = logexporter.export(admin);
		}
		return ret;
	}

	/**
	 * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
	 *
	 * @param query a number of statements compiled by query class to a SQL 'WHERE'-clause statement.
	 * @param viewlogprivileges is a SQL query string returned by a LogAuthorization object.
	 * @param maxResults Maximum size of Collection
	 * @return a collection of LogEntry.
	 * @throws IllegalQueryException when query parameters internal rules isn't fulfilled.
	 * @see org.ejbca.util.query.Query
	 */
	public Collection query(Query query, String viewlogprivileges, String capriviledges, int maxResults) throws IllegalQueryException {
		return oldLogSession.query(query, viewlogprivileges, capriviledges, maxResults);
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public void destructor() {
		// No action needed
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public boolean getAllowConfigurableEvents() {
		return true;
	}
}
