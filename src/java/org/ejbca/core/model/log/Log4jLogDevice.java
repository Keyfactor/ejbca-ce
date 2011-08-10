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

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.cesecore.certificates.util.CertTools;
import org.ejbca.config.ConfigurationHolder;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.util.ValidityDate;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;


/**
 * Implements a log device using Log4j, implements the Singleton pattern.
 *
 * @version $Id$
 */
public class Log4jLogDevice implements ILogDevice, Serializable {

	public final static String DEFAULT_DEVICE_NAME	= "Log4jLogDevice";

    /** Log4j instance  */
    private static final Logger log = Logger.getLogger(Log4jLogDevice.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /**
     * A handle to the unique Singleton instance.
     */
    private static Log4jLogDevice instance;

	private String deviceName = null;

    /**
     * Initializes all internal data
     *
     * @param prop Arguments needed for the eventual creation of the object
     */

    protected Log4jLogDevice(String name) throws Exception {
		deviceName = name;
    }
    
    /**
     * Creates (if needed) the log device and returns the object.
     *
     * @return An instance of the log device.
     */
    public static synchronized ILogDevice instance(String name) throws Exception {
        if (instance == null) {
            instance = new Log4jLogDevice(name);
        }
        return instance;
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
    public void log(Admin admininfo, int caid, int module, Date time, String username, Certificate certificate, int event, String comment, Exception exception) {

    	String user = intres.getLocalizedMessage("log.nouserinvolved");
    	String cert = intres.getLocalizedMessage("log.nocertinvolved");
    	String admin = intres.getLocalizedMessage("log.adminnotknown");

        if (username != null) {
            user = username;
        }
        
        String admindata = admininfo.getAdminData();

        if (certificate != null) {
        	cert = CertTools.getSerialNumberAsString(certificate) + " : issuer: \"" + CertTools.getIssuerDN(certificate)+"\"";
        	if(event == LogConstants.EVENT_ERROR_ADMINISTRATORLOGGEDIN){
        		admindata += " : CertDN : \"" + CertTools.getSubjectDN(certificate) + "\"";
        	}
        }

        if (admininfo.getAdminType() == Admin.TYPE_CLIENTCERT_USER) {
            admin = Admin.ADMINTYPETEXTS[Admin.TYPE_CLIENTCERT_USER] + " : Certificate SNR : " + admininfo.getAdminData();
        } else if (admininfo.getAdminType() == Admin.TYPE_PUBLIC_WEB_USER) {
            if (admininfo.getAdminData() != null) {
                if (!admininfo.getAdminData().equals("")) {
                    admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER] + " : IP Address : " + admininfo.getAdminData();
                }
            } else {
                admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER];
            }
        } else {
            admin = Admin.ADMINTYPETEXTS[admininfo.getAdminType()];
        }

        Priority priority = Level.INFO;
        String eventText = "";
        if (event >= LogConstants.EVENT_SYSTEM_BOUNDRARY) {
            event -= LogConstants.EVENT_SYSTEM_BOUNDRARY;
            eventText = LogConstants.EVENTNAMES_SYSTEM[event];
        } else if (event >= LogConstants.EVENT_ERROR_BOUNDRARY) {
            priority = Level.ERROR;
            event -= LogConstants.EVENT_ERROR_BOUNDRARY;
            eventText = LogConstants.EVENTNAMES_ERROR[event];
        }else{
        	eventText = LogConstants.EVENTNAMES_INFO[event];	
        }
        
        String timePattern = ConfigurationHolder.getString("log4j.timepattern", ValidityDate.ISO8601_DATE_FORMAT);
         
        String logline = FastDateFormat.getInstance(timePattern).format(time) + ", CAId : " + caid + ", " + LogConstants.MODULETEXTS[module] + ", " + eventText + ", Administrator : " +
                admin + ", User : " + user + ", Certificate : " + cert + ", Comment : " + comment;
        log.log(priority, logline, null);

        if (exception != null) {
            log.log(priority, "Exception : ", exception);
        }
    }

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public byte[] export(Admin admin, Query query, String viewlogprivileges, String capriviledges, ILogExporter logexporter, int maxResults) throws IllegalQueryException, Exception {
		// Does not make sense to implement.. just return null
		return null;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public Collection<LogEntry> query(Query query, String viewlogprivileges, String capriviledges, int maxResults) throws IllegalQueryException {
		// Does not make sense to implement.. just return null
		return null;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	public boolean getAllowConfigurableEvents() {
		return true;
	}

	/**
	 * @see org.ejbca.core.model.log.ILogDevice
	 */
	@Override
	public boolean isSupportingQueries() {
		return false;
	}
}
