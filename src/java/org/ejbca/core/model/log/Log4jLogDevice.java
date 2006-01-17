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

import org.apache.log4j.Logger;
import org.apache.log4j.Priority;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Date;
import java.util.Properties;


/**
 * Implements a log device using Log4j, implementes the Singleton pattern.
 *
 * @version $Id: Log4jLogDevice.java,v 1.1 2006-01-17 20:28:08 anatom Exp $
 */
public class Log4jLogDevice implements ILogDevice, Serializable {

    /**
     * Log4j instance for Base
     */
    private static final Logger log = Logger.getLogger(Log4jLogDevice.class);


    /**
     * A handle to the unique Singleton instance.
     */
    private static Log4jLogDevice instance;


    /**
     * Initializes all internal data
     *
     * @param prop Arguments needed for the eventual creation of the object
     */

    protected Log4jLogDevice(Properties prop) throws Exception {
        // Do nothing
    }

    /**
     * Creates (if needed) the log device and returns the object.
     *
     * @param prop Arguments needed for the eventual creation of the object
     * @return An instance of the log device.
     */
    public static synchronized ILogDevice instance(Properties prop) throws Exception {
        if (instance == null) {
            instance = new Log4jLogDevice(prop);
        }
        return instance;
    }

    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment) {
        log(admininfo, caid, module, time, username, certificate, event, comment, null);
    }

    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) {

        String user = "No User Involved";
        String cert = "No Certificate Involved";
        String admin = "Administrator not known";

        if (username != null) {
            user = username;
        }

        if (certificate != null) {
            cert = certificate.getSerialNumber().toString(16) + ", issuer: " + certificate.getIssuerDN().toString();
        }

        if (admininfo.getAdminType() == Admin.TYPE_CLIENTCERT_USER) {
            admin = Admin.ADMINTYPETEXTS[Admin.TYPE_CLIENTCERT_USER] + ", Certificate SNR : " + admininfo.getAdminData();
        } else if (admininfo.getAdminType() == Admin.TYPE_PUBLIC_WEB_USER) {
            if (admininfo.getAdminData() != null) {
                if (!admininfo.getAdminData().equals(""))
                    admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER] + ", IP Address : " + admininfo.getAdminData();
            } else {
                admin = Admin.ADMINTYPETEXTS[Admin.TYPE_PUBLIC_WEB_USER];
            }
        } else {
            admin = Admin.ADMINTYPETEXTS[admininfo.getAdminType()];
        }

        Priority priority = Priority.INFO;
        String eventText = "";
        if (event >= LogEntry.EVENT_ERROR_BOUNDRARY) {
            priority = Priority.ERROR;
            event -= LogEntry.EVENT_ERROR_BOUNDRARY;
            eventText = LogEntry.EVENTNAMES_ERROR[event];
        }else{
        	eventText = LogEntry.EVENTNAMES_INFO[event];	
        }

        String logline = DateFormat.getDateTimeInstance(DateFormat.LONG, DateFormat.LONG).format(time) + ", CAId : " + caid + ", " + LogEntry.MODULETEXTS[module] + ", " + eventText + ", Administrator : " +
                admin + ", User : " + user + ", Certificate : " + cert + ", Comment : " + comment;
        log.log(priority, logline, null);

        if (exception != null) {
            log.error("Exception : ", exception);
        }
    }
}
