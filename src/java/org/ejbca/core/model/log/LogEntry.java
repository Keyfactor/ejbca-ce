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

/*
 * LogEntry.java
 *
 * Created on den 28 aug 2002, 10:02
 */

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.Date;

/**
 *  This is a  class containing information about one log event in the database. Used mainly during database queries by the web interface.
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class LogEntry implements Serializable {

    // Indicates the type of administrator.
    /** An administrator authenticated with client certificate */
    public static final int TYPE_CLIENTCERT_USER = 0;
    /** A user of the public web pages */
    public static final int TYPE_PUBLIC_WEB_USER = 1;
    /** An internal RA function, such as cmd line or CMP */
    public static final int TYPE_RA_USER = 2;
    /** An internal CA admin function, such as cms line */
    public static final int TYPE_CACOMMANDLINE_USER = 3;
    /** Batch generation tool */
    public static final int TYPE_BATCHCOMMANDLINE_USER = 4;
    /** Internal user in EJBCA, such as automatic job */
    public static final int TYPE_INTERNALUSER = 5;

    private int id;
    /** One of LogEntry.TYPE_ constants */
    private int admintype;
    private String admindata;
    private int caid;
    private int module;
    private Date time;
    private String username;
    private String certificatesnr;
    private int event;
    private String comment;

    /**
     * Determines if a de-serialized file is compatible with this class.
     *
     * Maintainers must change this value if and only if the new version
     * of this class is not compatible with old versions. See Sun docs
     * for <a href=http://java.sun.com/products/jdk/1.1/docs/guide
     * /serialization/spec/version.doc.html> details. </a>
     *
     */
	private static final long serialVersionUID = -1L;


    /**
     * Function used by EJBCA to log information.
     *
     * @param admintype is pricipally the type of data stored in the admindata field, should be one of org.ejbca.core.model.log.Admin.TYPE_ constants.
     * @param admindata is the data identifying the administrator, should be certificate snr or ip-address when no certificate could be retrieved.
     * @param module indicates from which module the event was logged. i.e one of the constans LogConstants.MODULE_RA, LogConstants.MODULE_CA ....
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the org.ejbca.core.model.log.LogConstants.EVENT_ constants.
     * @param comment comment of the event.
     */

    public LogEntry(int id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment) {
        this.id = id;
    	this.admintype = admintype;
        this.admindata = admindata;
        this.caid = caid;
        this.module = module;
        this.time = time;
        this.username = username;
        this.certificatesnr = certificatesnr;
        this.event = event;
        this.comment = comment;
    }

    // Public methods

    /**
     * Method used to map between event id and a string representation of event
     *
     * @return a string representation of the event.
     */
    public String getEventName() {
        if (this.event < LogConstants.EVENT_ERROR_BOUNDRARY) {
            return LogConstants.EVENTNAMES_INFO[this.event];
        }
        if (this.event < LogConstants.EVENT_SYSTEM_BOUNDRARY) {
            return LogConstants.EVENTNAMES_ERROR[this.event - LogConstants.EVENT_ERROR_BOUNDRARY];
        }
        return LogConstants.EVENTNAMES_SYSTEM[this.event - LogConstants.EVENT_SYSTEM_BOUNDRARY];
    }

    /**
     * Method used to map between event id and a string representation of event
     *
     * @return a string representation of the event.
     */
    static public String getEventName(int eventId) {
        if (eventId < LogConstants.EVENT_ERROR_BOUNDRARY) {
            return LogConstants.EVENTNAMES_INFO[eventId];
        }
        if (eventId < LogConstants.EVENT_SYSTEM_BOUNDRARY) {
            return LogConstants.EVENTNAMES_ERROR[eventId - LogConstants.EVENT_ERROR_BOUNDRARY];
        }
        return LogConstants.EVENTNAMES_SYSTEM[eventId - LogConstants.EVENT_SYSTEM_BOUNDRARY];
    }

	public int getId() {
		return this.id;
	}

    public int getAdminType() {
        return this.admintype;
    }

    public String getAdminData() {
        return this.admindata;
    }

    public int getCAId() {
        return this.caid;
    }

    public int getModule() {
        return this.module;
    }

    public Date getTime() {
        return this.time;
    }

    public String getUsername() {
        return this.username;
    }

    public String getCertificateSNR() {
        return this.certificatesnr;
    }

    public int getEvent() {
        return this.event;
    }

    public String getComment() {
        return this.comment;
    }
}
