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

/*
 * LogEntry.java
 *
 * Created on den 28 aug 2002, 10:02
 */

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Date;

import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.model.protect.Protectable;
import org.ejbca.core.model.protect.TableVerifyResult;

/**
 *  This is a  class containing information about one log event in the database. Used mainly during database queries by the web interface.
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class LogEntry implements Serializable, Protectable {

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

    public String getVerifyResult() {
        return this.verifyResult;
    }

    public void setVerifyResult(String result) {
        this.verifyResult=result;
    }
    
    // 
    // Protectable
    //
    public int getHashVersion() {
    	return 1;
    }
    public String getDbKeyString() {
    	return Integer.toString(id);
    }
    public String getEntryType() {
    	return "LOGENTRY";
    }
    public String getHash() throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
    	StringBuffer buf = new StringBuffer();
    	buf.append(id).append(admintype).append(admindata).append(caid).append(module).append(time.getTime()).
    		append(username).append(certificatesnr).append(event).append(comment);
        MessageDigest digest = MessageDigest.getInstance("SHA-256", "BC");
        byte[] result = digest.digest(buf.toString().getBytes("UTF-8"));
        return new String(Hex.encode(result));
    }
    public String getHash(int version) throws NoSuchAlgorithmException, NoSuchProviderException, UnsupportedEncodingException {
    	return getHash();
    }

    // Private methods

    // Private fields
    private int id;
    private int admintype;
    private String admindata;
    private int caid;
    private int module;
    private Date time;
    private String username;
    private String certificatesnr;
    private int event;
    private String comment;
    private String verifyResult = TableVerifyResult.VERIFY_DISABLED_MSG;

}
