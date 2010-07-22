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


import java.util.Date;

import javax.ejb.CreateException;

import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.util.StringTools;

/** Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing a log entry in the log database.
 * Information stored:
 * <pre>
 *  id (Primary Key)
 *  admintype is pricipally the type of data stored in the admindata field, should be one of org.ejbca.core.model.log.Admin.TYPE_ constants.
 *  admindata is the data identifying the administrator, should be certificate snr or ip-address when no certificate could be retrieved.
 *  time is the time the event occured.
 *  username the name of the user involved or null if no user is involved.
 *  certificate the certificate involved in the event or null if no certificate is involved.
 *  event is id of the event, should be one of the org.ejbca.core.model.log.LogConstants.EVENT_ constants.
 *  comment an optional comment of the event.
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a Log Entry with accompanying data"
 *   display-name="LogEntryDataEB"
 *   name="LogEntryData"
 *   jndi-name="LogEntryData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="LogEntryDataBean"
 *   primkey-field="id"
 *
 * @ejb.pk
 *   generate="false"
 *   class="java.lang.Integer"
 *
 * @ejb.persistence table-name = "LogEntryData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.log.LogEntryDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.log.LogEntryDataLocal"
 *
 * @ejb.transaction type="Required"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *   
 * @version $Id$
 */
public abstract class LogEntryDataBean extends BaseEntityBean {

	// NOTE: The column mapping here is also present in LogMatch used for queries to the log table.
	
    /**
     * @ejb.pk-field
     * @ejb.persistence column-name="id"
     * @ejb.interface-method view-type="local"
     */
    public abstract Integer getId();

    /**
     */
    public abstract void setId(Integer id);

    /**
     * @ejb.persistence column-name="adminType"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getAdminType();

    /**
     */
    public abstract void setAdminType(int admintype);

    /**
     * @ejb.persistence column-name="adminData"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getAdminData();

    /**
     */
    public abstract void setAdminData(String admindata);

    /** The id of the CA performing the event.
     * @ejb.persistence column-name="cAId"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getCaId();

    /**
     */
    public abstract void setCaId(int caid);

    /** Indicates the module (CA,RA ...) using the logsession bean.
     * @ejb.persistence column-name="module"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getModule();

    /**
     */
    public abstract void setModule(int module);

    /**
     * @ejb.persistence column-name="time"
     */
    public abstract long getTime();

    /**
     */
    public abstract void setTime(long time);

    /**
     * @ejb.persistence column-name="username"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getUsername();

    /** username must be called 'stripped' using StringTools.strip()
     */
    public abstract void setUsername(String username);

    /**
     * @ejb.persistence column-name="certificateSNR"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getCertificateSNR();

    /**
     */
    public abstract void setCertificateSNR(String certificatesnr);

    /**
     * @ejb.persistence column-name="event"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getEvent();

    /**
     */
    public abstract void setEvent(int event);

    /**
     * @ejb.persistence column-name="logComment"
     * @ejb.interface-method view-type="local"
     */
    public abstract String getComment();

    private static final int COMMENT_MAXLEN = 249;	// 250-255 chars depending on current mapping.
    
    /**
     *  @param comment should never be longer than the database column can hold.
     */
    public abstract void setComment(String comment);

    /**
     * @ejb.interface-method view-type="local"
     */
    public Date getTimeAsDate() {
        return new Date(getTime());
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public LogEntry getLogEntry() {
        return new LogEntry(getId().intValue(), getAdminType(), getAdminData(), getCaId(), getModule(), getTimeAsDate(), getUsername(), getCertificateSNR(), getEvent(), getComment());
    }

    /**
     *
     * @ejb.create-method view-type="local"
     */
    public Integer ejbCreate(Integer id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment) throws CreateException {
        setId(id);
        setAdminType(admintype);
        setAdminData(admindata);
        setCaId(caid);
        setModule(module);
        setTime(time.getTime());
        setUsername(StringTools.strip(username));
        setCertificateSNR(certificatesnr);
        setEvent(event);
        if ( (comment != null) && (comment.length() > COMMENT_MAXLEN) ) {
        	log.warn("Too large comment for LogEntry was truncated. The full comment was: " + comment);
        	comment = new String(comment.substring(0, COMMENT_MAXLEN-3)) + "..."; // new String to avoid possible memory leak, see http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4513622
        }
        setComment(comment);
        return null;
    }
    
    /**
     */
    public void ejbPostCreate(Integer id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment) {
// Do nothing. Required.
    }
}

