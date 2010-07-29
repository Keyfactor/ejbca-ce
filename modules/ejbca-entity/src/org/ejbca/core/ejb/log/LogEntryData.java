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

import java.io.Serializable;
import java.util.Date;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.util.StringTools;

/**
 * Representation of a log entry in the database.
 * 
 * @version $Id$
 * 
 * TODO: This class is now very similar to LogEntry and these two files could probably be merged,
 */
@Entity
@Table(name="LogEntryData")
public class LogEntryData implements Serializable {

	private static final long serialVersionUID = 1L;
    private static final int COMMENT_MAXLEN = 249;	// 250-255 chars depending on current mapping.
	private static final Logger log = Logger.getLogger(LogEntryData.class);

	private Integer id;
	private int adminType;
	private String adminData;
	private int caId;
	private int module;
	private long time;
	private String username;
	private String certificateSNR;
	private int event;
	private String logComment;

	public LogEntryData(Integer id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String logComment) {
		setId(id);
		setAdminType(admintype);
		setAdminData(admindata);
		setCaId(caid);
		setModule(module);
		setTime(time.getTime());
		setUsername(username);
		setCertificateSNR(certificatesnr);
		setEvent(event);
        if ( (logComment != null) && (logComment.length() > COMMENT_MAXLEN) ) {
        	log.warn("Too large comment for LogEntry was truncated. The full comment was: " + logComment);
        	logComment = new String(logComment.substring(0, COMMENT_MAXLEN-3)) + "..."; // new String to avoid possible memory leak, see http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4513622
        }
		setLogComment(logComment);
	}

	public LogEntryData() { }

	@Id
	@Column(name="id")
	public Integer getId() { return id; }
	public void setId(Integer id) { this.id = id; }

	@Column(name="adminType", nullable=false)
	public int getAdminType() { return adminType; }
	public void setAdminType(int adminType) { this.adminType = adminType; }

	@Column(name="adminData")
	public String getAdminData() { return adminData; }
	public void setAdminData(String adminData) { this.adminData = adminData; }

	/** 
	 * The id of the CA performing the event.
	 */
	@Column(name="caId", nullable=false)
	public int getCaId() { return caId; }
	public void setCaId(int caId) { this.caId = caId; }

	/** 
	 * Indicates the module (CA,RA ...) using the LogSessionBean.
	 */
	@Column(name="module", nullable=false)
	public int getModule() { return module; }
	public void setModule(int module) { this.module = module; }

	@Column(name="time", nullable=false)
	public long getTime() { return time; }
	public void setTime(long time) { this.time = time; }

	@Column(name="username")
	public String getUsername() { return username; }
	public void setUsername(String username) { this.username = StringTools.strip(username); }

	@Column(name="certificateSNR")
	public String getCertificateSNR() { return certificateSNR; }
	public void setCertificateSNR(String certificateSNR) { this.certificateSNR = certificateSNR; }

	@Column(name="event", nullable=false)
	public int getEvent() { return event; }
	public void setEvent(int event) { this.event = event; }

	@Column(name="logComment")
	public String getLogComment() { return logComment; }
	public void setLogComment(String logComment) { this.logComment = logComment; }

	@Transient
	public Date getTimeAsDate() {
		return new Date(getTime());
	}

	@Transient
	public LogEntry getLogEntry() {
		return new LogEntry(getId().intValue(), getAdminType(), getAdminData(), getCaId(), getModule(), getTimeAsDate(), getUsername(), getCertificateSNR(), getEvent(), getLogComment());
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static LogEntryData findById(EntityManager entityManager, Integer id) {
		return entityManager.find(LogEntryData.class, id);
	}
}
