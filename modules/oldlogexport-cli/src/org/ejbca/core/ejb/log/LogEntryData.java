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

package org.ejbca.core.ejb.log;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.log.LogEntry;

/**
 * Representation of a log entry in the database.
 * 
 * @version $Id$
 * 
 * @deprecated This class is kept in EJBCA 5.0 just in order to be able to export old logs using the OldLogExportCli
 */
@Entity
@Table(name="LogEntryData")
public class LogEntryData implements Serializable {

	private static final long serialVersionUID = 1L;
    private static final int COMMENT_MAXLEN = 249;	// 250-255 chars depending on current mapping.
	private static final Logger log = Logger.getLogger(LogEntryData.class);

	private int id;
	private int adminType;
	private String adminData;
	private int caId;
	private int module;
	private long time;
	private String username;
	private String certificateSNR;
	private int event;
	private String logComment;
	private int rowVersion = 0;
	private String rowProtection;

	public LogEntryData(int id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String logComment) {
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

	//@Id @Column
	public int getId() { return id; }
	public void setId(int id) { this.id = id; }

	//@Column
	public int getAdminType() { return adminType; }
	public void setAdminType(int adminType) { this.adminType = adminType; }

	//@Column
	public String getAdminData() { return adminData; }
	public void setAdminData(String adminData) { this.adminData = adminData; }

	/** 
	 * The id of the CA performing the event.
	 */
	//@Column
	public int getCaId() { return caId; }
	public void setCaId(int caId) { this.caId = caId; }

	/** 
	 * Indicates the module (CA,RA ...) using the LogSessionBean.
	 */
	//@Column
	public int getModule() { return module; }
	public void setModule(int module) { this.module = module; }

	//@Column
	public long getTime() { return time; }
	public void setTime(long time) { this.time = time; }

	//@Column
	public String getUsername() { return username; }
	public void setUsername(String username) { this.username = StringTools.stripUsername(username); }

	//@Column
	public String getCertificateSNR() { return certificateSNR; }
	public void setCertificateSNR(String certificateSNR) { this.certificateSNR = certificateSNR; }

	//@Column
	public int getEvent() { return event; }
	public void setEvent(int event) { this.event = event; }

	//@Column
	public String getLogComment() { return logComment; }
	public void setLogComment(String logComment) { this.logComment = logComment; }

	//@Version @Column
	public int getRowVersion() { return rowVersion; }
	public void setRowVersion(int rowVersion) { this.rowVersion = rowVersion; }

	//@Column @Lob
	public String getRowProtection() { return rowProtection; }
	public void setRowProtection(String rowProtection) { this.rowProtection = rowProtection; }

	@Transient
	public Date getTimeAsDate() {
		return new Date(getTime());
	}

	@Transient
	public LogEntry getLogEntry() {
		return new LogEntry(getId(), getAdminType(), getAdminData(), getCaId(), getModule(), getTimeAsDate(), getUsername(), getCertificateSNR(), getEvent(), getLogComment());
	}

	//
	// Search functions. 
	//

	/** @return the found entity instance or null if the entity does not exist */
	public static LogEntryData findById(EntityManager entityManager, Integer id) {
		return entityManager.find(LogEntryData.class, id);
	}

	/** @return a List<LogEntryData> from a custom SQL query. */
	@SuppressWarnings("unchecked")
    public static List<LogEntryData> findByCustomQueryAndPrivileges(EntityManager entityManager, String queryString, String caPriviledges, String viewLogPrivileges, int maxResults) {
		// Hibernate on DB2 wont allow us to "SELECT *" in combination with setMaxResults  
		String sql = "SELECT id, adminType, adminData, cAId, module, time, username, certificateSNR, event, logComment, rowVersion, rowProtection FROM LogEntryData WHERE ( " + queryString + ") AND (" + caPriviledges + ")";
		if (StringUtils.isNotEmpty(viewLogPrivileges)) {
			sql += " AND (" + viewLogPrivileges + ")";
		}
		sql += " ORDER BY time DESC";
		if (log.isDebugEnabled()) {
			log.debug("Query: "+sql);
		}
		Query query = entityManager.createNativeQuery(sql, LogEntryData.class);
		query.setMaxResults(maxResults);
		return query.getResultList();
	}
}
