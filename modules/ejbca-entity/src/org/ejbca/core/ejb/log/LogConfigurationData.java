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

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.Table;
import javax.persistence.Transient;

import org.ejbca.core.ejb.JBossUnmarshaller;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;

/**
 * Representation of the log configuration data.
 * 
 * @version $Id$
 */
@Entity
@Table(name="LogConfigurationData")
public class LogConfigurationData implements Serializable {

	private static final long serialVersionUID = 1L;

	private Integer id;
	private Serializable logConfiguration;
	private int logEntryRowNumber;

	/**
	 * Entity holding data of log configuration.
	 *
	 * @param id the unique id of the log configuration.
	 * @param logConfiguration is the serialized representation of the log configuration.
	 */
	public LogConfigurationData(Integer id, LogConfiguration logConfiguration) {
		setId(id);
		setLogConfiguration(logConfiguration);
		setLogEntryRowNumber(0);
	}

	public LogConfigurationData() { }

	@Id
	@Column(name="id")
	public Integer getId() { return id; }
	public void setId(Integer id) { this.id = id; }

	@Column(name="logConfiguration",length=17*1024*1024)
	@Lob
	private Serializable getLogConfigurationUnsafe() {
		LogConfiguration h = JBossUnmarshaller.extractObject(LogConfiguration.class, logConfiguration);	// This is a workaround for JBoss J2EE CMP Serialization
		if (h != null) {
			setLogConfigurationUnsafe(h);
		}
		return logConfiguration;
	}
	/** DO NOT USE! Stick with setLogConfiguration(LogConfiguration logConfiguration) instead. */
	private void setLogConfigurationUnsafe(Serializable logConfiguration) { this.logConfiguration = logConfiguration; }

	@Transient
	private LogConfiguration getLogConfiguration() { return (LogConfiguration) getLogConfigurationUnsafe(); }
	private void setLogConfiguration(LogConfiguration logConfiguration) { setLogConfigurationUnsafe(logConfiguration); }

	@Column(name="logEntryRowNumber", nullable=false)
	public int getLogEntryRowNumber() { return logEntryRowNumber; }
	public void setLogEntryRowNumber(int logEntryRowNumber) { this.logEntryRowNumber = logEntryRowNumber; }

	@Transient
	public LogConfiguration loadLogConfiguration() {
		LogConfiguration logconfiguration = (LogConfiguration) getLogConfiguration();
		// Fill in new information from LogEntry constants.
		for (int i = 0; i < LogConstants.EVENTNAMES_INFO.length; i++) {
			if (logconfiguration.getLogEvent(i) == null) {
				logconfiguration.setLogEvent(i, true);
			}
		}
		for (int i = 0; i < LogConstants.EVENTNAMES_ERROR.length; i++) {
			int index = i + LogConstants.EVENT_ERROR_BOUNDRARY;

			if (logconfiguration.getLogEvent(index) == null) {
				logconfiguration.setLogEvent(index, true);
			}
		}
		return logconfiguration;
	}

	@Transient
	public void saveLogConfiguration(LogConfiguration logConfiguration) {
		setLogConfiguration(logConfiguration);
	}

	@Transient
	public Integer getAndIncrementRowCount() {
		int returnval = getLogEntryRowNumber();
		setLogEntryRowNumber(returnval + 1);
		return new Integer(returnval);
	}

    //
    // Search functions. 
    //

	public static LogConfigurationData findByPK(EntityManager entityManager, Integer id) {
		return entityManager.find(LogConfigurationData.class,  id);
	}

	/*
	public static LogConfigurationData findFirst(EntityManager entityManager) {
    	return entityManager.find(LogConfigurationData.class,  new Integer(0));
    }
    */
}
