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
 
package se.anatom.ejbca.log;

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing the
 * log configuration data. Information stored:
 * <pre>
 * Id (Should always be 0)
 * logConfiguration  is the actual log configuration
 * logentryrownumber is the number of the last row number in the log entry database.
 * </pre>
 *
 * @version $Id: LogConfigurationDataBean.java,v 1.11 2004-06-03 09:22:45 anatom Exp $
 *
 * @ejb.bean
 *	 generate="true"
 *   description="This enterprise bean entity represents a Log Entry with accompanying data"
 *   display-name="LogConfigurationDataEB"
 *   name="LogConfigurationData"
 *   jndi-name="LogConfigurationData"
 *   local-jndi-name="LogConfigurationDataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="false"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="LogConfigurationDataBean"
 *
 * @ejb.permission role-name="InternalUser"
 *  
 * @ejb.pk
 *   class="java.lang.Integer"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.log.LogConfigurationDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.log.LogConfigurationDataLocal"
 *
 */
public abstract class LogConfigurationDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(LogConfigurationDataBean.class);

	/**
     * @ejb.pk-field
	 * @ejb.persistence
     * @ejb.interface-method view-type="local"
	 */
    public abstract Integer getId();

	/**
	 * @ejb.persistence
	 */
    public abstract void setId(Integer id);

	/**
	 * @ejb.persistence
	 */
    public abstract LogConfiguration getLogConfiguration();

	/**
	 * @ejb.persistence
	 */
    public abstract void setLogConfiguration(LogConfiguration logConfiguration);

	/**
	 * @ejb.persistence
	 */
    public abstract int getLogEntryRowNumber();

	/**
	 * @ejb.persistence
	 */
    public abstract void setLogEntryRowNumber(int logEntryRowNumber);

    /**
     * DOCUMENT ME!
     *
     * @ejb.interface-method view-type="local"
	 */
    public LogConfiguration loadLogConfiguration() {
        LogConfiguration logconfiguration = getLogConfiguration();

        // Fill in new information from LogEntry constants.
        for (int i = 0; i < LogEntry.EVENTNAMES_INFO.length; i++) {
            if (logconfiguration.getLogEvent(i) == null) {
                logconfiguration.setLogEvent(i, true);
            }
        }

        for (int i = 0; i < LogEntry.EVENTNAMES_ERROR.length; i++) {
            int index = i + LogEntry.EVENT_ERROR_BOUNDRARY;

            if (logconfiguration.getLogEvent(index) == null) {
                logconfiguration.setLogEvent(index, true);
            }
        }

        return logconfiguration;
    }

    /**
     * DOCUMENT ME!
     *
     * @ejb.interface-method view-type="local"
	 */
    public void saveLogConfiguration(LogConfiguration logConfiguration) {
        setLogConfiguration(logConfiguration);
    }

    /**
     * DOCUMENT ME!
     *
     * @ejb.interface-method view-type="local"
	 */
    public Integer getAndIncrementRowCount() {    	
        int returnval = getLogEntryRowNumber();               
        setLogEntryRowNumber(returnval + 1);		

        return new Integer(returnval);
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of log configuration. Create by sending in the id.
     *
     * @param id the unique id of logconfiguration (should always be 0).
     * @param logconfiguration is the serialized representation of the log configuration.
     *
     * @return the given id
	 *
     * @ejb.create-method view-type="local"
	 */
    public Integer ejbCreate(Integer id, LogConfiguration logConfiguration)
        throws CreateException {
        setId(id);
        setLogConfiguration(logConfiguration);
        setLogEntryRowNumber(0);

        return id;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param logconfiguration DOCUMENT ME!
     */
    public void ejbPostCreate(Integer id, LogConfiguration logConfiguration) {
        // Do nothing. Required.
    }
}
