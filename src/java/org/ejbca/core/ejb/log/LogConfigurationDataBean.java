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

import javax.ejb.CreateException;

import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.log.LogConfiguration;
import org.ejbca.core.model.log.LogConstants;




/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing the
 * log configuration data. Information stored:
 * <pre>
 * Id (Should always be 0)	
 * logConfiguration  is the actual log configuration
 * logentryrownumber is the number of the last row number in the log entry database.
 * </pre>
 *
 * @version $Id$
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents a Log Entry with accompanying data"
 *   display-name="LogConfigurationDataEB"
 *   name="LogConfigurationData"
 *   jndi-name="LogConfigurationData"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="LogConfigurationDataBean"
 *   primkey-field="id"
 *
 * @ejb.pk
 *   generate="false"
 *   class="java.lang.Integer"
 *
 * @ejb.persistence table-name = "LogConfigurationData"
 * 
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.log.LogConfigurationDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.log.LogConfigurationDataLocal"
 *
 * @ejb.transaction type="Required"
 *
 * @jboss.method-attributes
 *   pattern = "load*"
 *   read-only = "true"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *   
 */
public abstract class LogConfigurationDataBean extends BaseEntityBean {

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
     * @ejb.persistence column-name="logConfiguration"
     * @weblogic.ora.columntyp@
     */
    public abstract LogConfiguration getLogConfiguration();

    /**
     */
    public abstract void setLogConfiguration(LogConfiguration logConfiguration);

    /**
     * @ejb.persistence column-name="logEntryRowNumber"
     */
    public abstract int getLogEntryRowNumber();

    /**
     * @ejb.interface-method view-type="local"
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
     * @ejb.transaction type="Required"
     */
    public Integer getAndIncrementRowCount() {
        int returnval = getLogEntryRowNumber();
        setLogEntryRowNumber(returnval + 1);
        return Integer.valueOf(returnval);
    }

    //
    // Fields required by Container
    //

    /**
     * Entity Bean holding data of log configuration. Create by sending in the id.
     *
     * @param id the unique id of logconfiguration (should always be 0).
     * @param logConfiguration is the serialized representation of the log configuration.
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

        return null;
    }

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param logConfiguration DOCUMENT ME!
     */
    public void ejbPostCreate(Integer id, LogConfiguration logConfiguration) {
        // Do nothing. Required.
    }
}
