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

/**
 * For docs, see LogConfigurationDataBean
 */
public interface LogConfigurationDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public Integer getId();

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public LogConfiguration loadLogConfiguration();

    /**
     * DOCUMENT ME!
     *
     * @param logconfiguration DOCUMENT ME!
     */
    public void saveLogConfiguration(LogConfiguration logconfiguration);

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Integer getAndIncrementRowCount();
}
