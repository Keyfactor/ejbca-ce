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
import javax.ejb.FinderException;


/**
 * For docs, see LogConfigurationDataBean
 */
public interface LogConfigurationDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     * @param logconfiguration DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public LogConfigurationDataLocal create(Integer id, LogConfiguration logconfiguration)
            throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public LogConfigurationDataLocal findByPrimaryKey(Integer id)
            throws FinderException;
}
