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

import java.util.Date;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see LogEntryDataBean
 *
 * @version $Id: LogEntryDataLocalHome.java,v 1.6 2004-06-10 12:35:05 sbailliez Exp $
 **/

public interface LogEntryDataLocalHome extends javax.ejb.EJBLocalHome {

    public LogEntryDataLocal create(Integer id, int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment)
            throws CreateException;

    public LogEntryDataLocal findByPrimaryKey(Integer id)
            throws FinderException;

}

