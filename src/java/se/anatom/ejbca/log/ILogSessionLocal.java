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


import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.util.query.Query;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: ILogSessionLocal.java,v 1.9 2004-06-10 12:35:05 sbailliez Exp $
 * @see se.anatom.ejbca.log.ILogSessionRemote
 */

public interface ILogSessionLocal extends javax.ejb.EJBLocalObject {

    public static final int MAXIMUM_QUERY_ROWCOUNT = LocalLogSessionBean.MAXIMUM_QUERY_ROWCOUNT;

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public static final int INTERNALCAID = ILogSessionRemote.INTERNALCAID;

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void log(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void log(Admin admin, X509Certificate caid, int module, Date time, String username, X509Certificate certificate, int event, String comment);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void log(Admin admin, X509Certificate caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public Collection query(Query query, String viewlogprivileges, String caprivileges) throws IllegalQueryException;

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public LogConfiguration loadLogConfiguration(int caid);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void saveLogConfiguration(Admin administrator, int caid, LogConfiguration logconfiguration);

}

