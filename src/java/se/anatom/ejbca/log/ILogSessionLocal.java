package se.anatom.ejbca.log;

import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.util.query.Query;

import java.security.cert.X509Certificate;

import java.util.Collection;
import java.util.Date;


/**
 * Local interface for EJB, unforturnately this must be a copy of the remote interface except that
 * RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: ILogSessionLocal.java,v 1.6 2003-06-26 11:43:24 anatom Exp $
 *
 * @see se.anatom.ejbca.log.ILogSessionRemote
 */
public interface ILogSessionLocal extends javax.ejb.EJBLocalObject {
    public static final int MAXIMUM_QUERY_ROWCOUNT = LocalLogSessionBean.MAXIMUM_QUERY_ROWCOUNT;

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void log(Admin admin, int module, Date time, String username,
        X509Certificate certificate, int event, String comment);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void log(Admin admininfo, int module, Date time, String username,
        X509Certificate certificate, int event, String comment, Exception exception);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public Collection query(Query query, String viewlogprivileges)
        throws IllegalQueryException;

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public LogConfiguration loadLogConfiguration();

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void saveLogConfiguration(Admin administrator, LogConfiguration logconfiguration);
}
