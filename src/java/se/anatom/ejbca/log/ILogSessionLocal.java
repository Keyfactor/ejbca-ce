package se.anatom.ejbca.log;


import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.util.query.Query;

/** Local interface for EJB, unforturnately this must be a copy of the remote interface except that RemoteException is not thrown, see ICertificateStoreSession for docs.
 *
 * @version $Id: ILogSessionLocal.java,v 1.7 2003-09-04 08:05:03 herrvendil Exp $
 * @see se.anatom.ejbca.log.ILogSessionRemote
 */

public interface ILogSessionLocal extends javax.ejb.EJBLocalObject

{

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
    public void log(Admin admin, X509Certificate caid, int module,  Date time, String username, X509Certificate certificate, int event, String comment);    
    
    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */
    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception);

    /**
     * @see se.anatom.ejbca.log.ILogSessionRemote
     */    
    public void log(Admin admin, X509Certificate caid, int module,  Date time, String username, X509Certificate certificate, int event, String comment, Exception exception);    
        
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

