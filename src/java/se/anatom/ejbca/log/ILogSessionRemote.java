package se.anatom.ejbca.log;

import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import se.anatom.ejbca.util.query.IllegalQueryException;
import se.anatom.ejbca.util.query.Query;

/**
 *
 * @version $Id: ILogSessionRemote.java,v 1.6 2003-09-04 08:05:04 herrvendil Exp $
 */
public interface ILogSessionRemote extends javax.ejb.EJBObject {
    
  public static final int MAXIMUM_QUERY_ROWCOUNT = LocalLogSessionBean.MAXIMUM_QUERY_ROWCOUNT;
  
  /**
   * Constant containing caid that couldn't be determined in any other way. Log events can only be viewed.
   * by superadministrator.
   */
  public static final int INTERNALCAID = 0;
  
    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param caid the id of the CA connected to the event.
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the se.anatom.ejbca.log.LogEntry.EVENT_ constants.
     * @param comment comment of the event.
     */
    public void log(Admin admin, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment) throws RemoteException;
    
     /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of 
     * given certificate.
     */
    
    public void log(Admin admin, X509Certificate caid, int module,  Date time, String username, X509Certificate certificate, int event, String comment) throws RemoteException;    
    
    /** 
    * Overloaded function that also logs an exception
    * See function above for more documentation.
    *
    * @param exception the exception that has occured
    */
    public void log(Admin admininfo, int caid, int module, Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) throws RemoteException;

    
     /**
     * Same as above but with the difference of CAid which is taken from the issuerdn of 
     * given certificate.
     */
    
    public void log(Admin admin, X509Certificate caid, int module,  Date time, String username, X509Certificate certificate, int event, String comment, Exception exception) throws RemoteException;    
    
     /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     * 
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @param authorizedcaids a collection of caid (Integer) indicating which CAs the administrator is authorized to. 
     * @return a collection of LogEntry. Maximum size of Collection is defined i ILogSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query 
     */
    public Collection query(Query query, String viewlogprivileges, String caprivileges) throws IllegalQueryException, RemoteException;
    
    /**
     * Loads the log configuration from the database.
     *
     * @param caid the logconfiguration specific for this CA     
     * @return the logconfiguration
     */
    public LogConfiguration loadLogConfiguration(int caid) throws RemoteException;
        
    /**
     * Saves the log configuration to the database.
     *
     * @param caid the logconfiguration specific for this CA.
     * @param logconfiguration the logconfiguration to save.
     */    
    public void saveLogConfiguration(Admin administrator, int caid, LogConfiguration logconfiguration) throws RemoteException;       

    
}

