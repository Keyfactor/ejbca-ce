package se.anatom.ejbca.log;

import java.util.Date;
import java.util.Collection;

import java.rmi.RemoteException;
import se.anatom.ejbca.util.query.Query;
import se.anatom.ejbca.util.query.IllegalQueryException;

import java.security.cert.X509Certificate;

/**
 *
 * @version $Id: ILogSessionRemote.java,v 1.3 2002-09-18 11:31:48 herrvendil Exp $
 */
public interface ILogSessionRemote extends javax.ejb.EJBObject {
    
  public static final int MAXIMUM_QUERY_ROWCOUNT = LocalLogSessionBean.MAXIMUM_QUERY_ROWCOUNT;
  
    /**
     * Session beans main function. Takes care of the logging functionality.
     *
     * @param admin the administrator performing the event.
     * @param time the time the event occured.
     * @param username the name of the user involved or null if no user is involved.
     * @param certificate the certificate involved in the event or null if no certificate is involved.
     * @param event id of the event, should be one of the se.anatom.ejbca.log.LogEntry.EVENT_ constants.
     * @param comment comment of the event.
     */
    public void log(Admin admin, int module, Date time, String username, X509Certificate certificate, int event, String comment) throws RemoteException;
    
     /**
     * Method to execute a customized query on the log db data. The parameter query should be a legal Query object.
     * 
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param viewlogprivileges is a sql query string returned by a LogAuthorization object.
     * @return a collection of LogEntry. Maximum size of Collection is defined i ILogSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query 
     */
    public Collection query(Query query, String viewlogprivileges) throws IllegalQueryException, RemoteException;
    
    /**
     * Loads the log configuration from the database.
     *
     * @return the logconfiguration
     */
    public LogConfiguration loadLogConfiguration() throws RemoteException;
        
    /**
     * Saves the log configuration to the database.
     *
     * @param logconfiguration the logconfiguration to save.
     */    
    public void saveLogConfiguration(Admin administrator, LogConfiguration logconfiguration) throws RemoteException;       

    
}

