package se.anatom.ejbca.upgrade;

import java.sql.Connection;
import java.sql.SQLException;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;

/** The upgrade session bean is used to upgrade the database between ejbca releases.
 *
 * @version $Id: UpgradeSessionBean.java,v 1.1 2004-04-10 10:15:33 anatom Exp $
 */
public class UpgradeSessionBean extends BaseSessionBean {

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The local interface of the log session bean */
    private ILogSessionLocal logsession = null;

    /** The local interface of the authorization session bean */
    private IAuthorizationSessionLocal authorizationsession = null;
    
    /** The local interface of the publisher session bean */
    private IPublisherSessionLocal publishersession = null;
    
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        debug("<ejbCreate()");
    }

    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection
    
    
    /** Gets connection to log session bean
     */
    private ILogSessionLocal getLogSession() {
        if(logsession == null){
          try{
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",ILogSessionLocalHome.class);
            logsession = logsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return logsession;
    } //getLogSession
    

    /** Runs a preCheck to see if an upgrade is possible
     * 
     * @param admin
     * @return true or false
     * @throws RemoteException
     */
    private boolean preCheck() {
        // TODO:
        return false;
    }

    /** Upgrades the database
     * 
     * @param admin
     * @return true or false if upgrade was done or not
     * @throws RemoteException
     */
    public boolean upgrade(Admin admin) {
        debug(">upgrade("+admin.toString()+")");
        if (!preCheck()) {
            return false;
        }
        // TODO:
        debug(">upgrade()");
        return false;
    }
    
} // UpgradeSessionBean
