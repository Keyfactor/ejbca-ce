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
 
package se.anatom.ejbca.upgrade;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
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
import se.anatom.ejbca.util.JDBCUtil;
import se.anatom.ejbca.util.SqlExecutor;

/** The upgrade session bean is used to upgrade the database between ejbca releases.
 *
 * @version $Id: UpgradeSessionBean.java,v 1.10 2004-04-23 08:18:19 anatom Exp $
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
     * @return true if ok to upgrade or false if not
     * @throws RemoteException
     */
    private boolean preCheck() {
        debug(">preCheck");
        boolean ret = false;
        Connection con = null;
        PreparedStatement ps = null;
        try {
            con = getConnection();
            // Check if cAId in the table admingroupdata is present. It is present only in ejbca 3, not 2.
            ps = con.prepareStatement("select * from admingroupdata");
            ResultSet rs = ps.executeQuery();
            ResultSetMetaData md = rs.getMetaData(); // MySQL does not implement getMetaData directly from ps
            debug("preCheck: no of columns="+md.getColumnCount());
            // Ejbca 3 has three columns, ejbca 2 only one
            if (md.getColumnCount() == 1) {
            	ret = true;
            }
        } catch (Exception e) {
        	error("Database error during preCheck: ", e);
        } finally {
            JDBCUtil.close(ps);
            JDBCUtil.close(con);
        }            
        debug("<preCheck("+ret+")");
        return ret;
    }

    /** Upgrades the database
     * 
     * @param admin
     * @return true or false if upgrade was done or not
     * @throws RemoteException
     */
    public boolean upgrade(Admin admin, String[] args) {
        debug(">upgrade("+admin.toString()+")");
        String dbtype = null;
        if (args.length > 0) {
            dbtype = args[0];
            debug("Database type="+dbtype);
        }
        if (args.length > 1) {
        	dataSource = args[1];
        	debug("Datasource="+dataSource);
        }
        if (!preCheck()) {
        	info("preCheck failed, no upgrade performed.");
            return false;
        }
        info("Starting upgrade from ejbca2 to ejbca3.");
        // Fetch the resource file
        InputStream in = this.getClass().getResourceAsStream("/upgrade/21_30/21_30-upgrade-"+dbtype+".sql");
        if (in == null) {
        	error("Can not read resource for database type '"+dbtype+"'");
        	return false;
        }
        // TODO: export and import profiles?
        // TODO: export and import key recovery keys?
        Connection con = null;
        info("Start migration of database.");
        try {
            InputStreamReader inreader = new InputStreamReader(in);
            con = getConnection();
            SqlExecutor sqlex = new SqlExecutor(con, false); 
            sqlex.runCommands(inreader);
        } catch (Exception e) {
            error("Error during database migration: ", e);
        } finally {
            JDBCUtil.close(con);
        }
        info("Finished migrating database.");
        // TODO: import CA from PKCS12 file
        // TODO: Change fields, i.e. CAId in database tables
        debug(">upgrade()");
        return false;
    }
    
} // UpgradeSessionBean
