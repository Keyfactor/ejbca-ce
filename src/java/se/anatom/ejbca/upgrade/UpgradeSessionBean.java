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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AdminGroupExistsException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.ra.raadmin.EndEntityProfile;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome;
import se.anatom.ejbca.util.FileTools;
import se.anatom.ejbca.util.JDBCUtil;
import se.anatom.ejbca.util.SqlExecutor;

/** The upgrade session bean is used to upgrade the database between ejbca releases.
 *
 * @version $Id: UpgradeSessionBean.java,v 1.20 2004-09-08 20:55:20 koen_serry Exp $
 * @ejb.bean
 *   display-name="UpgradeSB"
 *   name="UpgradeSession"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.upgrade.IUpgradeSessionLocalHome"
 *   remote-class="se.anatom.ejbca.upgrade.IUpgradeSessionHome"
 *
 * @ejb.env-entry
 * name="DataSource"
 * type="java.lang.String"
 * value="java:/${datasource.jndi-name}"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.upgrade.IUpgradeSessionLocal"
 *   remote-class="se.anatom.ejbca.upgrade.IUpgradeSessionRemote"
 * 
 * @ejb.ejb-external-ref
 *   description="The Authorization session bean"
 *   view-type="local"
 *   ejb-name="AuthorizationSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome"
 *   business="se.anatom.ejbca.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Ra Admin session bean"
 *   view-type="local"
 *   ejb-name="RaAdminSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.log.ILogSessionLocalHome"
 *   business="se.anatom.ejbca.log.ILogSessionLocal"
 *   link="LogSession"
 */
public class UpgradeSessionBean extends BaseSessionBean {

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The local interface of the log session bean */
    private ILogSessionLocal logsession = null;

    /** The local interface of the ca admin session bean */
    private ICAAdminSessionLocal caadminsession = null;

    /** The local interface of the authorization session bean */
    private IAuthorizationSessionLocal authorizationsession = null;

    /** The local interface of the publisher session bean */
    private IPublisherSessionLocal publishersession = null;

    /** The local interface of the raadmin session bean */
    private IRaAdminSessionLocal raadminsession = null;

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
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup(ILogSessionLocalHome.COMP_NAME,ILogSessionLocalHome.class);
            logsession = logsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return logsession;
    } //getLogSession

    /** Gets connection to ca admin session bean
     */
    private ICAAdminSessionLocal getCaAdminSession() {
        if(caadminsession == null){
          try{
              ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome)lookup("java:comp/env/ejb/CAAdminSessionLocal", ICAAdminSessionLocalHome.class);
              caadminsession = caadminsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return caadminsession;
    } //getCaAdminSession

    /** Gets connection to ca admin session bean
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if(authorizationsession == null){
          try{
            IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) lookup("java:comp/env/ejb/AuthorizationSessionLocal", IAuthorizationSessionLocalHome.class);
            authorizationsession = authorizationsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return authorizationsession;
    } //getAuthorizationSession

    /** Gets connection to ca admin session bean
     */
    private IRaAdminSessionLocal getRaAdminSession() {
        if(raadminsession == null){
          try{
            IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) lookup("java:comp/env/ejb/RaAdminSessionLocal", IRaAdminSessionLocalHome.class);
            raadminsession = raadminsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return raadminsession;
    } //getRaAdminSession

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
     * @ejb.interface-method
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
        String caName = "MyCA";
        if (args.length > 2) {
            caName = args[2];
            debug("CaName="+caName);
        }
        String keyStore = null;
        if (args.length > 3) {
            keyStore = args[3];
            debug("KeyStore="+keyStore);
        }
        String pwd = null;
        if (args.length > 4) {
            pwd = args[4];
            debug("Pwd="+pwd);
        }
        if (!preCheck()) {
        	info("preCheck failed, no upgrade performed.");
            return false;
        }
        // Read old keystore file in the beginning so we know it's good
        byte[] keystorebytes = null;
        try {
            keystorebytes = FileTools.readFiletoBuffer(keyStore);
        } catch (IOException ioe) {
            error("IOException reading old keystore file: ", ioe);
            return false;
        }
        info("Starting upgrade from ejbca2 to ejbca3.");
        // Fetch the resource file with SQL to modify the database tables
        InputStream in = this.getClass().getResourceAsStream("/upgrade/21_30/21_30-upgrade-"+dbtype+".sql");
        if (in == null) {
        	error("Can not read resource for database type '"+dbtype+"'");
        	return false;
        }

        // Migrate database tables to new columns etc
        Connection con = null;
        info("Start migration of database.");
        try {
            InputStreamReader inreader = new InputStreamReader(in);
            con = getConnection();
            SqlExecutor sqlex = new SqlExecutor(con, false);
            sqlex.runCommands(inreader);
        } catch (NamingException e) {
            error("Error during database migration: ", e);
            return false;
        } catch (SQLException e) {
            error("SQL error during database migration: ", e);
            return false;
        } catch (IOException e) {
            error("IO error during database migration: ", e);
            return false;
        } finally {
            JDBCUtil.close(con);
        }
        info("Finished migrating database.");

        // Import CA from PKCS12 file
        String privKeyAlias = "privateKey";
        getCaAdminSession().upgradeFromOldCAKeyStore(admin, caName, keystorebytes, pwd.toCharArray(), pwd.toCharArray(), privKeyAlias);

        // Change fields, i.e. CAId in database tables
        CAInfo cainfo = getCaAdminSession().getCAInfo(admin, caName);
        int caId = cainfo.getCAId();
        debug("Upgraded CAId="+caId);
        // Fix all End Entity Profiles
        HashMap profileidtonamemap = getRaAdminSession().getEndEntityProfileIdToNameMap(admin);
        Iterator iter = profileidtonamemap.keySet().iterator();
        while(iter.hasNext()){
        	int next = ((Integer) iter.next()).intValue();
            debug("Found entityprofile "+next);
        	// Only upgrade nonfixed profiles.
        	if(next > SecConst.EMPTY_ENDENTITYPROFILE){
        		EndEntityProfile profile = getRaAdminSession().getEndEntityProfile(admin,next);
                profile.upgrade();
                profile.setValue(EndEntityProfile.DEFAULTCA,0,Integer.toString(caId));
                profile.setRequired(EndEntityProfile.DEFAULTCA,0,true);
                profile.setValue(EndEntityProfile.AVAILCAS,0,Integer.toString(caId));
                profile.setRequired(EndEntityProfile.AVAILCAS,0,true);
        		getRaAdminSession().changeEndEntityProfile(admin,(String) profileidtonamemap.get(new Integer(next)),profile);
        	}
        }

        PreparedStatement ps1 = null;
        PreparedStatement ps2 = null;
        PreparedStatement ps3 = null;
        try {
            con = getConnection();
            ps1 = con.prepareStatement("update admingroupdata set caId=?");
            ps1.setInt(1, caId);
            ps1.executeUpdate();

            ps2 = con.prepareStatement("update logentrydata set caId=?");
            ps2.setInt(1, caId);
            ps2.executeUpdate();

            ps3 = con.prepareStatement("update userdata set caId=?");
            ps3.setInt(1, caId);
            ps3.executeUpdate();
        } catch (SQLException sqle) {
            error("Error updating caId: ", sqle);
            return false;
        } catch (NamingException ne) {
            error("Error getting connection: ", ne);
            return false;
        } finally {
            JDBCUtil.close(ps1);
            JDBCUtil.close(ps2);
            JDBCUtil.close(ps3);
            JDBCUtil.close(con);
        }
        try {
            getAuthorizationSession().initialize(admin, caId);
        } catch (AdminGroupExistsException e) {
            error("Error initializing admin group: ", e);
            return false;
        }
        debug("<upgrade()");
        return true;
    }

} // UpgradeSessionBean
