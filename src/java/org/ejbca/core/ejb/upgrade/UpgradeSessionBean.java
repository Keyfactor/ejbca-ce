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

package org.ejbca.core.ejb.upgrade;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;

import javax.ejb.CreateException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.JDBCUtil;

/** The upgrade session bean is used to upgrade the database between ejbca releases.
 *
 * @version $Id: UpgradeSessionBean.java,v 1.1 2006-01-17 20:30:56 anatom Exp $
 * @ejb.bean
 *   display-name="UpgradeSB"
 *   name="UpgradeSession"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *   generate="false"
 *
 * @ejb.transaction type="Required"
 * 
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.upgrade.IUpgradeSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.upgrade.IUpgradeSessionHome"
 *
 * @ejb.env-entry
 * name="DataSource"
 * type="java.lang.String"
 * value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.upgrade.IUpgradeSessionLocal"
 *   remote-class="org.ejbca.core.ejb.upgrade.IUpgradeSessionRemote"
 * 
 * @ejb.ejb-external-ref
 *   description="The Authorization session bean"
 *   view-type="local"
 *   ejb-name="AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Ra Admin session bean"
 *   view-type="local"
 *   ejb-name="RaAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The CA Admin Session"
 *   view-type="local"
 *   ejb-name="CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 * 
 */
public class UpgradeSessionBean extends BaseSessionBean {

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        dataSource = getLocator().getString(JNDINames.DATASOURCE);
    }


    /** Runs a preCheck to see if an upgrade is possible
     *
     * @return true if ok to upgrade or false if not
     */
    private boolean preCheck() {
        debug(">preCheck");
        boolean ret = false;
        Connection con = null;
        PreparedStatement ps = null;
        try {
            con = JDBCUtil.getDBConnection(dataSource);
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
//        info("Starting upgrade from ejbca2 to ejbca3.");
//        // Fetch the resource file with SQL to modify the database tables
//        InputStream in = this.getClass().getResourceAsStream("/upgrade/21_30/21_30-upgrade-"+dbtype+".sql");
//        if (in == null) {
//        	error("Can not read resource for database type '"+dbtype+"'");
//        	return false;
//        }

        // Migrate database tables to new columns etc
//        Connection con = null;
//        info("Start migration of database.");
//        try {
//            InputStreamReader inreader = new InputStreamReader(in);
//            con = JDBCUtil.getDBConnection(dataSource);
//            SqlExecutor sqlex = new SqlExecutor(con, false);
//            sqlex.runCommands(inreader);
//        } catch (SQLException e) {
//            error("SQL error during database migration: ", e);
//            return false;
//        } catch (IOException e) {
//            error("IO error during database migration: ", e);
//            return false;
//        } finally {
//            JDBCUtil.close(con);
//        }
//        info("Finished migrating database.");

        PreparedStatement ps1 = null;
        PreparedStatement ps2 = null;
        Connection con = null;
        try {
            con = JDBCUtil.getDBConnection(dataSource);
            ps1 = con.prepareStatement("SELECT LogConfiguration FROM LogConfigurationData");
            ps2 = con.prepareStatement("update LogConfigurationData set LogConfiguration=?");
            ResultSet rs = ps1.executeQuery();
            while (rs.next()) {
                //org.ejbca.core.model.log.LogConfiguration logConf = (LogConfiguration)rs.getObject(1);
                //LogConfiguration newLog = new LogConfiguration(logConf);
                //ps2.setObject(1, newLog);
                ps2.executeUpdate();
            }
        } catch (SQLException sqle) {
            error("Error updating LogConfigurationData: ", sqle);
            return false;
        } finally {
            JDBCUtil.close(ps1);
            JDBCUtil.close(ps2);
            JDBCUtil.close(con);
        }
        debug("<upgrade()");
        return true;
    }

} // UpgradeSessionBean
