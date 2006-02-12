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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.log.LogConfigurationDataLocal;
import org.ejbca.core.ejb.log.LogConfigurationDataLocalHome;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.SqlExecutor;

import se.anatom.ejbca.log.OldLogConfigurationDataLocal;
import se.anatom.ejbca.log.OldLogConfigurationDataLocalHome;

/** The upgrade session bean is used to upgrade the database between ejbca releases.
 *
 * @version $Id: UpgradeSessionBean.java,v 1.4 2006-02-12 10:37:39 anatom Exp $
 * @ejb.bean
 *   display-name="UpgradeSB"
 *   name="UpgradeSession"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *   generate="true"
 *
 * @ejb.transaction type="RequiresNew"
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
 *   description="The Log Configuration Data Entity bean"
 *   view-type="local"
 *   ejb-name="LogConfigurationDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.log.LogConfigurationDataLocalHome"
 *   business="org.ejbca.core.ejb.log.LogConfigurationDataLocal"
 *   link="LogConfigurationData"
 *   
 * @ejb.ejb-external-ref
 *   description="The Old Log Configuration Data Entity bean"
 *   view-type="local"
 *   ejb-name="OldLogConfigurationDataLocal"
 *   type="Entity"
 *   home="se.anatom.ejbca.log.LogConfigurationDataLocalHome"
 *   business="se.anatom.ejbca.log.LogConfigurationDataLocal"
 *   link="OldLogConfigurationData"
 * 
 * @ejb.ejb-external-ref
 *   description="The CA Admin Session"
 *   view-type="local"
 *   ejb-name="CAAdminSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 */
public class UpgradeSessionBean extends BaseSessionBean {

    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    private  OldLogConfigurationDataLocalHome oldLogHome = null;
    private  LogConfigurationDataLocalHome logHome = null;
    /** The local interface of the ca admin session bean */
    private ICAAdminSessionLocal caadminsession = null;
    private Admin administrator = null;
    
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        dataSource = getLocator().getString(JNDINames.DATASOURCE);
        logHome = (LogConfigurationDataLocalHome)ServiceLocator.getInstance().getLocalHome(LogConfigurationDataLocalHome.COMP_NAME);
        oldLogHome = (OldLogConfigurationDataLocalHome)ServiceLocator.getInstance().getLocalHome(OldLogConfigurationDataLocalHome.COMP_NAME);
        
    }

    /** 
     * Gets connection to ca admin session bean
     */
    private ICAAdminSessionLocal getCaAdminSession() {
        if(caadminsession == null){
          try{
              ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome)getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
              caadminsession = caadminsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return caadminsession;
    } //getCaAdminSession

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
            error("Getting connection for: "+dataSource);
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select userDataVO from CertReqHistoryData");
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                try {
                    String ud = rs.getString(1);
                    java.beans.XMLDecoder decoder = null;
                    try {
                      decoder = new java.beans.XMLDecoder(
                                new java.io.ByteArrayInputStream(ud.getBytes("UTF8")));
                    } catch (UnsupportedEncodingException e) {
                        error("Can not decode old UserDataVO: ", e);
                    }
                    se.anatom.ejbca.common.UserDataVO oldud  = (se.anatom.ejbca.common.UserDataVO)decoder.readObject();                          
                    decoder.close();
                    // If we came this far, we have an old UserDataVO.
                    ret = true;
                    error("(this is not an error) during pre-check successfully decoded old UserDataVO with username="+oldud.getUsername());
                } catch (Exception e) {
                    error("Can not decode old UserDataVO: ", e);
                }                
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
        this.administrator = admin;
        
        String dbtype = null;
        if (args.length > 0) {
            dbtype = args[0];
            debug("Database type="+dbtype);
        }

        if (!preCheck()) {
        	info("preCheck failed, no upgrade performed.");
            return false;
        }

        if (!migradeDatabase(dbtype)) {
        	return false;
        }

        if (!upgradeHardTokenClassPath()) {
        	return false;
        }
        if (!upgradeUserDataVO()) {
            return false;
        }
        ArrayList datas = logConfStep1(); 
        if (datas == null) {
            return false;            
        }
        if (!logConfStep2(datas)) {
            return false;
        }
        if (!logConfStep3(datas)) {
            return false;
        }
        debug("<upgrade()");
        return true;
    }


    /** 
     * @ejb.interface-method
     */
	public boolean migradeDatabase(String dbtype) {
		error("(this is not an error) Starting upgrade from ejbca 3.1.x to ejbca 3.2.x");
        // Fetch the resource file with SQL to modify the database tables
        InputStream in = this.getClass().getResourceAsStream("/31_32/31_32-upgrade-"+dbtype+".sql");
        if (in == null) {
        	error("Can not read resource for database type '"+dbtype+"', this database probably does not need table definition changes.");
        	// no error
        	return true;
        }

        // Migrate database tables to new columns etc
        Connection con = null;
        info("Start migration of database.");
        try {
            InputStreamReader inreader = new InputStreamReader(in);
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            SqlExecutor sqlex = new SqlExecutor(con, false);
            sqlex.runCommands(inreader);
        } catch (SQLException e) {
            error("SQL error during database migration: ", e);
            return false;
        } catch (IOException e) {
            error("IO error during database migration: ", e);
            return false;
        } finally {
            JDBCUtil.close(con);
        }
        error("(this is not an error) Finished migrating database.");
        return true;
	}

    /** 
     * @ejb.interface-method
     */
	public boolean upgradeHardTokenClassPath() {
		try {
			ICAAdminSessionLocal casession = getCaAdminSession(); 
	        Collection caids = casession.getAvailableCAs(administrator);
	        Iterator iter = caids.iterator();
	        if (iter.hasNext()) {
	            int caid = ((Integer) iter.next()).intValue();
	            casession.upgradeFromOldCAHSMKeyStore(administrator, caid);
	        }			
		} catch (Exception e) {
			error("Error upgrading hard token class path: ", e);
			return false;
		}
        return true;
	}

	/** 
     * @ejb.interface-method
     */
    public ArrayList logConfStep1() {
        ArrayList datas = new ArrayList();
        try {
            Collection oldColl = oldLogHome.findAll();
            Iterator it = oldColl.iterator();
            while (it.hasNext()) {
                OldLogConfigurationDataLocal odata = (OldLogConfigurationDataLocal)it.next();
                LogConfData d = new LogConfData();
                d.id = odata.getId();
                d.data = odata.getLogConfiguration();
                d.row = odata.getLogEntryRowNumber();
                datas.add(d);
            }
            error("(this is not an error) read "+datas.size()+" old LogConfigurationData.");
        } catch (Exception e) {
            error("Error reading old LogConfigurationData: ", e);
            return null;
        }
        return datas;
    }

    /** 
     * @ejb.interface-method
     */
    public boolean logConfStep2(ArrayList datas) {
        try {
            Iterator it2 = datas.iterator();
            while (it2.hasNext()) {
                LogConfData d = (LogConfData) it2.next();
                OldLogConfigurationDataLocal l = oldLogHome.findByPrimaryKey(d.id);
                oldLogHome.remove(l.getPrimaryKey());
            }
            error("(this is not an error) deleted old LogConfigurationData.");
        } catch (Exception e) {
            error("Failed to delete old LogConfigurationData");
            return false;
        }
        return true;
    }
    /** 
     * @ejb.interface-method
     */
    public boolean logConfStep3(ArrayList datas) {
        try {
            // Start creating the new ones
            Iterator it2 = datas.iterator();
            error("(this is not an error) Upgrading "+datas.size()+" LogConfigurationData.");
            while (it2.hasNext()) {
                LogConfData d = (LogConfData)it2.next();
                se.anatom.ejbca.log.LogConfiguration logConf = d.data;
                org.ejbca.core.model.log.LogConfiguration newLog = new org.ejbca.core.model.log.LogConfiguration(
                logConf.useLogDB(), logConf.useExternalLogDevices(), logConf.getConfigurationData());
                logHome.create(d.id, newLog);
                LogConfigurationDataLocal dl = logHome.findByPrimaryKey(d.id);
                dl.setLogEntryRowNumber(d.row);
            }
            error("(this is not an error) Upgraded LogConfigurationData successfully.");
        } catch (Exception e) {
            error("Error upgrading LogConfigurationData: ", e);  
            return false;
        } 
        return true;
    }
    private boolean upgradeUserDataVO() {
        PreparedStatement ps1 = null;
        PreparedStatement ps2 = null;
        Connection con = null;
        int count = 0;
        try {
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps1 = con.prepareStatement("select fingerprint,userDataVO from CertReqHistoryData");
            ps2 = con.prepareStatement("update CertReqHistoryData set userDataVO=? where fingerprint=?");
            ResultSet rs = ps1.executeQuery();
            se.anatom.ejbca.common.UserDataVO oldud = null;
            while (rs.next()) {
                boolean goon = true;
                String fp = rs.getString(1);
                String ud = rs.getString(2);
                try {
                    java.beans.XMLDecoder decoder = null;
                    try {
                      decoder = new java.beans.XMLDecoder(
                                new java.io.ByteArrayInputStream(ud.getBytes("UTF8")));
                    } catch (UnsupportedEncodingException e) {
                        goon = false;
                    }
                    if (goon) {
                        oldud  = (se.anatom.ejbca.common.UserDataVO)decoder.readObject();                          
                    }
                    decoder.close();
                } catch (Exception e) {
                    error("Can not decode old UserDataVO for fingerprint "+fp+": ", e);
                    goon = false;
                }
                if (goon) {
                    org.ejbca.core.model.ra.UserDataVO newud = createNewUserDataVO(oldud);
                    ByteArrayOutputStream baos = null; 
                    try {
                        baos = new java.io.ByteArrayOutputStream();
                        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
                        encoder.writeObject(newud);
                        encoder.close();
                        String newudstr = baos.toString("UTF8");
                        ps2.setString(1, newudstr);
                        ps2.setString(2, fp);
                        ps2.executeUpdate();                                            
                        count ++;
                    } catch (Exception e) {
                        error("Can not create new UserDataVO for fingerprint "+fp+": ", e);
                    } finally {
                        try {
                            if (baos != null) baos.close();                            
                        } catch (Exception e) {} 
                    }
                }
                if ( (count % 1000) == 0) {
                    error("(this is not an error) migrated "+count+" UserDataVO");
                }
            }
            //con.commit();
        } catch (SQLException sqle) {
            error("Error updating CertReqHistoryData: ", sqle);
            return false;
        } finally {
            JDBCUtil.close(ps1);
            JDBCUtil.close(ps2);
            JDBCUtil.close(con);
        }
        error("(this is not an error) migrated "+count+" UserDataVO");
        return true;
    }
    private org.ejbca.core.model.ra.UserDataVO createNewUserDataVO(se.anatom.ejbca.common.UserDataVO old) {
        org.ejbca.core.model.ra.UserDataVO ret = new org.ejbca.core.model.ra.UserDataVO(
                old.getUsername(), old.getDN(), old.getCAId(),
                old.getSubjectAltName(),old.getEmail(),old.getStatus(),
                old.getType(),old.getEndEntityProfileId(),old.getCertificateProfileId(),
                old.getTimeCreated(),old.getTimeModified(),old.getTokenType(),
                old.getHardTokenIssuerId(),old.getExtendedinformation()
                );
        return ret;
    }
    /**
     * Enum type to hold old logconfigurationdatalocal
     *
     */
    private class LogConfData {
        public Integer id;
        public se.anatom.ejbca.log.LogConfiguration data;
        public int row;
    }
} // UpgradeSessionBean
