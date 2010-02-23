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

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.approval.ApprovalDataLocal;
import org.ejbca.core.ejb.approval.ApprovalDataLocalHome;
import org.ejbca.core.ejb.approval.IApprovalSessionLocal;
import org.ejbca.core.ejb.approval.IApprovalSessionLocalHome;
import org.ejbca.core.ejb.authorization.AdminEntityDataLocal;
import org.ejbca.core.ejb.authorization.AdminGroupDataLocal;
import org.ejbca.core.ejb.authorization.AdminGroupDataLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.SqlExecutor;
import org.ejbca.util.keystore.KeyTools;

/** The upgrade session bean is used to upgrade the database between ejbca releases.
 *
 * @version $Id$
 * @ejb.bean
 *   display-name="UpgradeSB"
 *   name="UpgradeSession"
 *   jndi-name="UpgradeSession"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *   generate="true"
 *
 * @ejb.transaction type="RequiresNew"
 * 
 * @weblogic.enable-call-by-reference True
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
 *   ref-name="ejb/LogConfigurationDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.log.LogConfigurationDataLocalHome"
 *   business="org.ejbca.core.ejb.log.LogConfigurationDataLocal"
 *   link="LogConfigurationData"
 * 
 * @ejb.ejb-external-ref
 *   description="The CA Admin Session"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *   
 * @ejb.ejb-external-ref
 *   description="Admin Groups"
 *   view-type="local"
 *   ref-name="ejb/AdminGroupDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.authorization.AdminGroupDataLocalHome"
 *   business="org.ejbca.core.ejb.authorization.AdminGroupDataLocal"
 *   link="AdminGroupData"
 *
 * @ejb.ejb-external-ref description="The Approval Session Bean"
 *   view-type="local"
 *   ref-name="ejb/ApprovalSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.approval.IApprovalSessionLocalHome"
 *   business="org.ejbca.core.ejb.approval.IApprovalSessionLocal"
 *   link="ApprovalSession"
 *   
 * @ejb.ejb-external-ref description="The Approval entity bean"
 *   view-type="local"
 *   ref-name="ejb/ApprovalDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.approval.ApprovalDataLocalHome"
 *   business="org.ejbca.core.ejb.approval.ApprovalDataLocal"
 *   link="ApprovalData"
 *   
 * @ejb.ejb-external-ref
 *   description="The User Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/UserAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *   link="UserAdminSession"
 *
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 */
public class UpgradeSessionBean extends BaseSessionBean {

    /** The local interface of the CA Admin session bean */
    private ICAAdminSessionLocal caadminsession;
	private IApprovalSessionLocal approvalSession;
	private IUserAdminSessionLocal userAdminSession;
	private ICertificateStoreSessionLocal certificateStoreSession;
    
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {  /* nothing to create */ }

    private IApprovalSessionLocal getApprovalSession() {
    	if (this.approvalSession == null) {
    		try {
    			IApprovalSessionLocalHome home = (IApprovalSessionLocalHome)getLocator().getLocalHome(IApprovalSessionLocalHome.COMP_NAME);
    			this.approvalSession = home.create();
    		} catch(Exception e) {
    			throw new EJBException(e);
    		}
    	}
    	return this.approvalSession;
    }

    private IUserAdminSessionLocal getUserAdminSession() {
		if (this.userAdminSession == null) {
    		try {
    			IUserAdminSessionLocalHome home = (IUserAdminSessionLocalHome)getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
    			this.userAdminSession = home.create();
    		} catch(Exception e) {
    			throw new EJBException(e);
    		}
    	}
    	return this.userAdminSession;
    }

    private ICertificateStoreSessionLocal getCertificateStoreSession() {
		if (this.certificateStoreSession == null) {
    		try {
    			ICertificateStoreSessionLocalHome home = (ICertificateStoreSessionLocalHome)getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
    			this.certificateStoreSession = home.create();
    		} catch(Exception e) {
    			throw new EJBException(e);
    		}
    	}
    	return this.certificateStoreSession;
    }

    /** 
     * Gets connection to ca admin session bean
     */
    private ICAAdminSessionLocal getCaAdminSession() {
        if(this.caadminsession == null){
          try{
              ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome)getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
              this.caadminsession = caadminsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return this.caadminsession;
    } //getCaAdminSession


    /** Upgrades the database
     * @ejb.interface-method
     * @jboss.method-attributes transaction-timeout="3600"
     * 
     * @param admin
     * @return true or false if upgrade was done or not
     */
    public boolean upgrade(Admin admin, String dbtype, String sOldVersion, boolean isPost) {
    	if (this.log.isTraceEnabled()) {
            this.log.trace(">upgrade("+admin.toString()+")");
    	}
    	try {
    		debug("Upgrading from version="+sOldVersion);
    		final int oldVersion; {
    			final String[] oldVersionArray = sOldVersion.split("\\.");	// Split around the '.'-char
    			oldVersion = Integer.parseInt(oldVersionArray[0]) * 100 + Integer.parseInt(oldVersionArray[1]);
    		}
    		if ( isPost ) {
    			return postUpgrade(admin, dbtype, oldVersion);
    		}
    		return upgrade(admin, dbtype, oldVersion);
    	} finally {
    		this.log.trace("<upgrade()");
    	}
    }
    private boolean postUpgrade(Admin admin, String dbtype, int oldVersion) {
    	// Upgrade database change between ejbca 3.9.x and 3.10.x if needed
        if (oldVersion <= 309) {
        	return postMigrateDatabase310(dbtype);
        }
    	return false;
    }
    private boolean upgrade(Admin admin, String dbtype, int oldVersion) {
        // Upgrade database change between ejbca 3.1.x and 3.2.x if needed
        if (oldVersion <= 301) {
        	error("Upgrade from EJBCA 3.1.x is no longer supported in EJBCA 3.9.x and later.");
        	return false;
        }

        // Upgrade database change between ejbca 3.3.x and 3.4.x if needed
        if (oldVersion <= 303) {
        	if (!migrateDatabase33(dbtype)) {
        		return false;
        	}
        }
    	// Upgrade database change between ejbca 3.5.x and 3.6.x if needed
        if (oldVersion <= 305) {
        	if (!migrateDatabase36(dbtype)) {
        		return false;
        	}
        }
    	// Upgrade database change between ejbca 3.7.x and 3.8.x if needed
        if (oldVersion <= 307) {
        	if (!migrateDatabase38(dbtype, admin)) {
        		return false;
        	}
        }
    	// Upgrade database change between ejbca 3.8.x and 3.9.x if needed
        if (oldVersion <= 308) {
        	if (!migrateDatabase39(dbtype)) {
        		return false;
        	}
        }
    	// Upgrade database change between ejbca 3.9.x and 3.10.x if needed
        if (oldVersion <= 309) {
        	if (!migrateDatabase310(dbtype)) {
        		return false;
        	}
        }
        return true;
    }


    /** Called from other migrate methods, don't call this directly, call from an interface-method
     */
	private boolean migradeDatabase(String resource) {
        // Fetch the resource file with SQL to modify the database tables
        InputStream in = this.getClass().getResourceAsStream(resource);
        if (in == null) {
        	error("Can not read resource for database '"+resource+"', this database probably does not need table definition changes.");
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
        return true;
	}

	private boolean migrateDatabase33(String dbtype) {
		error("(this is not an error) Starting upgrade from ejbca 3.3.x to ejbca 3.4.x");
		boolean ret = migradeDatabase("/33_34/33_34-upgrade-"+dbtype+".sql");
        error("(this is not an error) Finished migrating database.");
        return ret;
	}
	private boolean migrateDatabase36(String dbtype) {
		error("(this is not an error) Starting upgrade from ejbca 3.5.x to ejbca 3.6.x");
		boolean ret = migradeDatabase("/35_36/35_36-upgrade-"+dbtype+".sql");
        error("(this is not an error) Finished migrating database.");
        return ret;
	}
    /** 
     * This upgrade will move the CA Id from the admin groups, to each administrator
     * Admingroups with similar names will be renamed with the CA Id as postfix to avoid collisions
     * Also removes the CAId from access rules primary key (since only group name is neccesary now) 
     */
	private boolean migrateDatabase38(String dbtype, Admin administrator) {
		error("(this is not an error) Starting upgrade from ejbca 3.7.x to ejbca 3.8.x");
		boolean ret = migradeDatabase("/37_38/37_38-upgrade-"+dbtype+".sql");
		
		AdminGroupDataLocalHome adminGroupHome = (AdminGroupDataLocalHome) ServiceLocator.getInstance().getLocalHome(AdminGroupDataLocalHome.COMP_NAME);
		// Change the name of AdminGroups with conflicting names
		try {
			Collection adminGroupDatas = adminGroupHome.findAll();
			Iterator i = adminGroupDatas.iterator();
			ArrayList groupNames = new ArrayList();	// <String>
			while (i.hasNext()) {
				AdminGroupDataLocal adminGroupData = (AdminGroupDataLocal) i.next();
				String currentName = adminGroupData.getAdminGroupName();
				if (groupNames.contains(currentName)) {
					if (currentName.equals(AdminGroup.PUBLICWEBGROUPNAME)) {
						// We don't need a group for each CA and longer
						try {
							adminGroupData.removeAccessRulesObjects(adminGroupData.getAccessRuleObjects());
							adminGroupData.removeAdminEntities(adminGroupData.getAdminEntityObjects());
							adminGroupData.remove();
						} catch (EJBException e) {
							this.log.error("Failed to remove duplicate \"" + AdminGroup.PUBLICWEBGROUPNAME + "\"", e);
						} catch (RemoveException e) {
							this.log.error("Failed to remove duplicate \"" + AdminGroup.PUBLICWEBGROUPNAME + "\"", e);
						}
					} else {
						// Conflicting name. We need to change it.
						adminGroupData.setAdminGroupName(currentName + "_" + getCaAdminSession().getCAIdToNameMap(administrator).get(adminGroupData.getCaId()));
					}
				} else {
					groupNames.add(currentName);
				}
			}
		} catch (FinderException e) {
			throw new EJBException(e);	// There should be at least one group..
		}
		// Read the CA Id from each AdminGroup and write it to each entity
		try {
			Collection adminGroupDatas = adminGroupHome.findAll();
			Iterator i = adminGroupDatas.iterator();
			while (i.hasNext()) {
				AdminGroupDataLocal adminGroupData = (AdminGroupDataLocal) i.next();
				Collection adminEntityObjects = adminGroupData.getAdminEntitesForUpgrade();
				Iterator i2 = adminEntityObjects.iterator();
				while (i2.hasNext()) {
					AdminEntityDataLocal adminEntityData = (AdminEntityDataLocal) i2.next();
					adminEntityData.setCaId(adminGroupData.getCaId());
				}
			}
		} catch (FinderException e) {
			throw new EJBException(e);	// There should be at least one group..
		}
		// Update access rules to not use a caid in the primary key
		try {
			Collection adminGroupDatas = adminGroupHome.findAll();
			Iterator i = adminGroupDatas.iterator();
			while (i.hasNext()) {
				AdminGroupDataLocal adminGroupData = (AdminGroupDataLocal) i.next();
				Collection accessRules = adminGroupData.getAccessRuleObjects();
				adminGroupData.removeAccessRulesObjects(accessRules);
				adminGroupData.addAccessRules(accessRules);
			}
		} catch (FinderException e) {
			throw new EJBException(e);	// There should be at least one group..
		}
	
        error("(this is not an error) Finished migrating database.");
        return ret;
	}

	private boolean migrateDatabase39(String dbtype) {
		error("(this is not an error) Starting upgrade from ejbca 3.8.x to ejbca 3.9.x");
		boolean ret = migradeDatabase("/38_39/38_39-upgrade-"+dbtype+".sql");
        error("(this is not an error) Finished migrating database.");
        return ret;
	}

    /**
     * We need to update all pending ApprovalsRequests since the Admin objects' now have username and email.
     * We need to update all pending Approvals since the it now stores an Admin object instead of pure information on the admin certificate.
     */
	private boolean migrateDatabase310(String dbtype) {
		error("(this is not an error) Starting upgrade from ejbca 3.9.x to ejbca 3.10.x");
		boolean ret = migradeDatabase("/39_310/39_310-upgrade-"+dbtype+".sql");
		if (ret) {
			List approvalIds = getApprovalSession().getAllPendingApprovalIds();
			ApprovalDataLocalHome approvalHome = (ApprovalDataLocalHome) getLocator().getLocalHome(ApprovalDataLocalHome.COMP_NAME);
			for (int i=0; i<approvalIds.size(); i++) {
				Integer approvalId = (Integer)approvalIds.get(i);
				try {
					Collection approvalDataLocals = approvalHome.findByApprovalId(approvalId.intValue());
					if (approvalDataLocals.size() < 1 || approvalDataLocals.size() > 1) {
						warn("There is an error in the database. You have " + approvalDataLocals.size() + " entries w approvalId " + approvalId.intValue());
					}
					final Iterator iterator = approvalDataLocals.iterator();
					while (iterator.hasNext()) {
						final ApprovalDataLocal approvalDataLocal = (ApprovalDataLocal) iterator.next();
						final ApprovalRequest approvalRequest = approvalDataLocal.getApprovalRequest();
						final Admin requestAdmin = approvalRequest.getRequestAdmin();
						if (requestAdmin.getAdminType() == Admin.TYPE_CLIENTCERT_USER) {
							// Upgrade the request admin if it of type CLIENT_CERT_USER
							final Certificate adminCert = requestAdmin.getAdminInformation().getX509Certificate();
							approvalRequest.setRequestAdmin(getUserAdminSession().getAdmin(adminCert));
							approvalDataLocal.setApprovalRequest(approvalRequest);
							
						} else {
							log.debug("Ignoring upgrade of approval request initialed by admin of type " + requestAdmin.getAdminType());
						}
						final Collection approvals = approvalDataLocal.getApprovals();
						final Iterator iterator2 = approvals.iterator();
						while (iterator2.hasNext()) {
							final Approval approval = (Approval) iterator2.next();
							// Lookup admin certificate that was used to approve this request and set a proper Admin that includes the admin certificate
							final String issuerDN = approval.getAdminCertIssuerDN();
							final BigInteger serialNumber = approval.getAdminCertSerialNumber();
							if (issuerDN != null && serialNumber != null) {
								final Certificate certificate = getCertificateStoreSession().findCertificateByIssuerAndSerno(new Admin(Admin.TYPE_INTERNALUSER), issuerDN, serialNumber);
								if (certificate == null) {
									// The approval was created with a certificate does not exist in the EJBCA database (an external Admin)
									log.warn("External Admin with issuerDN '" + issuerDN + "' and serialNumer '" + serialNumber + "' does not have a certificate in the EJBCA database. Approval Admin will be set to Admin.TYPE_INTERNALUSER as a workaround.");
									approval.setApprovalAdmin(approval.isApproved(), new Admin(Admin.TYPE_INTERNALUSER));
								} else {
									// Create a new Admin object from the certificate
									approval.setApprovalAdmin(approval.isApproved(), getUserAdminSession().getAdmin(certificate));
								}
							} else {
								error("Approval in ApprovalData w approvalId " + approvalId + " lacks issuerDN or serialNumber");
							}
						}
					}
				} catch (FinderException e) {
			        error("Could not fetch pending approval with id " + ((Integer)approvalIds.get(i)).intValue());
			        return false;
				}
			}
		}
        error("(this is not an error) Finished migrating database.");
        return ret;
	}
	private boolean postMigrateDatabase310(String dbtype) {
		error("(this is not an error) Starting post upgrade from ejbca 3.9.x to ejbca 3.10.x");
		final String lKeyID = "subjectKeyId";
		final String lCert = "base64Cert";
		final String lFingerPrint = "fingerprint";
		final Connection connection = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
		try {
			final Statement stmt = connection.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_UPDATABLE);
			final ResultSet srs = stmt.executeQuery("select "+lFingerPrint+","+lKeyID+","+lCert+" from CertificateData where "+lKeyID+" IS NULL");
			final int iKeyID; // it should be faster to use column number instead of column label.
			final int iCert;
			{
				final ResultSetMetaData rsmd= srs.getMetaData();
				final Map map = new HashMap();
				for (int i=1; i<=rsmd.getColumnCount(); i++) {
					map.put(rsmd.getColumnLabel(i).toLowerCase(), new Integer(i));
				}
				iKeyID=((Integer)map.get(lKeyID.toLowerCase())).intValue();
				iCert=((Integer)map.get(lCert.toLowerCase())).intValue();
			}
			while ( srs.next() ) {
				final Certificate cert;
				try {
					cert = CertTools.getCertfromByteArray(Base64.decode(srs.getString(iCert).getBytes()));
				} catch (CertificateException e) {
					this.log.error("Certificate could not be parsed.", e);
					continue;
				}
				srs.updateString(iKeyID, new String(Base64.encode(KeyTools.createSubjectKeyId(cert.getPublicKey()).getKeyIdentifier(), false)));
				srs.updateRow();
			}
			srs.close();
			stmt.close();
			error("(this is not an error) Finished post upgrade.");
			return true;
		} catch (SQLException e) {
			error("post upgrade failed. See exception:", e);
		} finally {
			if ( connection!=null ) {
				try {
					connection.close();
				} catch (SQLException e) {
					// just ignore. other exception has been thrown before for the problem
				}
			}
		}
		return false;
	}
}
