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

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.approval.ApprovalData;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.AdminEntityData;
import org.ejbca.core.ejb.authorization.AdminGroupData;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.authorization.AccessRule;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.SqlExecutor;
import org.ejbca.util.keystore.KeyTools;

/**
 * The upgrade session bean is used to upgrade the database between ejbca
 * releases.
 * 
 * @version $Id$
 * @ejb.bean display-name="UpgradeSB" name="UpgradeSession"
 *           jndi-name="UpgradeSession" view-type="both" type="Stateless"
 *           transaction-type="Container" generate="true"
 * 
 * @ejb.transaction type="RequiresNew"
 * 
 * @weblogic.enable-call-by-reference True
 * 
 * @ejb.home extends="javax.ejb.EJBHome" local-extends="javax.ejb.EJBLocalHome"
 *           local-class="org.ejbca.core.ejb.upgrade.IUpgradeSessionLocalHome"
 *           remote-class="org.ejbca.core.ejb.upgrade.IUpgradeSessionHome"
 * 
 * @ejb.env-entry name="DataSource" type="java.lang.String"
 *                value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 * 
 * @ejb.interface extends="javax.ejb.EJBObject"
 *                local-extends="javax.ejb.EJBLocalObject"
 *                local-class="org.ejbca.core.ejb.upgrade.IUpgradeSessionLocal"
 *                remote
 *                -class="org.ejbca.core.ejb.upgrade.IUpgradeSessionRemote"
 * 
 * @ejb.ejb-external-ref description="The Log Configuration Data Entity bean"
 *                       view-type="local"
 *                       ref-name="ejb/LogConfigurationDataLocal" type="Entity"
 *                       home=
 *                       "org.ejbca.core.ejb.log.LogConfigurationDataLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.log.LogConfigurationDataLocal"
 *                       link="LogConfigurationData"
 * 
 * @ejb.ejb-external-ref description="The CA Admin Session" view-type="local"
 *                       ref-name="ejb/CAAdminSessionLocal" type="Session"
 *                       home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *                       link="CAAdminSession"
 * 
 * @ejb.ejb-external-ref description="Admin Groups" view-type="local"
 *                       ref-name="ejb/AdminGroupDataLocal" type="Entity"
 *                       home="org.ejbca.core.ejb.authorization.AdminGroupDataLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.authorization.AdminGroupDataLocal"
 *                       link="AdminGroupData"
 * 
 * @ejb.ejb-external-ref description="The Approval Session Bean"
 *                       view-type="local" ref-name="ejb/ApprovalSessionLocal"
 *                       type="Session"
 *                       home="org.ejbca.core.ejb.approval.IApprovalSessionLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.approval.IApprovalSessionLocal"
 *                       link="ApprovalSession"
 * 
 * @ejb.ejb-external-ref description="The Approval entity bean"
 *                       view-type="local" ref-name="ejb/ApprovalDataLocal"
 *                       type="Entity"
 *                       home="org.ejbca.core.ejb.approval.ApprovalDataLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.approval.ApprovalDataLocal"
 *                       link="ApprovalData"
 * 
 * @ejb.ejb-external-ref description="The User Admin session bean"
 *                       view-type="local" ref-name="ejb/UserAdminSessionLocal"
 *                       type="Session"
 *                       home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *                       business="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *                       link="UserAdminSession"
 * 
 * @ejb.ejb-external-ref 
 *                       description="The Certificate store used to store and fetch certificates"
 *                       view-type="local"
 *                       ref-name="ejb/CertificateStoreSessionLocal"
 *                       type="Session"
 *                       home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *                       link="CertificateStoreSession"
 * 
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "UpgradeSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
public class UpgradeSessionBean implements UpgradeSessionLocal, UpgradeSessionRemote {

    private static final Logger log = Logger.getLogger(UpgradeSessionBean.class);

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private UserAdminSessionLocal userAdminSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;

    /**
     * Upgrades the database
     * 
     * @ejb.interface-method
     * @jboss.method-attributes transaction-timeout="3600"
     * 
     * @param admin
     * @return true or false if upgrade was done or not
     */
    public boolean upgrade(Admin admin, String dbtype, String sOldVersion, boolean isPost) {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade(" + admin.toString() + ")");
        }
        try {
            log.debug("Upgrading from version=" + sOldVersion);
            final int oldVersion;
            {
                final String[] oldVersionArray = sOldVersion.split("\\."); // Split
                                                                           // around
                                                                           // the
                                                                           // '.'-char
                oldVersion = Integer.parseInt(oldVersionArray[0]) * 100 + Integer.parseInt(oldVersionArray[1]);
            }
            if (isPost) {
                return postUpgrade(oldVersion);
            }
            return upgrade(admin, dbtype, oldVersion);
        } finally {
            log.trace("<upgrade()");
        }
    }

    private boolean postUpgrade(int oldVersion) {
        // Upgrade database change between ejbca 3.9.x and 3.10.x if needed
        if (oldVersion <= 309) {
            return postMigrateDatabase310();
        }
        // Upgrade database change between ejbca 3.9.x and 3.10.x if needed
        if (oldVersion <= 400) {
            return postMigrateDatabase400();
        }
        return false;
    }

    private boolean upgrade(Admin admin, String dbtype, int oldVersion) {
        // Upgrade database change between ejbca 3.1.x and 3.2.x if needed
        if (oldVersion <= 301) {
            log.error("Upgrade from EJBCA 3.1.x is no longer supported in EJBCA 3.9.x and later.");
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
        // Upgrade database change between ejbca 3.10.x and 4.0.x if needed
        if (oldVersion <= 310) {
            if (!migrateDatabase400(dbtype)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Called from other migrate methods, don't call this directly, call from an
     * interface-method
     */
    private boolean migradeDatabase(String resource) {
        // Fetch the resource file with SQL to modify the database tables
        InputStream in = this.getClass().getResourceAsStream(resource);
        if (in == null) {
            log.error("Can not read resource for database '" + resource + "', this database probably does not need table definition changes.");
            // no error
            return true;
        }

        // Migrate database tables to new columns etc
        Connection con = null;
        log.info("Start migration of database.");
        try {
            InputStreamReader inreader = new InputStreamReader(in);
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            SqlExecutor sqlex = new SqlExecutor(con, false);
            sqlex.runCommands(inreader);
        } catch (SQLException e) {
            log.error("SQL error during database migration: ", e);
            return false;
        } catch (IOException e) {
            log.error("IO error during database migration: ", e);
            return false;
        } finally {
            JDBCUtil.close(con);
        }
        return true;
    }

    private boolean migrateDatabase33(String dbtype) {
        log.error("(this is not an error) Starting upgrade from ejbca 3.3.x to ejbca 3.4.x");
        boolean ret = migradeDatabase("/33_34/33_34-upgrade-" + dbtype + ".sql");
        log.error("(this is not an error) Finished migrating database.");
        return ret;
    }

    private boolean migrateDatabase36(String dbtype) {
        log.error("(this is not an error) Starting upgrade from ejbca 3.5.x to ejbca 3.6.x");
        boolean ret = migradeDatabase("/35_36/35_36-upgrade-" + dbtype + ".sql");
        log.error("(this is not an error) Finished migrating database.");
        return ret;
    }

    /**
     * This upgrade will move the CA Id from the admin groups, to each
     * administrator Admingroups with similar names will be renamed with the CA
     * Id as postfix to avoid collisions Also removes the CAId from access rules
     * primary key (since only group name is neccesary now)
     */
    private boolean migrateDatabase38(String dbtype, Admin administrator) {
        log.error("(this is not an error) Starting upgrade from ejbca 3.7.x to ejbca 3.8.x");
        boolean ret = migradeDatabase("/37_38/37_38-upgrade-" + dbtype + ".sql");

        // Change the name of AdminGroups with conflicting names
        Collection<AdminGroupData> adminGroupDatas = AdminGroupData.findAll(entityManager);
        Iterator<AdminGroupData> i = adminGroupDatas.iterator();
        ArrayList<String> groupNames = new ArrayList<String>();
        while (i.hasNext()) {
            AdminGroupData adminGroupData = i.next();
            String currentName = adminGroupData.getAdminGroupName();
            if (groupNames.contains(currentName)) {
                if (currentName.equals(AdminGroup.PUBLICWEBGROUPNAME)) {
                    // We don't need a group for each CA any longer
                    try {
                        adminGroupData.removeAccessRulesObjects(entityManager, adminGroupData.getAccessRuleObjects());
                        adminGroupData.removeAdminEntities(entityManager, adminGroupData.getAdminEntityObjects());
                        entityManager.remove(adminGroupData);
                        // adminGroupData.remove();
                    } catch (EJBException e) {
                        log.error("Failed to remove duplicate \"" + AdminGroup.PUBLICWEBGROUPNAME + "\"", e);
                    } catch (IllegalArgumentException e) {
                        log.error("Failed to remove duplicate \"" + AdminGroup.PUBLICWEBGROUPNAME + "\"", e);
                    }
                } else {
                    // Conflicting name. We need to change it.
                    adminGroupData.setAdminGroupName(currentName + "_" + caAdminSession.getCAIdToNameMap(administrator).get(adminGroupData.getCaId()));
                }
            } else {
                groupNames.add(currentName);
            }
        }
        // Read the CA Id from each AdminGroup and write it to each entity
        Iterator<AdminGroupData> iter = AdminGroupData.findAll(entityManager).iterator();
        while (iter.hasNext()) {
            AdminGroupData adminGroupData = iter.next();
            Collection<AdminEntityData> adminEntityObjects = adminGroupData.getAdminEntities();
            Iterator<AdminEntityData> i2 = adminEntityObjects.iterator();
            while (i2.hasNext()) {
                AdminEntityData adminEntityData = i2.next();
                adminEntityData.setCaId(adminGroupData.getCaId());
            }
        }
        // Update access rules to not use a caid in the primary key
        Iterator<AdminGroupData> i3 = AdminGroupData.findAll(entityManager).iterator();
        while (i3.hasNext()) {
            AdminGroupData adminGroupData = i3.next();
            Collection<AccessRule> accessRules = adminGroupData.getAccessRuleObjects();
            adminGroupData.removeAccessRulesObjects(entityManager, accessRules);
            adminGroupData.addAccessRules(entityManager, accessRules);
        }
        log.error("(this is not an error) Finished migrating database.");
        return ret;
    }

    private boolean migrateDatabase39(String dbtype) {
        log.error("(this is not an error) Starting upgrade from ejbca 3.8.x to ejbca 3.9.x");
        boolean ret = migradeDatabase("/38_39/38_39-upgrade-" + dbtype + ".sql");
        log.error("(this is not an error) Finished migrating database.");
        return ret;
    }

    /**
     * We need to update all pending ApprovalsRequests since the Admin objects'
     * now have username and email. We need to update all pending Approvals
     * since the it now stores an Admin object instead of pure information on
     * the admin certificate.
     */
    private boolean migrateDatabase310(String dbtype) {
        log.error("(this is not an error) Starting upgrade from ejbca 3.9.x to ejbca 3.10.x");
        boolean ret = migradeDatabase("/39_310/39_310-upgrade-" + dbtype + ".sql");
        if (ret) {
            List<Integer> approvalIds = approvalSession.getAllPendingApprovalIds();
            for (int i = 0; i < approvalIds.size(); i++) {
                Integer approvalId = approvalIds.get(i);
                Collection<ApprovalData> approvalDatas = ApprovalData.findByApprovalId(entityManager, approvalId.intValue());
                if (approvalDatas.size() < 1 || approvalDatas.size() > 1) {
                    log.warn("There is an error in the database. You have " + approvalDatas.size() + " entries w approvalId " + approvalId.intValue());
                }
                final Iterator<ApprovalData> iterator = approvalDatas.iterator();
                while (iterator.hasNext()) {
                    final ApprovalData approvalData = iterator.next();
                    final ApprovalRequest approvalRequest = approvalData.getApprovalRequest();
                    final Admin requestAdmin = approvalRequest.getRequestAdmin();
                    if (requestAdmin.getAdminType() == Admin.TYPE_CLIENTCERT_USER) {
                        // Upgrade the request admin if it of type
                        // CLIENT_CERT_USER
                        final Certificate adminCert = requestAdmin.getAdminInformation().getX509Certificate();
                        approvalRequest.setRequestAdmin(userAdminSession.getAdmin(adminCert));
                        approvalData.setApprovalRequest(approvalRequest);

                    } else {
                        log.debug("Ignoring upgrade of approval request initialed by admin of type " + requestAdmin.getAdminType());
                    }
                    final Collection<Approval> approvals = approvalData.getApprovals();
                    final Iterator<Approval> iterator2 = approvals.iterator();
                    while (iterator2.hasNext()) {
                        final Approval approval = iterator2.next();
                        // Lookup admin certificate that was used to approve
                        // this request and set a proper Admin that includes the
                        // admin certificate
                        final String issuerDN = approval.getAdminCertIssuerDN();
                        final BigInteger serialNumber = approval.getAdminCertSerialNumber();
                        if (issuerDN != null && serialNumber != null) {
                            final Certificate certificate = certificateStoreSession.findCertificateByIssuerAndSerno(new Admin(Admin.TYPE_INTERNALUSER),
                                    issuerDN, serialNumber);
                            if (certificate == null) {
                                // The approval was created with a certificate
                                // does not exist in the EJBCA database (an
                                // external Admin)
                                log
                                        .warn("External Admin with issuerDN '"
                                                + issuerDN
                                                + "' and serialNumer '"
                                                + serialNumber
                                                + "' does not have a certificate in the EJBCA database. Approval Admin will be set to Admin.TYPE_INTERNALUSER as a workaround.");
                                approval.setApprovalAdmin(approval.isApproved(), new Admin(Admin.TYPE_INTERNALUSER));
                            } else {
                                // Create a new Admin object from the
                                // certificate
                                approval.setApprovalAdmin(approval.isApproved(), userAdminSession.getAdmin(certificate));
                            }
                        } else {
                            log.error("Approval in ApprovalData w approvalId " + approvalId + " lacks issuerDN or serialNumber");
                        }
                    }
                }
            }
        }
        log.error("(this is not an error) Finished migrating database.");
        return ret;
    }

    private boolean postMigrateDatabase310() {
        log.error("(this is not an error) Starting post upgrade from ejbca 3.9.x to ejbca 3.10.x");
        final String lKeyID = "subjectKeyId";
        final String lCert = "base64Cert";
        final String lFingerPrint = "fingerprint";
        final Connection connection = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
        try {
            final Statement stmt = connection.createStatement(ResultSet.TYPE_FORWARD_ONLY, ResultSet.CONCUR_UPDATABLE);
            final ResultSet srs = stmt.executeQuery("select " + lFingerPrint + "," + lKeyID + "," + lCert + " from CertificateData where " + lKeyID
                    + " IS NULL");
            final int iKeyID; // it should be faster to use column number
                              // instead of column label.
            final int iCert;
            {
                final ResultSetMetaData rsmd = srs.getMetaData();
                final Map<String, Integer> map = new HashMap<String, Integer>();
                for (int i = 1; i <= rsmd.getColumnCount(); i++) {
                    map.put(rsmd.getColumnLabel(i).toLowerCase(), new Integer(i));
                }
                iKeyID = map.get(lKeyID.toLowerCase()).intValue();
                iCert = map.get(lCert.toLowerCase()).intValue();
            }
            while (srs.next()) {
                final Certificate cert;
                try {
                    cert = CertTools.getCertfromByteArray(Base64.decode(srs.getString(iCert).getBytes()));
                } catch (CertificateException e) {
                    log.error("Certificate could not be parsed.", e);
                    continue;
                }
                srs.updateString(iKeyID, new String(Base64.encode(KeyTools.createSubjectKeyId(cert.getPublicKey()).getKeyIdentifier(), false)));
                srs.updateRow();
            }
            srs.close();
            stmt.close();
            log.error("(this is not an error) Finished post upgrade.");
            return true;
        } catch (SQLException e) {
            log.error("post upgrade failed. See exception:", e);
        } finally {
            if (connection != null) {
                try {
                    connection.close();
                } catch (SQLException e) {
                    // just ignore. other exception has been thrown before for
                    // the problem
                }
            }
        }
        return false;
    }

    private boolean migrateDatabase400(String dbtype) {
        log.error("(this is not an error) Starting post upgrade from ejbca 3.10.x to ejbca 4.0.x");
        boolean ret = migradeDatabase("/310_40/310_40-upgrade-" + dbtype + ".sql");
        log.error("(this is not an error) Finished migrating database.");
        return ret;
    }

    private boolean postMigrateDatabase400() {
        // TODO: Here we could access all serialized objects so they are stored
        // in a non-JBoss-proprietary way and allow an app-server switch..
        log.error("Post upgrade not yet implemented for EJBCA 4.0.x.");
        return false;
    }
}
