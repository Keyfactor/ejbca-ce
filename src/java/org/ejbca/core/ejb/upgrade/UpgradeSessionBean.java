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
import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.cache.AccessTreeUpdateSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.certificateprofile.CertificateProfileData;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.cesecore.util.JBossUnmarshaller;
import org.ejbca.core.ejb.hardtoken.HardTokenData;
import org.ejbca.core.ejb.hardtoken.HardTokenIssuerData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.ejb.ra.raadmin.GlobalConfigurationData;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.SqlExecutor;

/**
 * The upgrade session bean is used to upgrade the database between EJBCA
 * releases.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "UpgradeSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
public class UpgradeSessionBean implements UpgradeSessionLocal, UpgradeSessionRemote {

    private static final Logger log = Logger.getLogger(UpgradeSessionBean.class);

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @Resource
    private SessionContext sessionContext;

    @EJB
    private RoleAccessSessionLocal roleAccessSession;
    @EJB
    private RoleManagementSessionLocal roleMgmtSession;
    @EJB
    private AccessTreeUpdateSessionLocal accessTreeUpdateSession;
    @EJB
    private AccessControlSessionLocal accessControlSession;

    private UpgradeSessionLocal upgradeSession;

    @PostConstruct
    public void ejbCreate() {
    	upgradeSession = sessionContext.getBusinessObject(UpgradeSessionLocal.class);
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public boolean upgrade(AuthenticationToken admin, String dbtype, String sOldVersion, boolean isPost) {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade(" + admin.toString() + ")");
        }
        try {
            log.debug("Upgrading from version=" + sOldVersion);
            final int oldVersion;
            {
                final String[] oldVersionArray = sOldVersion.split("\\."); // Split around the '.'-char
                oldVersion = Integer.parseInt(oldVersionArray[0]) * 100 + Integer.parseInt(oldVersionArray[1]);
            }
            if (isPost) {
                return postUpgrade(oldVersion);
            }
            return upgrade(dbtype, oldVersion);
        } finally {
            log.trace("<upgrade()");
        }
    }

    private boolean postUpgrade(int oldVersion) {
        if (oldVersion < 311) {
            log.error("Only upgrade from EJBCA 3.11.x is supported in EJBCA 4.0.x.");
            return false;
        }
        // Upgrade database change between EJBCA 3.11.x and EJBCA 4.0.x if needed
        if (oldVersion < 400) {
            return postMigrateDatabase400();
        }
        // Upgrade database change between EJBCA 4.0.x and EJBCA 5.0.x if needed
        if (oldVersion < 500) {
            return postMigrateDatabase500();
        }
        return false;
    }

    private boolean upgrade(String dbtype, int oldVersion) {
        if (oldVersion <= 311) {
            log.error("Only upgrade from EJBCA 3.11.x is supported in EJBCA 4.0.x and higher.");
            return false;
        }
        // Seamless upgrade between EJBCA 3.11.x and EJBCA 4.0.x and 5.0.x
        return true;
    }

    /**
     * Called from other migrate methods, don't call this directly, call from an
     * interface-method
     * 
     * Not used in EJBCA 4.0.x, but might be later
     */
    private boolean migrateDatabase(String resource) {
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
            con = JDBCUtil.getDBConnection();
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

    /**
     * (ECA-200:) In EJB 2.1 JBoss CMP used it's own serialization method for all Object/BLOB fields.
     * 
     * This affects the following entity fields:
     * - CertificateProfileData.data
     * - HardTokenData.data
     * - HardTokenIssuerData.data
     * - LogConfigurationData.logConfiguration
     * - AdminPreferencesData.data
     * - EndEntityProfileData.data
     * - GlobalConfigurationData.data
     * 
     * NOTE: You only need to run this if you upgrade a JBoss installation.
     */
    private boolean postMigrateDatabase400() {
    	log.error("(this is not an error) Starting post upgrade from ejbca 3.11.x to ejbca 4.0.x");
    	boolean ret = true;
    	upgradeSession.postMigrateDatabase400SmallTables();	// Migrate small tables in a new transaction 
    	log.info(" Processing HardTokenData entities.");
    	log.info(" - Building a list of entities.");
    	final List<String> tokenSNs = HardTokenData.findAllTokenSN(entityManager);
    	int position = 0;
    	final int chunkSize = 1000;
    	while (position < tokenSNs.size()) {
        	log.info(" - Processing entity " + position + " to " + Math.min(position+chunkSize-1, tokenSNs.size()-1) + ".");
        	// Migrate HardTokenData table in chunks, each running in a new transaction
    		upgradeSession.postMigrateDatabase400HardTokenData(getSubSet(tokenSNs, position, chunkSize));
    		position += chunkSize;
    	}
    	log.error("(this is not an error) Finished post upgrade from ejbca 3.11.x to ejbca 4.0.x with result: "+ret);
        return ret;
    }
    
    /** @return a subset of the source list with index as its first item and index+count-1 as its last. */
    private <T> List<T> getSubSet(final List<T> source, final int index, final int count) {
    	List<T> ret = new ArrayList<T>(count);
    	for (int i=0; i<count; i++) {
    		ret.add(source.get(index + i));
    	}
    	return ret;
    }

    @Override
    public void postMigrateDatabase400SmallTables() {
    	// LogConfiguration removed for EJBCA 5.0, so no upgrade of that needed
    	log.info(" Processing CertificateProfileData entities.");
    	final List<CertificateProfileData> cpds = CertificateProfileData.findAll(entityManager);
    	for (CertificateProfileData cpd : cpds) {
    		// When the wrong class is given it can either return null, or throw an exception
    		HashMap h = getDataUnsafe(cpd.getDataUnsafe());
    		cpd.setDataUnsafe(h);
    	}
    	log.info(" Processing HardTokenIssuerData entities.");
    	final List<HardTokenIssuerData> htids = HardTokenIssuerData.findAll(entityManager);
    	for (HardTokenIssuerData htid : htids) {
    		HashMap h = getDataUnsafe(htid.getDataUnsafe());
    		htid.setDataUnsafe(h);
    	}
    	log.info(" Processing AdminPreferencesData entities.");
    	final List<AdminPreferencesData> apds = AdminPreferencesData.findAll(entityManager);
    	for (AdminPreferencesData apd : apds) {
    		HashMap h = getDataUnsafe(apd.getDataUnsafe());
    		apd.setDataUnsafe(h);
    	}
    	log.info(" Processing EndEntityProfileData entities.");
    	final List<EndEntityProfileData> eepds = EndEntityProfileData.findAll(entityManager);
    	for (EndEntityProfileData eepd : eepds) {
    		HashMap h = getDataUnsafe(eepd.getDataUnsafe());
    		eepd.setDataUnsafe(h);
    	}
    	log.info(" Processing GlobalConfigurationData entities.");
    	GlobalConfigurationData gcd = GlobalConfigurationData.findByConfigurationId(entityManager, "0");
		HashMap h = getDataUnsafe(gcd.getDataUnsafe());
    	gcd.setDataUnsafe(h);
    }

	/**
	 * @param cpd
	 * @return
	 */
	private HashMap getDataUnsafe(Serializable s) {
		HashMap h = null; 
		try {
			h = JBossUnmarshaller.extractObject(LinkedHashMap.class, s);
			if (h == null) {
				h = new LinkedHashMap(JBossUnmarshaller.extractObject(HashMap.class, s));
			}
		} catch (ClassCastException e) {
			h = new LinkedHashMap(JBossUnmarshaller.extractObject(HashMap.class, s));
		}
		return h;
	}
    
    @Override
    public void postMigrateDatabase400HardTokenData(List<String> subSet) {
    	for (String tokenSN : subSet) {
    		HardTokenData htd = HardTokenData.findByTokenSN(entityManager, tokenSN);
    		if (htd != null) {
        		HashMap h = getDataUnsafe(htd);
        		htd.setDataUnsafe(h);
    		} else {
    	    	log.warn("Hard token was removed during processing. Ignoring token with serial number '" + tokenSN + "'.");
    		}
    	}
    }
    
    /**
     * In EJBCA 5.0 we have introduced a new authorization rule system.
     * The old "/super_administrator" rule is replaced by a rule to access "/" with recursive=true.
     * therefore we must insert a new acess rule in the database in all roles that have super_administrator access.
     * @throws AuthorizationDeniedException 
     * @throws RoleNotFoundException 
     * @throws AccessRuleNotFoundException 
     * 
     */
    private boolean postMigrateDatabase500() {
    	log.error("(this is not an error) Starting post upgrade from ejbca 4.0.x to ejbca 5.0.x");
    	boolean ret = true;
    	AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("UpgradeSessionBean.postMigrateDatabase500"));
    	Collection<RoleData> roles = roleAccessSession.getAllRoles();
    	for (RoleData role : roles) {
    		Map<Integer, AccessRuleData> rulemap = role.getAccessRules();
    		Collection<AccessRuleData> rules = rulemap.values();
    		for (AccessRuleData rule : rules) {
    			if (StringUtils.equals(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, rule.getAccessRuleName()) && 
    					rule.getInternalState().equals(AccessRuleState.RULE_ACCEPT)) {
    				// Now we add a new rule
    				log.info("Adding new access rule of '/' on role: "+role.getRoleName());
    		    	AccessRuleData slashrule = new AccessRuleData(role.getRoleName(), "/", AccessRuleState.RULE_ACCEPT, true);
    	        	Collection<AccessRuleData> newrules = new ArrayList<AccessRuleData>();
    	        	newrules.add(slashrule);
    	    		try {
						roleMgmtSession.addAccessRulesToRole(admin, role, newrules);
					} catch (AccessRuleNotFoundException e) {
						log.error("Not possible to add new access rule to role: "+role.getRoleName(), e);
					} catch (RoleNotFoundException e) {
						log.error("Not possible to add new access rule to role: "+role.getRoleName(), e);
					} catch (AuthorizationDeniedException e) {
						log.error("Not possible to add new access rule to role: "+role.getRoleName(), e);
					}
    			}
    		}
		}
    	accessTreeUpdateSession.signalForAccessTreeUpdate();
    	accessControlSession.forceCacheExpire();
    	log.error("(this is not an error) Finished post upgrade from ejbca 4.0.x to ejbca 5.0.x with result: "+ret);
        return ret;
    }

}
