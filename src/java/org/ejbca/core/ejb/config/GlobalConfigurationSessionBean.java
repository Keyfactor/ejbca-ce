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

package org.ejbca.core.ejb.config;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.raadmin.GlobalConfigurationData;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;

/**
 * This bean handled global configurations.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "GlobalConfigurationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class GlobalConfigurationSessionBean implements GlobalConfigurationSessionLocal, GlobalConfigurationSessionRemote {

    private static final Logger log = Logger.getLogger(GlobalConfigurationSessionBean.class);
    
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    /**
     * Cache variable containing the global configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Uses volatile internal to make it thread friendly.
     */
    private static final GlobalConfigurationCache globalconfigurationCache = new GlobalConfigurationCache();
    
    private final AlwaysAllowLocalAuthenticationToken internalAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal GlobalConfiguration Admin"));

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private AccessControlSessionLocal accessSession;

    @Override
    public GlobalConfiguration flushCache() {
        GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, "0");
        GlobalConfiguration result = null;
        if (gcdata != null) {
            result = gcdata.getGlobalConfiguration();
            globalconfigurationCache.setGlobalconfiguration(result);
        }
        return result;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Properties getAllProperties(AuthenticationToken admin) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, AccessRulesConstants.ROLE_ROOT)) {
            String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.ROLE_ROOT, null);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null, null, details);
            throw new AuthorizationDeniedException(msg);
        } 

        Properties ejbca = EjbcaConfigurationHolder.getAsProperties();
        Properties cesecore = ConfigurationHolder.getAsProperties();
        for (Iterator<Object> iterator = ejbca.keySet().iterator(); iterator.hasNext();) {
            String key = (String)iterator.next();
            cesecore.setProperty(key, ejbca.getProperty(key));            
        }
        return cesecore;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public GlobalConfiguration getCachedGlobalConfiguration() {
        GlobalConfiguration result;
        try {
            if (log.isTraceEnabled()) {
                log.trace(">loadGlobalConfiguration()");
            }
            // Only do the actual SQL query if we might update the configuration
            // due to cache time anyhow
            if (!globalconfigurationCache.needsUpdate()) {
                result = globalconfigurationCache.getGlobalconfiguration();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Reading GlobalConfiguration");
                }
                GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, "0");
                if (gcdata != null) {
                    result = gcdata.getGlobalConfiguration();
                    globalconfigurationCache.setGlobalconfiguration(result);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No default GlobalConfiguration exists. Trying to create a new one.");
                    }
                    result = new GlobalConfiguration();
                    try {
                        saveGlobalConfiguration(internalAdmin, result);
                    } catch (AuthorizationDeniedException e) {
                        throw new RuntimeException("Internal admin was denied access. This should not be able to happen.");
                    }
                }
            }
            return result;
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<loadGlobalConfiguration()");
            }
        }
    }
    
    @Override
    public void saveGlobalConfiguration(final AuthenticationToken admin, final GlobalConfiguration globconf) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">saveGlobalConfiguration()");
        }
        if (this.accessSession.isAuthorizedNoLogging(admin, "/")) {
            final String pk = "0";
            final GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, pk);
            if (gcdata != null) {
                // Save object and create a diff over what has changed
                @SuppressWarnings("unchecked")
                final Map<Object, Object> orgmap = (Map<Object, Object>) gcdata.getGlobalConfiguration().saveData();
                gcdata.setGlobalConfiguration(globconf);
                @SuppressWarnings("unchecked")
                final Map<Object, Object> newmap = (Map<Object, Object>) globconf.saveData();
                // Get the diff of what changed
                final Map<Object, Object> diff = UpgradeableDataHashMap.diffMaps(orgmap, newmap);
                // Make security audit log record
                final String msg = intres.getLocalizedMessage("ra.savedconf", gcdata.getConfigurationId());
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                    details.put(entry.getKey().toString(), entry.getValue().toString());
                }
                auditSession.log(EjbcaEventTypes.SYSTEMCONF_EDIT, EventStatus.SUCCESS, EjbcaModuleTypes.GLOBALCONF, EjbcaServiceTypes.EJBCA,
                        admin.toString(), null, null, null, details);
            } else {
                // Global configuration doesn't yet exists.
                try {
                    entityManager.persist(new GlobalConfigurationData(pk, globconf));
                    final String msg = intres.getLocalizedMessage("ra.createdconf", pk);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    auditSession.log(EjbcaEventTypes.SYSTEMCONF_CREATE, EventStatus.SUCCESS, EjbcaModuleTypes.GLOBALCONF, EjbcaServiceTypes.EJBCA,
                            admin.toString(), null, null, null, details);
                } catch (Exception e) {
                    final String msg = intres.getLocalizedMessage("ra.errorcreateconf");
                    log.info(msg, e);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    details.put("error", e.getMessage());
                    auditSession.log(EjbcaEventTypes.SYSTEMCONF_CREATE, EventStatus.FAILURE, EjbcaModuleTypes.GLOBALCONF, EjbcaServiceTypes.EJBCA,
                            admin.toString(), null, null, null, details);
                }
            }
            globalconfigurationCache.setGlobalconfiguration(globconf);
        } else {
            throw new AuthorizationDeniedException("Authorization was denied to user " + admin
                    + " to resource /. Could not save configuration.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<saveGlobalConfiguration()");
        }
    }

    @Override
    public void flushGlobalConfigurationCache()  {
    	if (log.isTraceEnabled()) {
    		log.trace(">flushGlobalConfigurationCache()");
    	}
    	globalconfigurationCache.clearCache();
    	getCachedGlobalConfiguration();
    	if (log.isDebugEnabled()) {
    		log.debug("Flushed global configuration cache.");
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<flushGlobalConfigurationCache()");
    	}
    }

    @Override
    public void setSettingIssueHardwareTokens(AuthenticationToken admin, boolean value) throws AuthorizationDeniedException {
    	final GlobalConfiguration config = flushCache();
    	config.setIssueHardwareTokens(value);
    	saveGlobalConfiguration(admin, config);
    }

}
