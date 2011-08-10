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

import java.util.LinkedHashMap;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.raadmin.GlobalConfigurationData;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.log.LogConstants;

/**
 * This bean handled global configurations.
 * 
 * @version $Id$
 */
@Stateless(mappedName = org.ejbca.core.ejb.JndiHelper.APP_JNDI_PREFIX + "GlobalConfigurationSessionRemote")
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

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
   
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
    public GlobalConfiguration getCachedGlobalConfiguration(AuthenticationToken admin) {
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
                	saveGlobalConfiguration(admin, result);
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
    public void saveGlobalConfigurationRemote(final AuthenticationToken admin, final GlobalConfiguration globconf) {
    	if (log.isTraceEnabled()) {
            log.trace(">saveGlobalConfigurationRemote()");
        }
    	if (EjbcaConfiguration.getIsInProductionMode()) {
    		throw new EJBException("Configuration can not be altered in production mode.");
    	} else {
    		saveGlobalConfiguration(admin, globconf);
    	}
    	if (log.isTraceEnabled()) {
            log.trace("<saveGlobalConfigurationRemote()");
        }
    }
    
    @Override
    public void saveGlobalConfiguration(AuthenticationToken admin, GlobalConfiguration globconf) {
        if (log.isTraceEnabled()) {
            log.trace(">saveGlobalConfiguration()");
        }
        
        String pk = "0";
        GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, pk);
        if (gcdata != null) {
        	// Save object and create a diff over what has changed
            Map<Object, Object> orgmap = (Map<Object, Object>)gcdata.getGlobalConfiguration().saveData(); 
            gcdata.setGlobalConfiguration(globconf);
            Map<Object, Object> newmap = (Map<Object, Object>)globconf.saveData();             
			// Get the diff of what changed
			Map<Object, Object> diff = UpgradeableDataHashMap.diffMaps(orgmap, newmap);
			// Make security audit log record
            String msg = intres.getLocalizedMessage("ra.savedconf", gcdata.getConfigurationId());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
			for (Map.Entry<Object,Object> entry : diff.entrySet()) {
				details.put(entry.getKey().toString(), entry.getValue().toString());				
			}
            auditSession.log(EjbcaEventTypes.SYSTEMCONF_EDIT, EventStatus.SUCCESS, EjbcaModuleTypes.GLOBALCONF, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), null, null, details);
        } else {
            // Global configuration doesn't yet exists.
            try {
                entityManager.persist(new GlobalConfigurationData(pk, globconf));
                String msg = intres.getLocalizedMessage("ra.createdconf", pk);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.SYSTEMCONF_CREATE, EventStatus.SUCCESS, EjbcaModuleTypes.GLOBALCONF, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), null, null, details);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("ra.errorcreateconf");
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                details.put("error", e.getMessage());
                auditSession.log(EjbcaEventTypes.SYSTEMCONF_CREATE, EventStatus.FAILURE, EjbcaModuleTypes.GLOBALCONF, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(LogConstants.INTERNALCAID), null, null, details);
            }
        }
        globalconfigurationCache.setGlobalconfiguration(globconf);
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
    	AuthenticationToken admin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("flushGlobalConfigurationCache"));
    	getCachedGlobalConfiguration(admin);
    	if (log.isDebugEnabled()) {
    		log.debug("Flushed global configuration cache.");
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<flushGlobalConfigurationCache()");
    	}
    }

    @Override
    public void setSettingIssueHardwareTokens(AuthenticationToken admin, boolean value) {
    	final GlobalConfiguration config = flushCache();
    	config.setIssueHardwareTokens(value);
    	saveGlobalConfiguration(admin, config);
    }

}
