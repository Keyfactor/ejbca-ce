/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.configuration;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;

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
    private static final InternalResources intres = InternalResources.getInstance();
        
    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private AccessControlSessionLocal accessSession;

    // Myself needs to be looked up in postConstruct
    @Resource
    private SessionContext sessionContext;
    private GlobalConfigurationSessionLocal globalConfigSession;
    
    /** Default create for SessionBean without any creation Arguments. */
    @PostConstruct
    public void postConstruct() {
        // We lookup the reference to our-self in PostConstruct, since we cannot inject this.
        // We can not inject ourself, JBoss will not start then therefore we use this to get a reference to this session bean
        // to call saveConfiguration from getCachedCOnfiguration we want to do it on the real bean in order to get
        // the transaction setting (REQUIRED) which created a new transaction in order to create default config
        globalConfigSession = sessionContext.getBusinessObject(GlobalConfigurationSessionLocal.class);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Properties getAllProperties(AuthenticationToken admin, String configID) throws AuthorizationDeniedException {
        if (!accessSession.isAuthorized(admin, StandardRules.ROLE_ROOT.resource())) {
            String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.ROLE_ROOT, null);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null, null, details);
            throw new AuthorizationDeniedException(msg);
        } 
        
        return GlobalConfigurationCacheHolder.INSTANCE.getAllProperties(configID);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public ConfigurationBase getCachedConfiguration(String configID) {
        
        ConfigurationBase result;
        try {
            if (log.isTraceEnabled()) {
                log.trace(">loadConfiguration()");
            }
            // Only do the actual SQL query if we might update the configuration
            // due to cache time anyhow
            if(!GlobalConfigurationCacheHolder.INSTANCE.needsUpdate(configID)) {
                result = GlobalConfigurationCacheHolder.INSTANCE.getConfiguration(configID);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Reading Configuration");
                }
                GlobalConfigurationData gcdata = findByConfigurationId(configID);
                if (gcdata != null) {
                    result = GlobalConfigurationCacheHolder.INSTANCE.getConfiguration(gcdata.getData(), configID);
                    GlobalConfigurationCacheHolder.INSTANCE.updateConfiguration(result, configID);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No default GlobalConfiguration exists. Trying to create a new one.");
                    }
                    result = GlobalConfigurationCacheHolder.INSTANCE.getNewConfiguration(configID);
                    // Call self bean as external here in order to create a transaction if no transaction exists (this method only has SUPPORTS to be as fast as possible)
                    globalConfigSession.saveConfigurationNoLog(result);            
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
    public void saveConfiguration(final AuthenticationToken admin, final ConfigurationBase conf) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">saveConfiguration()");
        }
        String configID = conf.getConfigurationId();
        if (this.accessSession.isAuthorized(admin, StandardRules.ROLE_ROOT.resource())) {
            final GlobalConfigurationData gcdata = findByConfigurationId(configID);
            if (gcdata != null) {
                // Save object and create a diff over what has changed
                @SuppressWarnings("unchecked")
                final Map<Object, Object> orgmap = (Map<Object, Object>) GlobalConfigurationCacheHolder.INSTANCE.getConfiguration(gcdata.getData(), configID).saveData();
                gcdata.setConfiguration(conf);
                GlobalConfigurationCacheHolder.INSTANCE.updateConfiguration(conf, configID);
                @SuppressWarnings("unchecked")
                final Map<Object, Object> newmap = (Map<Object, Object>) conf.saveData();
                // Get the diff of what changed
                final Map<Object, Object> diff = UpgradeableDataHashMap.diffMaps(orgmap, newmap);
                // Make security audit log record
                final String msg = intres.getLocalizedMessage("globalconfig.savedconf", gcdata.getConfigurationId());
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                    details.put(entry.getKey().toString(), entry.getValue().toString());
                }
                auditSession.log(EventTypes.SYSTEMCONF_EDIT, EventStatus.SUCCESS, ModuleTypes.GLOBALCONF, ServiceTypes.CORE,
                        admin.toString(), null, null, null, details);
            } else {
                // Global configuration doesn't yet exists.
                try {
                    saveConfigurationNoLog(conf);
                    final String msg = intres.getLocalizedMessage("globalconfig.createdconf", configID);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    auditSession.log(EventTypes.SYSTEMCONF_CREATE, EventStatus.SUCCESS, ModuleTypes.GLOBALCONF, ServiceTypes.CORE,
                            admin.toString(), null, null, null, details);
                } catch (Exception e) {
                    final String msg = intres.getLocalizedMessage("globalconfig.errorcreateconf");
                    log.info(msg, e);
                    final Map<String, Object> details = new LinkedHashMap<String, Object>();
                    details.put("msg", msg);
                    details.put("error", e.getMessage());
                    auditSession.log(EventTypes.SYSTEMCONF_CREATE, EventStatus.FAILURE, ModuleTypes.GLOBALCONF, ServiceTypes.CORE,
                            admin.toString(), null, null, null, details);
                }
            }
        } else {
            throw new AuthorizationDeniedException("Authorization was denied to user " + admin
                    + " to resource /. Could not save configuration.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<saveGlobalConfiguration()");
        }
    }
    
    @Override
   public void saveConfigurationNoLog(ConfigurationBase conf) {
        String configID = conf.getConfigurationId();
        GlobalConfigurationData gcd = new GlobalConfigurationData(configID, conf);
        entityManager.persist(gcd);
        GlobalConfigurationCacheHolder.INSTANCE.updateConfiguration(conf, configID);
    }

    @Override
    public void flushConfigurationCache(final String configID)  {
    	if (log.isTraceEnabled()) {
    		log.trace(">flushConfigurationCache()");
    	}
    	
    	GlobalConfigurationCacheHolder.INSTANCE.clearCache(configID);
    	getCachedConfiguration(configID);

    	if (log.isTraceEnabled()) {
    		log.trace("<flushConfigurationCache()");
    	}
    }
    
    /** @return the found entity instance or null if the entity does not exist */
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public GlobalConfigurationData findByConfigurationId(String configurationId) {
        return entityManager.find(GlobalConfigurationData.class, configurationId);
    }
    
    private static enum GlobalConfigurationCacheHolder {
        INSTANCE;
        
        private final Map<String, ConfigurationCache> caches = new ConcurrentHashMap<String, ConfigurationCache>();
        
        private GlobalConfigurationCacheHolder() {
            ServiceLoader<? extends ConfigurationCache> serviceLoader = ServiceLoader.load(ConfigurationCache.class);
            // Extract all the caches from the plugin list
            for (ConfigurationCache cache : serviceLoader) {
                if (caches.containsKey(cache.getConfigId())) {
                    throw new IllegalStateException("Two caches loaded with the same config ID: " + cache.getConfigId()
                            + ". This is an invalid state.");
                } else {
                    caches.put(cache.getConfigId(), cache);
                }
            }
        }
        
        public void updateConfiguration(final ConfigurationBase conf, final String configId) {
            caches.get(configId).updateConfiguration(conf);
        }
        
        public void clearCache(final String configId) {
            caches.get(configId).clearCache();
        }
        
        public boolean needsUpdate(final String configId) {
            return caches.get(configId).needsUpdate();
        }
        
        public ConfigurationBase getConfiguration(final String configId) {
            ConfigurationCache cache = caches.get(configId);
            if (cache == null) {
                return null;
            } else {
                return cache.getConfiguration();
            }
        }

        @SuppressWarnings("rawtypes")
        public ConfigurationBase getConfiguration(final HashMap data, final String configId) {
            ConfigurationCache cache = caches.get(configId);
            if (cache == null) {
                return null;
            } else {
                return cache.getConfiguration(data);
            }
        }
        
        public ConfigurationBase getNewConfiguration(final String configId) {
            ConfigurationCache cache = caches.get(configId);
            if (cache == null) {
                return null;
            } else {
                return cache.getNewConfiguration();
            }
        }
        
        public Properties getAllProperties(final String configId) {
            ConfigurationCache cache = caches.get(configId);
            if (cache == null) {
                return null;
            } else {
                return caches.get(configId).getAllProperties();
            }
        }
        
    }
}


