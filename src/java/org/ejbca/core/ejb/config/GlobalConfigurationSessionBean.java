/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.config.EjbcaConfigurationHolder;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ra.raadmin.GlobalConfigurationData;
import org.ejbca.core.model.InternalEjbcaResources;

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
    private static final CMPConfigurationCache cmpConfigurationCache = new CMPConfigurationCache();
    private static final ScepConfigurationCache scepConfigurationCache = new ScepConfigurationCache();
    
    private final AlwaysAllowLocalAuthenticationToken internalAdmin = new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal GlobalConfiguration Admin"));
    
    @PersistenceContext(unitName = "ejbca")
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

    @Override
    public Configuration flushCache(String configID) {
        GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, configID);
        Configuration result = null;
        if (gcdata != null) {
            result = gcdata.getConfiguration(configID);
            updateConfigurationCache(result, configID);
        }
        return result;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Properties getAllProperties(AuthenticationToken admin, String configID) throws AuthorizationDeniedException {
        if(StringUtils.equals(configID, Configuration.GlobalConfigID)) {
            if (!accessSession.isAuthorized(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.ROLE_ROOT, null);
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
        } else if(StringUtils.equals(configID, Configuration.CMPConfigID)) {
            if (!accessSession.isAuthorized(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.ROLE_ROOT, null);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null, null, details);
                throw new AuthorizationDeniedException(msg);
            } 
            
            CmpConfiguration cmpConfig = (CmpConfiguration) getCachedConfiguration(configID);
            return cmpConfig.getAsProperties();
            
        } else if(StringUtils.equals(configID, Configuration.ScepConfigID)) {
            if (!accessSession.isAuthorized(admin, StandardRules.ROLE_ROOT.resource())) {
                String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.ROLE_ROOT, null);
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EventTypes.ACCESS_CONTROL, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), null, null, null, details);
                throw new AuthorizationDeniedException(msg);
            } 
            
            ScepConfiguration scepConfig = (ScepConfiguration) getCachedConfiguration(configID);
            return scepConfig.getAsProperties();
        }
        
        return null;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Configuration getCachedConfiguration(String configID) {
        
        Configuration result;
        try {
            if (log.isTraceEnabled()) {
                log.trace(">loadConfiguration()");
            }
            // Only do the actual SQL query if we might update the configuration
            // due to cache time anyhow
            if (StringUtils.equals(configID, Configuration.GlobalConfigID) && !globalconfigurationCache.needsUpdate()) {
                result = globalconfigurationCache.getGlobalconfiguration();
            } else if(StringUtils.equals(configID, Configuration.CMPConfigID) && !cmpConfigurationCache.needsUpdate()) {
                result = cmpConfigurationCache.getCMPConfiguration();
            } else if(StringUtils.equals(configID, Configuration.ScepConfigID) && !scepConfigurationCache.needsUpdate()) {
                result = scepConfigurationCache.getScepConfiguration();
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Reading Configuration");
                }
                GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, configID);
                if (gcdata != null) {
                    result = gcdata.getConfiguration(configID);
                    updateConfigurationCache(result, configID);
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("No default GlobalConfiguration exists. Trying to create a new one.");
                    }
                    result = getNewConfiguration(configID);
                    try {
                        // Call self bean as external here in order to create a transaction if no transaction exists (this method only has SUPPORTS to be as fast as possible)
                        globalConfigSession.saveConfiguration(internalAdmin, result, configID);
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
    public void saveConfiguration(final AuthenticationToken admin, final Configuration conf, final String configID) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">saveConfiguration()");
        }
        if (this.accessSession.isAuthorized(admin, StandardRules.ROLE_ROOT.resource())) {
            final GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, configID);
            if (gcdata != null) {
                // Save object and create a diff over what has changed
                @SuppressWarnings("unchecked")
                final Map<Object, Object> orgmap = (Map<Object, Object>) gcdata.getConfiguration(configID).saveData();
                gcdata.setConfiguration(conf);
                @SuppressWarnings("unchecked")
                final Map<Object, Object> newmap = (Map<Object, Object>) conf.saveData();
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
                    GlobalConfigurationData gcd = new GlobalConfigurationData(configID, conf);
                    entityManager.persist(gcd);
                    final String msg = intres.getLocalizedMessage("ra.createdconf", configID);
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
            updateConfigurationCache(conf, configID);
        } else {
            throw new AuthorizationDeniedException("Authorization was denied to user " + admin
                    + " to resource /. Could not save configuration.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<saveGlobalConfiguration()");
        }
    }

    @Override
    public void flushConfigurationCache(final String configID)  {
    	if (log.isTraceEnabled()) {
    		log.trace(">flushConfigurationCache()");
    	}
    	
    	clearConfigCache(configID);
    	getCachedConfiguration(configID);

    	if (log.isTraceEnabled()) {
    		log.trace("<flushConfigurationCache()");
    	}
    }

    @Override
    public void setSettingIssueHardwareTokens(AuthenticationToken admin, boolean value) throws AuthorizationDeniedException {
    	final GlobalConfiguration config = (GlobalConfiguration) flushCache(Configuration.GlobalConfigID);
    	config.setIssueHardwareTokens(value);
    	saveConfiguration(admin, config, Configuration.GlobalConfigID);
    }
    
    private void updateConfigurationCache(Configuration conf, String configID) {
        if(StringUtils.equals(configID, Configuration.GlobalConfigID)) {
            globalconfigurationCache.setGlobalconfiguration((GlobalConfiguration) conf);
        } else if(StringUtils.equals(configID, Configuration.CMPConfigID)) {
            cmpConfigurationCache.setCMPConfiguration((CmpConfiguration) conf);
        } else if(StringUtils.equals(configID, Configuration.ScepConfigID)) {
            scepConfigurationCache.setScepConfiguration((ScepConfiguration) conf);
        }
    }

    private void clearConfigCache(String configID) {
        if(StringUtils.equals(configID, Configuration.GlobalConfigID)) {
            globalconfigurationCache.clearCache();
            if (log.isDebugEnabled()) {
                log.debug("Flushed global configuration cache.");
            }
        } else if(StringUtils.equals(configID, Configuration.CMPConfigID)) {
            cmpConfigurationCache.clearCache();
            if (log.isDebugEnabled()) {
                log.debug("Flushed CMP configuration cache.");
            }
        } else if(StringUtils.equals(configID, Configuration.ScepConfigID)) {
            scepConfigurationCache.clearCache();
            if (log.isDebugEnabled()) {
                log.debug("Flushed SCEP configuration cache.");
            }
        }
    }
    
    private Configuration getNewConfiguration(String configID) {
        if(StringUtils.equals(configID, Configuration.GlobalConfigID)) {
            return new GlobalConfiguration();
        } else if(StringUtils.endsWith(configID, Configuration.CMPConfigID)) {
            return new CmpConfiguration();
        } else if(StringUtils.endsWith(configID, Configuration.ScepConfigID)) {
            return new ScepConfiguration();
        }
        return null;
    }
    
}
