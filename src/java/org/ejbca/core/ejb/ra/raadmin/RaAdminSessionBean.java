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

package org.ejbca.core.ejb.ra.raadmin;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * Stores data used by web server clients.
 * 
 * @version $Id: RaAdminSessionBean.java 9579 2010-07-30 18:07:23Z jeklund$
 */
@Stateless(mappedName = org.ejbca.core.ejb.JndiHelper.APP_JNDI_PREFIX + "RaAdminSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RaAdminSessionBean implements RaAdminSessionLocal, RaAdminSessionRemote {

    private static final String DEFAULTUSERPREFERENCE = "default";

    private static final Logger log = Logger.getLogger(RaAdminSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * Cache variable containing the global configuration. This cache may be
     * unsynchronized between multiple instances of EJBCA, but is common to all
     * threads in the same VM. Uses volatile internal to make it thread friendly.
     */
    private static final GlobalConfigurationCache globalconfigurationCache = new GlobalConfigurationCache();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private LogSessionLocal logSession;

    @Override
    public AdminPreference getAdminPreference(Admin admin, String certificatefingerprint) {
        if (log.isTraceEnabled()) {
            log.trace(">getAdminPreference()");
        }
        AdminPreference ret = null;
        AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, certificatefingerprint);
        if (apdata != null) {
            ret = apdata.getAdminPreference();
        }
        if (log.isTraceEnabled()) {
            log.trace("<getAdminPreference()");
        }
        return ret;
    }

    @Override
    public boolean addAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference) {
        if (log.isTraceEnabled()) {
            log.trace(">addAdminPreference(fingerprint : " + certificatefingerprint + ")");
        }
        boolean ret = false;
        // EJB 2.1 only?: We must actually check if there is one before we try
        // to add it, because wls does not allow us to catch any errors if
        // creating fails, that sux
        if (AdminPreferencesData.findById(entityManager, certificatefingerprint) == null) {
            try {
                AdminPreferencesData apdata = new AdminPreferencesData(certificatefingerprint, adminpreference);
                entityManager.persist(apdata);
                String msg = intres.getLocalizedMessage("ra.adminprefadded", apdata.getId());
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED, msg);
                ret = true;
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("ra.adminprefexists");
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED, msg);
            }
        } else {
            String msg = intres.getLocalizedMessage("ra.adminprefexists");
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED, msg);
        }
        log.trace("<addAdminPreference()");
        return ret;
    }

    @Override
    public boolean changeAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference) {
        if (log.isTraceEnabled()) {
            log.trace(">changeAdminPreference(fingerprint : " + certificatefingerprint + ")");
        }
        return updateAdminPreference(admin, certificatefingerprint, adminpreference, true);
    }

    @Override
    public boolean changeAdminPreferenceNoLog(Admin admin, String certificatefingerprint, AdminPreference adminpreference) {
        if (log.isTraceEnabled()) {
            log.trace(">changeAdminPreferenceNoLog(fingerprint : " + certificatefingerprint + ")");
        }
        return updateAdminPreference(admin, certificatefingerprint, adminpreference, false);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsAdminPreference(Admin admin, String certificatefingerprint) {
        if (log.isTraceEnabled()) {
            log.trace(">existsAdminPreference(fingerprint : " + certificatefingerprint + ")");
        }
        boolean ret = false;
        AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, certificatefingerprint);
        if (apdata != null) {
            log.debug("Found admin preferences with id " + apdata.getId());
            ret = true;
        }
        log.trace("<existsAdminPreference()");
        return ret;
    }

    @Override
    public AdminPreference getDefaultAdminPreference(Admin admin) {
        if (log.isTraceEnabled()) {
            log.trace(">getDefaultAdminPreference()");
        }
        AdminPreference ret = null;
        AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, DEFAULTUSERPREFERENCE);
        if (apdata != null) {
            ret = apdata.getAdminPreference();
        } else {
            try {
                // Create new configuration
                AdminPreferencesData newapdata = new AdminPreferencesData(DEFAULTUSERPREFERENCE, new AdminPreference());
                entityManager.persist(newapdata);
                ret = newapdata.getAdminPreference();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getDefaultAdminPreference()");
        }
        return ret;
    }

    @Override
    public void saveDefaultAdminPreference(Admin admin, AdminPreference defaultadminpreference) {
        if (log.isTraceEnabled()) {
            log.trace(">saveDefaultAdminPreference()");
        }
        AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, DEFAULTUSERPREFERENCE);
        if (apdata != null) {
            apdata.setAdminPreference(defaultadminpreference);
            String msg = intres.getLocalizedMessage("ra.defaultadminprefsaved");
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED, msg);
        } else {
            String msg = intres.getLocalizedMessage("ra.errorsavedefaultadminpref");
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED, msg);
            throw new EJBException(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<saveDefaultAdminPreference()");
        }
    }

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
    public GlobalConfiguration getCachedGlobalConfiguration(Admin admin) {
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
    public void saveGlobalConfiguration(Admin admin, GlobalConfiguration globconf) {
        if (log.isTraceEnabled()) {
            log.trace(">saveGlobalConfiguration()");
        }
        String pk = "0";
        GlobalConfigurationData gcdata = GlobalConfigurationData.findByConfigurationId(entityManager, pk);
        if (gcdata != null) {
            gcdata.setGlobalConfiguration(globconf);
            String msg = intres.getLocalizedMessage("ra.savedconf", gcdata.getConfigurationId());
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_EDITSYSTEMCONFIGURATION,
                    msg);
        } else {
            // Global configuration doesn't yet exists.
            try {
                entityManager.persist(new GlobalConfigurationData(pk, globconf));
                String msg = intres.getLocalizedMessage("ra.createdconf", pk);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_EDITSYSTEMCONFIGURATION, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("ra.errorcreateconf");
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_EDITSYSTEMCONFIGURATION, msg);
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
    	getCachedGlobalConfiguration(new Admin(Admin.TYPE_INTERNALUSER, "internal"));
    	if (log.isDebugEnabled()) {
    		log.debug("Flushed global configuration cache.");
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<flushGlobalConfigurationCache()");
    	}
    }

    /**
     * Changes the admin preference in the database. Returns false if admin
     * preference doesn't exist.
     */
    private boolean updateAdminPreference(Admin admin, String certificatefingerprint, AdminPreference adminpreference, boolean dolog) {
        if (log.isTraceEnabled()) {
            log.trace(">updateAdminPreference(fingerprint : " + certificatefingerprint + ")");
        }
        boolean ret = false;
        AdminPreferencesData apdata1 = AdminPreferencesData.findById(entityManager, certificatefingerprint);
        if (apdata1 != null) {
            apdata1.setAdminPreference(adminpreference);
            // Earlier we used to remove and re-add the adminpreferences data
            // I don't know why, but that did not work on Oracle AS, so lets
            // just do what create does, and setAdminPreference.
            /*
             * adminpreferenceshome.remove(certificatefingerprint); try{
             * AdminPreferencesDataLocal apdata2 =
             * adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
             * debug("Found admin preferences with id: "+apdata2.getId()); }
             * catch (javax.ejb.FinderException fe) {
             * debug("Admin preferences has been removed: "
             * +certificatefingerprint); }
             * adminpreferenceshome.create(certificatefingerprint
             * ,adminpreference); try{ AdminPreferencesDataLocal apdata3 =
             * adminpreferenceshome.findByPrimaryKey(certificatefingerprint);
             * debug("Found admin preferences with id: "+apdata3.getId()); }
             * catch (javax.ejb.FinderException fe) {
             * error("Admin preferences was not created: "
             * +certificatefingerprint); }
             */
            if (dolog) {
                String msg = intres.getLocalizedMessage("ra.changedadminpref", certificatefingerprint);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_ADMINISTRATORPREFERENCECHANGED, msg);
            }
            ret = true;
        } else {
            ret = false;
            if (dolog) {
                String msg = intres.getLocalizedMessage("ra.adminprefnotfound", certificatefingerprint);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_RA, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED, msg);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<updateAdminPreference()");
        }
        return ret;
    }
}
