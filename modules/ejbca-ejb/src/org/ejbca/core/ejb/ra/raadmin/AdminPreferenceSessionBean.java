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

package org.ejbca.core.ejb.ra.raadmin;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.config.RaStyleInfo;
import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ra.raadmin.AdminPreference;

/**
 * Stores data used by web server clients.
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "AdminPreferenceSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class AdminPreferenceSessionBean extends AdminPreferenceSessionDefault implements AdminPreferenceSessionLocal, AdminPreferenceSessionRemote {

    private static final String DEFAULTUSERPREFERENCE = "default";

    private static final Logger log = Logger.getLogger(AdminPreferenceSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private RaStyleCacheBean raStyleCacheBean;

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public AdminPreference getAdminPreference(final AuthenticationToken admin) {
        if (log.isTraceEnabled()) {
            log.trace(">getAdminPreference()");
        }
        final String id = makeAdminPreferenceId(admin);
        AdminPreference ret = null;
        if (id != null) {
            final AdminPreferencesData adminPreferencesData = AdminPreferencesData.findById(entityManager, id);
            if (adminPreferencesData != null) {
                ret = adminPreferencesData.getAdminPreference();
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getAdminPreference()");
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<String, AdminPreference> getAdminPreferences() {
        if (log.isTraceEnabled()) {
            log.trace(">getAdminPreference()");
        }        
        HashMap<String, AdminPreference> adminPreferences = new HashMap<>();
        final List<AdminPreferencesData> adminPreferencesData = AdminPreferencesData.findAll(entityManager);
        
        if (adminPreferencesData != null && !adminPreferencesData.isEmpty()) {
            for(final AdminPreferencesData adminPreferenceData : adminPreferencesData) {
                adminPreferences.put(adminPreferenceData.getId(), adminPreferenceData.getAdminPreference());
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getAdminPreference()");
        }        
        return adminPreferences;
    }

    @Override
    public boolean addAdminPreference(final AuthenticationToken admin, final AdminPreference adminpreference) {
        String id = makeAdminPreferenceId(admin);
        if (log.isTraceEnabled()) {
            log.trace(">addAdminPreference(id : " + id + ")");
        }
        boolean ret = false;
        // EJB 2.1 only?: We must actually check if there is one before we try
        // to add it, because wls does not allow us to catch any errors if
        // creating fails, that sux
        if (AdminPreferencesData.findById(entityManager, id) == null) {
            try {
                AdminPreferencesData apdata = new AdminPreferencesData(id, adminpreference);
                entityManager.persist(apdata);
                String msg = intres.getLocalizedMessage("ra.adminprefadded", apdata.getId());
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.RA_ADDADMINPREF, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
                ret = true;
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("ra.adminprefexists");
                log.info(msg, e);
            }
        } else {
            String msg = intres.getLocalizedMessage("ra.adminprefexists");
            log.info(msg);
        }
        log.trace("<addAdminPreference()");
        return ret;
    }

    @Override
    public boolean changeAdminPreference(final AuthenticationToken admin, final AdminPreference adminpreference) {
        return updateAdminPreference(admin, adminpreference, true);
    }

    @Override
    public boolean changeAdminPreferenceNoLog(final AuthenticationToken admin, final AdminPreference adminpreference) {
        return updateAdminPreference(admin, adminpreference, false);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsAdminPreference(final AuthenticationToken admin) {
        final String id = makeAdminPreferenceId(admin);
        if (log.isTraceEnabled()) {
            log.trace(">existsAdminPreference(id : " + id + ")");
        }
        boolean ret = false;
        if (id != null) {
            final AdminPreferencesData adminPreferencesData = AdminPreferencesData.findById(entityManager, id);
            if (adminPreferencesData != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Found admin preferences with id " + adminPreferencesData.getId());
                }
                ret = true;
            }
        }
        log.trace("<existsAdminPreference()");
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public RaStyleInfo getPreferedRaStyleInfo(final AuthenticationToken admin) {
        final List<RaStyleInfo> availableRaStyles = getAvailableRaStyleInfos(admin);
        final Integer preferedStyleId = getCurrentRaStyleId(admin);
        // Administrator hasn't set a preferred style. Use first available
        if (preferedStyleId == null && !availableRaStyles.isEmpty()) {
            return availableRaStyles.get(0);
        }
        // Default style will be used
        if (availableRaStyles.isEmpty() || preferedStyleId == 0) {
            return null;
        }
        
        // Return the style preferred by administrator
        for (final RaStyleInfo rastyle : availableRaStyles) {
            if (preferedStyleId == rastyle.getArchiveId()) {
                return rastyle;
            }
        }
        
        // Previously set preference is no longer available, return first available.
        return availableRaStyles.get(0);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<RaStyleInfo> getAvailableRaStyleInfos(AuthenticationToken admin) {
        return raStyleCacheBean.getAvailableRaStyles(admin);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void invalidateRaStyleCache() {
        raStyleCacheBean.invalidateCache();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public AdminPreference getDefaultAdminPreference() {
        if (log.isTraceEnabled()) {
            log.trace(">getDefaultAdminPreference()");
        }
        AdminPreference ret = null;
        AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, DEFAULTUSERPREFERENCE);
        if (apdata != null) {
            ret = apdata.getAdminPreference();
        } else {
            try {
                // Just return an object with default settings.
                // This is not persisted in the database at this point, because this method may be called without a transaction.
                AdminPreferencesData newapdata = new AdminPreferencesData(DEFAULTUSERPREFERENCE, new AdminPreference());
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
    public void saveDefaultAdminPreference(final AuthenticationToken admin, final AdminPreference defaultadminpreference)
            throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">saveDefaultAdminPreference()");
        }

        if (!authorizationSession.isAuthorized(admin, StandardRules.SYSTEMCONFIGURATION_EDIT.resource())) {
            String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.SYSTEMCONFIGURATION_EDIT, null);
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.RA_DEFAULTADMINPREF, EventStatus.FAILURE, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA,
                    admin.toString(), null, null, null, details);
            throw new AuthorizationDeniedException(msg);
        }

        final AdminPreferencesData apdata = AdminPreferencesData.findById(entityManager, DEFAULTUSERPREFERENCE);
        final AdminPreference currentPreferences;
        if (apdata != null) {
            apdata.setAdminPreference(defaultadminpreference);
            currentPreferences = apdata.getAdminPreference();
        } else {
            final AdminPreferencesData initialData = new AdminPreferencesData(DEFAULTUSERPREFERENCE, new AdminPreference());
            currentPreferences = initialData.getAdminPreference();
            entityManager.persist(new AdminPreferencesData(DEFAULTUSERPREFERENCE, defaultadminpreference));
        }
        final Map<Object, Object> diff = currentPreferences.diff(defaultadminpreference);
        final String msg = intres.getLocalizedMessage("ra.defaultadminprefsaved");
        final Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        for (Map.Entry<Object, Object> entry : diff.entrySet()) {
            details.put(entry.getKey().toString(), entry.getValue().toString());
        }
        auditSession.log(EjbcaEventTypes.RA_DEFAULTADMINPREF, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA,
                admin.toString(), null, null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<saveDefaultAdminPreference()");
        }
    }

    /**
     * Changes the admin preference in the database. Returns false if admin
     * preference doesn't exist.
     */
    private boolean updateAdminPreference(final AuthenticationToken admin, AdminPreference adminpreference, boolean dolog) {
        String id = makeAdminPreferenceId(admin);
        if (log.isTraceEnabled()) {
            log.trace(">updateAdminPreference(id : " + id + ")");
        }
        boolean ret = false;
        final AdminPreferencesData apdata1 = AdminPreferencesData.findById(entityManager, id);
        if (apdata1 != null) {
            final Map<Object, Object> diff = apdata1.getAdminPreference().diff(adminpreference);
            apdata1.setAdminPreference(adminpreference);
            if (dolog) {
                final String msg = intres.getLocalizedMessage("ra.changedadminpref", id);
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);
                for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                    details.put(entry.getKey().toString(), entry.getValue().toString());
                }
                auditSession.log(EjbcaEventTypes.RA_EDITADMINPREF, EventStatus.SUCCESS, EjbcaModuleTypes.RA, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            }
            ret = true;
        } else {
            ret = false;
            if (dolog) {
                final String msg = intres.getLocalizedMessage("ra.adminprefnotfound", id);
                log.info(msg);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<updateAdminPreference()");
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Integer getCurrentRaStyleId(final AuthenticationToken admin) {
        final AdminPreference adminPreference = getAdminPreference(admin);
        if (adminPreference == null) {
            return null;
        }

        final Integer currentStyleId = adminPreference.getPreferedRaStyleId();
        if (currentStyleId != null) {
            return currentStyleId;
        }
        return null;

    }

    @Override
    public void setCurrentRaStyleId(final int currentStyleId, final AuthenticationToken admin) {
        final AdminPreference adminPreference = getAdminPreference(admin);
        adminPreference.setPreferedRaStyleId(currentStyleId);
        updateAdminPreference(admin, adminPreference, false);
        
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Locale getCurrentRaLocale(final AuthenticationToken admin) {
        try {
            final AdminPreference adminPreference = getAdminPreference(admin);
            if (adminPreference == null) {
                return getDefaultAdminPreference().getPreferedRaLanguage();
            }

            final Locale currentLocale = adminPreference.getPreferedRaLanguage();
            if (currentLocale != null) {
                return currentLocale;
            }

            return getDefaultAdminPreference().getPreferedRaLanguage();
        } catch (RuntimeException e) {
            // This method is called in the error handler, so we don't want to throw any exceptions.
            log.warn("Failed to get locale: " + e.getMessage(), e);
            return null;
        }
    }

    @Override
    public void setCurrentRaLocale(final Locale locale, final AuthenticationToken admin) {
        final AdminPreference adminPreference = getAdminPreference(admin);
        adminPreference.setPreferedRaLanguage(locale);
        updateAdminPreference(admin, adminPreference, false);
        
    }

}
