/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.validation;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.ProfileID;
import org.ejbca.core.model.validation.BlacklistEntry;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntry;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntryCache;

/**
 * Handles management of public key blacklist entries.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "BlacklistSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class BlacklistSessionBean implements BlacklistSessionLocal, BlacklistSessionRemote {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(BlacklistSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;

    @Override
    public BlacklistEntry getBlacklistEntry(int id) {
        return getBlacklistEntryInternal(id, null, true);
    }

    @Override
    public BlacklistEntry getBlacklistEntry(String value) {
        return getBlacklistEntryInternal(-1, value, true);
    }

    @Override
    public String getBlacklistEntryFingerprint(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getBlacklistEntryFingerprint(id: " + id + ")");
        }
        // Get public key blacklist to ensure it is in the cache, or read.
        final BlacklistEntry entity = getBlacklistEntryInternal(id, null, true);
        final String result = (entity != null) ? entity.getValue() : null;
        if (log.isTraceEnabled()) {
            log.trace("<getBlacklistEntryFingerprint(): " + result);
        }
        return result;
    }

    @Override
    public void addBlacklistEntry(AuthenticationToken admin, int id, BlacklistEntry entry)
            throws AuthorizationDeniedException, BlacklistExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addBlacklist(value: " + entry.getValue() + ", id: " + id + ")");
        }
        addBlacklistEntryInternal(admin, id, entry);
        final String message = intres.getLocalizedMessage("blacklist.addedpublickeyblacklist", entry.getValue());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.BLACKLIST_CREATION, EventStatus.SUCCESS, ModuleTypes.BLACKLIST, ServiceTypes.CORE,
                admin.toString(), null, null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<addBlacklist()");
        }
    }

    @Override
    public void changeBlacklistEntry(AuthenticationToken admin, BlacklistEntry entry)
            throws AuthorizationDeniedException, BlacklistDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">changeBlacklist(value: " + entry.getValue() + ")");
        }
        assertIsAuthorizedToEditBlacklists(admin);
        BlacklistData data = BlacklistData.findByFingerprint(entityManager, entry.getValue());
        final String message;
        if (data != null) {
            final Map<Object, Object> diff = data.getBlacklistEntry().diff(entry);
            data.setBlacklistEntry(entry);
            // Since loading a PublicKeyBlacklist is quite complex, we simple purge the cache here.
            PublicKeyBlacklistEntryCache.INSTANCE.removeEntry(data.getId());
            message = intres.getLocalizedMessage("blacklist.changedpublickeyblacklist", entry.getValue());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            for (Map.Entry<Object, Object> mapEntry : diff.entrySet()) {
                details.put(mapEntry.getKey().toString(), mapEntry.getValue().toString());
            }
            auditSession.log(EventTypes.BLACKLIST_CHANGE, EventStatus.SUCCESS, ModuleTypes.BLACKLIST, ServiceTypes.CORE,
                    admin.toString(), null, null, null, details);
        } else {
            message = intres.getLocalizedMessage("blacklist.errorchangepublickeyblacklist", entry.getValue());
            log.info(message);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changeBlacklist()");
        }
    }

    @Override
    public void removeBlacklistEntry(AuthenticationToken admin, String value)
            throws AuthorizationDeniedException, BlacklistDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">removeBlacklist(fingerprint: " + value + ")");
        }
        assertIsAuthorizedToEditBlacklists(admin);
        String message;
        BlacklistData data = BlacklistData.findByFingerprint(entityManager, value);
        if (data == null) {
            if (log.isDebugEnabled()) {
                log.debug("Trying to remove a blacklist that does not exist: " + value);
            }
            throw new BlacklistDoesntExistsException();
        } else {
            entityManager.remove(data);
            // Purge the cache here.
            PublicKeyBlacklistEntryCache.INSTANCE.removeEntry(data.getId());
            message = intres.getLocalizedMessage("blacklist.removedpublickeyblacklist", value);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            auditSession.log(EventTypes.BLACKLIST_REMOVAL, EventStatus.SUCCESS, ModuleTypes.BLACKLIST, ServiceTypes.CORE,
                    admin.toString(), null, null, null, details);
        }
        if (log.isTraceEnabled()) {
            log.trace("<removeBlacklist()");
        }
    }

    @Override
    public void flushBlacklistEntryCache() {
        PublicKeyBlacklistEntryCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed BlacklistEntry cache.");
        }
    }

    @Override
    public int addBlacklistEntry(AuthenticationToken admin, BlacklistEntry entry)
            throws AuthorizationDeniedException, BlacklistExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addBlacklist(fingerprint: " + entry.getValue() + ")");
        }
        final int id = findFreeBlacklistId();
        addBlacklistEntry(admin, id, entry);
        if (log.isTraceEnabled()) {
            log.trace("<addBlacklist()");
        }
        return id;
    }

    @Override
    public Map<Integer, String> getBlacklistEntryIdToFingerprintMap() {
        final HashMap<Integer, String> result = new HashMap<Integer, String>();
        for (BlacklistData data : BlacklistData.findAll(entityManager)) {
            if (log.isDebugEnabled()) {
                log.debug("Find blacklist " + data.getValue() + " with id " + data.getId());
            }
            result.put(data.getId(), data.getValue());
        }
        return result;
    }

    @Override
    public int getBlacklistEntryId(String fingerprint) {
        // Get object to ensure it is in the cache, or read.
        final BlacklistEntry entry = getBlacklistEntryInternal(-1, fingerprint, true);
        int result = 0;
        if (null != entry) {
            result = entry.getID();
        }
        return result;
    }

    /** Adds a public key blacklist or throws an exception. Will not update the cache, it will be read into the cache on next try to read. */
    private void addBlacklistEntryInternal(AuthenticationToken admin, int id, BlacklistEntry blacklist) throws AuthorizationDeniedException, BlacklistExistsException {
        assertIsAuthorizedToEditBlacklists(admin);
        if (BlacklistData.findByFingerprint(entityManager, blacklist.getValue()) == null
                && BlacklistData.findById(entityManager, Integer.valueOf(id)) == null) {
            blacklist.setID(Integer.valueOf(id));
            final BlacklistData entity = new BlacklistData(blacklist);
            entityManager.persist(entity);
        } else {
            final String message = intres.getLocalizedMessage("blacklist.erroraddpublickeyblacklist", blacklist.getValue());
            log.info(message);
            throw new BlacklistExistsException();
        }
    }

    /** Gets a public key blacklist by cache or database, can return null. */
    private BlacklistEntry getBlacklistEntryInternal(int id, final String value, boolean fromCache) {
        if (log.isTraceEnabled()) {
            log.trace(">getBlacklistEntryInternal: " + id + ", " + value);
        }
        Integer idValue = Integer.valueOf(id);
        if (id == -1) {
            idValue = PublicKeyBlacklistEntryCache.INSTANCE.getNameToIdMap().get(value);
        }
        BlacklistEntry result = null;
        // If we should read from cache, and we have an id to use in the cache, and the cache does not need to be updated
        if (fromCache && idValue != null && !PublicKeyBlacklistEntryCache.INSTANCE.shouldCheckForUpdates(idValue)) {
            // Get from cache (or null)
            result = PublicKeyBlacklistEntryCache.INSTANCE.getEntry(idValue);
        }

        // if we selected to not read from cache, or if the cache did not contain this entry
        if (result == null) {
            if (log.isDebugEnabled()) {
                log.debug("BlacklistEntry with ID " + idValue + " and/or value '" + value + "' will be checked for updates.");
            }
            // We need to read from database because we specified to not get from cache or we don't have anything in the cache
            BlacklistData data = null;
            if (value != null) {
                data = BlacklistData.findByFingerprint(entityManager, value);
            } else if (idValue != null) {
                data = BlacklistData.findById(entityManager, idValue);
            }
            if (data != null) {
                result = data.getBlacklistEntry();
                final int digest = data.getProtectString(0).hashCode();
                // The cache compares the database data with what is in the cache
                // If database is different from cache, replace it in the cache
                PublicKeyBlacklistEntry newEntry = new PublicKeyBlacklistEntry(data.getId(), data.getValue(), data.getData());
                PublicKeyBlacklistEntryCache.INSTANCE.updateWith(data.getId(), digest, data.getValue(), newEntry);
            } else {
                // Ensure that it is removed from cache if it exists
                if (idValue != null) {
                    PublicKeyBlacklistEntryCache.INSTANCE.removeEntry(idValue);
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getBlacklistEntryInternal: " + id + ", " + value + ": " + (result == null ? "null" : "not null"));
        }
        return result;
    }

    /** Gets a free ID for the new blacklist instance. */
    private int findFreeBlacklistId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return BlacklistData.findById(BlacklistSessionBean.this.entityManager, i) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    /** Assert the administrator is authorized to edit public key blacklists. */
    private void assertIsAuthorizedToEditBlacklists(AuthenticationToken admin) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.BLACKLISTEDIT.resource())) {
            final String message = intres.getLocalizedMessage("store.editpublickeyblacklistnotauthorized", admin.toString());
            throw new AuthorizationDeniedException(message);
        }
    }
}
