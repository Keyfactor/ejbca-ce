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

import java.beans.XMLDecoder;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;
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
import org.cesecore.keys.validation.CouldNotRemovePublicKeyBlacklistException;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.ProfileID;
import org.ejbca.core.ejb.ca.validation.PublicKeyBlacklistData;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntry;
import org.ejbca.core.model.validation.PublicKeyBlacklistEntryCache;

/**
 * Handles management of public key blacklist entries.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublicKeyBlacklistSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class PublicKeyBlacklistSessionBean implements PublicKeyBlacklistSessionLocal, PublicKeyBlacklistSessionRemote {

    /** Class logger. */
    private static final Logger log = Logger.getLogger(PublicKeyBlacklistSessionBean.class);

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
    public PublicKeyBlacklistEntry getPublicKeyBlacklistEntry(int id) {
        return getPublicKeyBlacklistEntryInternal(id, null, true);
    }

    @Override
    public PublicKeyBlacklistEntry getPublicKeyBlacklistEntry(String fingerprint) {
        return getPublicKeyBlacklistEntryInternal(-1, fingerprint, true);
    }

    @Override
    public String getPublicKeyBlacklistEntryFingerprint(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublicKeyBlacklistFingerprint(id: " + id + ")");
        }
        // Get public key blacklist to ensure it is in the cache, or read.
        final PublicKeyBlacklistEntry entity = getPublicKeyBlacklistEntryInternal(id, null, true);
        final String result = (entity != null) ? entity.getFingerprint() : null;
        if (log.isTraceEnabled()) {
            log.trace("<getPublicKeyBlacklistFingerprint(): " + result);
        }
        return result;
    }

    @Override
    public void addPublicKeyBlacklistEntry(AuthenticationToken admin, int id, PublicKeyBlacklistEntry entry)
            throws AuthorizationDeniedException, PublicKeyBlacklistExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublicKeyBlacklist(fingerprint: " + entry.getFingerprint() + ", id: " + id + ")");
        }
        addPublicKeyBlacklistEntryInternal(admin, id, entry);
        final String message = intres.getLocalizedMessage("publickeyblacklist.addedpublickeyblacklist", entry.getFingerprint());
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", message);
        auditSession.log(EventTypes.PUBLICKEYBLACKLIST_CREATION, EventStatus.SUCCESS, ModuleTypes.PUBLIC_KEY_BLACKLIST, ServiceTypes.CORE,
                admin.toString(), null, null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<addPublicKeyBlacklist()");
        }
    }

    @Override
    public void changePublicKeyBlacklistEntry(AuthenticationToken admin, String fingerprint, PublicKeyBlacklistEntry entry)
            throws AuthorizationDeniedException, PublicKeyBlacklistDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">changePublicKeyBlacklist(fingerprint: " + fingerprint + ")");
        }
        assertIsAuthorizedToEditPublicKeyBlacklists(admin);
        PublicKeyBlacklistData data = PublicKeyBlacklistData.findByFingerprint(entityManager, fingerprint);
        final String message;
        if (data != null) {
            final Map<Object, Object> diff = getPublicKeyBlacklist(data).diff(entry);
            data.setPublicKeyBlacklist(entry);
            // Since loading a PublicKeyBlacklist is quite complex, we simple purge the cache here.
            PublicKeyBlacklistEntryCache.INSTANCE.removeEntry(data.getId());
            message = intres.getLocalizedMessage("publickeyblacklist.changedpublickeyblacklist", fingerprint);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", message);
            for (Map.Entry<Object, Object> mapEntry : diff.entrySet()) {
                details.put(mapEntry.getKey().toString(), mapEntry.getValue().toString());
            }
            auditSession.log(EventTypes.PUBLICKEYBLACKLIST_CHANGE, EventStatus.SUCCESS, ModuleTypes.PUBLIC_KEY_BLACKLIST, ServiceTypes.CORE,
                    admin.toString(), null, null, null, details);
        } else {
            message = intres.getLocalizedMessage("publickeyblacklist.errorchangepublickeyblacklist", fingerprint);
            log.info(message);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changePublicKeyBlacklist()");
        }
    }

    @Override
    public void removePublicKeyBlacklistEntry(AuthenticationToken admin, String fingerprint)
            throws AuthorizationDeniedException, PublicKeyBlacklistDoesntExistsException, CouldNotRemovePublicKeyBlacklistException {
        if (log.isTraceEnabled()) {
            log.trace(">removePublicKeyBlacklist(fingerprint: " + fingerprint + ")");
        }
        assertIsAuthorizedToEditPublicKeyBlacklists(admin);
        String message;
        try {
            PublicKeyBlacklistData data = PublicKeyBlacklistData.findByFingerprint(entityManager, fingerprint);
            if (data == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Trying to remove a public key blacklist that does not exist: " + fingerprint);
                }
                throw new PublicKeyBlacklistDoesntExistsException();
            } else {
                entityManager.remove(data);
                // Purge the cache here.
                PublicKeyBlacklistEntryCache.INSTANCE.removeEntry(data.getId());
                message = intres.getLocalizedMessage("publickeyblacklist.removedpublickeyblacklist", fingerprint);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", message);
                auditSession.log(EventTypes.PUBLICKEYBLACKLIST_REMOVAL, EventStatus.SUCCESS, ModuleTypes.PUBLIC_KEY_BLACKLIST, ServiceTypes.CORE,
                        admin.toString(), null, null, null, details);
            }
        } catch (Exception e) {
            message = intres.getLocalizedMessage("publickeyblacklist.errorremovepublickeyblacklist", fingerprint);
            log.info(message, e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<removePublicKeyBlacklist()");
        }
    }

    @Override
    public void flushPublicKeyBlacklistEntryCache() {
        PublicKeyBlacklistEntryCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed PublicKeyBlacklistEntry cache.");
        }
    }

    @Override
    public int addPublicKeyBlacklistEntry(AuthenticationToken admin, PublicKeyBlacklistEntry entry)
            throws AuthorizationDeniedException, PublicKeyBlacklistExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addPublicKeyBlacklist(fingerprint: " + entry.getFingerprint() + ")");
        }
        final int id = findFreePublicKeyBlacklistId();
        addPublicKeyBlacklistEntry(admin, id, entry);
        if (log.isTraceEnabled()) {
            log.trace("<addPublicKeyBlacklist()");
        }
        return id;
    }

    @Override
    public Map<Integer, String> getPublicKeyBlacklistEntryIdToFingerprintMap() {
        final HashMap<Integer, String> result = new HashMap<Integer, String>();
        for (PublicKeyBlacklistData data : PublicKeyBlacklistData.findAll(entityManager)) {
            if (log.isDebugEnabled()) {
                log.debug("Find public key blacklist " + data.getFingerprint() + " with id " + data.getId());
            }
            result.put(data.getId(), data.getFingerprint());
        }
        return result;
    }

    @Override
    public int getPublicKeyBlacklistEntryId(String fingerprint) {
        // Get object to ensure it is in the cache, or read.
        final PublicKeyBlacklistEntry entry = getPublicKeyBlacklistEntryInternal(-1, fingerprint, true);
        int result = 0;
        if (null != entry) {
            result = entry.getID();
        }
        return result;
    }

    /** Adds a public key blacklist or throws an exception. Will not update the cache, it will be read into the cache on next try to read. */
    private void addPublicKeyBlacklistEntryInternal(AuthenticationToken admin, int id, PublicKeyBlacklistEntry publicKeyBlacklist) throws AuthorizationDeniedException, PublicKeyBlacklistExistsException {
        assertIsAuthorizedToEditPublicKeyBlacklists(admin);
        if (PublicKeyBlacklistData.findByFingerprint(entityManager, publicKeyBlacklist.getFingerprint()) == null
                && PublicKeyBlacklistData.findById(entityManager, Integer.valueOf(id)) == null) {
            publicKeyBlacklist.setID(Integer.valueOf(id));
            final PublicKeyBlacklistData entity = new PublicKeyBlacklistData(publicKeyBlacklist);
            entityManager.persist(entity);
        } else {
            final String message = intres.getLocalizedMessage("publickeyblacklist.erroraddpublickeyblacklist", publicKeyBlacklist.getFingerprint());
            log.info(message);
            throw new PublicKeyBlacklistExistsException();
        }
    }

    /** Gets a public key blacklist by cache or database, can return null. */
    private PublicKeyBlacklistEntry getPublicKeyBlacklistEntryInternal(int id, final String fingerprint, boolean fromCache) {
        if (log.isTraceEnabled()) {
            log.trace(">getPublicKeyBlacklistInternal: " + id + ", " + fingerprint);
        }
        Integer idValue = Integer.valueOf(id);
        if (id == -1) {
            idValue = PublicKeyBlacklistEntryCache.INSTANCE.getNameToIdMap().get(fingerprint);
        }
        PublicKeyBlacklistEntry result = null;
        // If we should read from cache, and we have an id to use in the cache, and the cache does not need to be updated
        if (fromCache && idValue != null && !PublicKeyBlacklistEntryCache.INSTANCE.shouldCheckForUpdates(idValue)) {
            // Get from cache (or null)
            result = PublicKeyBlacklistEntryCache.INSTANCE.getEntry(idValue);
        }

        // if we selected to not read from cache, or if the cache did not contain this entry
        if (result == null) {
            if (log.isDebugEnabled()) {
                log.debug("PublicKeyBlacklistEntry with ID " + idValue + " and/or fingerpint '" + fingerprint + "' will be checked for updates.");
            }
            // We need to read from database because we specified to not get from cache or we don't have anything in the cache
            final PublicKeyBlacklistData data;
            if (fingerprint != null) {
                data = PublicKeyBlacklistData.findByFingerprint(entityManager, fingerprint);
            } else {
                data = PublicKeyBlacklistData.findById(entityManager, idValue);
            }
            if (data != null) {
                result = getPublicKeyBlacklist(data);
                final int digest = data.getProtectString(0).hashCode();
                // The cache compares the database data with what is in the cache
                // If database is different from cache, replace it in the cache
                PublicKeyBlacklistEntryCache.INSTANCE.updateWith(data.getId(), digest, data.getFingerprint(), result);
            } else {
                // Ensure that it is removed from cache if it exists
                if (idValue != null) {
                    PublicKeyBlacklistEntryCache.INSTANCE.removeEntry(idValue);
                }
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<getPublicKeyBlacklistInternal: " + id + ", " + fingerprint + ": " + (result == null ? "null" : "not null"));
        }
        return result;
    }

    /** Gets the concrete public key blacklist by the base objects data, and updates it if necessary. */
    private PublicKeyBlacklistEntry getPublicKeyBlacklist(PublicKeyBlacklistData data) {
        PublicKeyBlacklistEntry result = data.getCachedPublicKeyBlacklistEntry();
        if (result == null) {
            XMLDecoder decoder;
            try {
                decoder = new XMLDecoder(new ByteArrayInputStream(data.getData().getBytes("UTF8")));
            } catch (UnsupportedEncodingException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Could not decode public key blacklist entry with name " + data.getFingerprint() + " because " + e.getMessage());
                }
                throw new EJBException(e);
            }
            final LinkedHashMap<?, ?> map = (LinkedHashMap<?, ?>) decoder.readObject();
            decoder.close();
            // Handle Base64 encoded string values.
            final LinkedHashMap<?, ?> base64Map = new Base64GetHashMap(map);
            result = new PublicKeyBlacklistEntry();
            result.setID(data.getId());
            result.setSource(data.getSource());
            result.setKeyspec(data.getKeyspec());
            result.setFingerprint(data.getFingerprint());
            result.loadData(base64Map);
        }
        return result;
    }

    /** Gets a free ID for the new public key blacklist instance. */
    private int findFreePublicKeyBlacklistId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return PublicKeyBlacklistData.findById(PublicKeyBlacklistSessionBean.this.entityManager, i) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    /** Assert the administrator is authorized to edit public key blacklists. */
    private void assertIsAuthorizedToEditPublicKeyBlacklists(AuthenticationToken admin) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.PUBLICKEYBLACKLISTEDIT.resource())) {
            final String message = intres.getLocalizedMessage("store.editpublickeyblacklistnotauthorized", admin.toString());
            throw new AuthorizationDeniedException(message);
        }
    }
}
