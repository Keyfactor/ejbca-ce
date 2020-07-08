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
package org.cesecore.certificates.ca;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.TreeSet;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import javax.persistence.TypedQuery;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.internal.CACacheHelper;
import org.cesecore.certificates.ca.internal.CaCache;
import org.cesecore.certificates.ca.internal.CaIDCacheBean;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.QueryResultWrapper;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Implementation of CaSession, i.e takes care of all CA related CRUD operations.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CaSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CaSessionBean implements CaSessionLocal, CaSessionRemote {

    private static final Logger log = Logger.getLogger(CaSessionBean.class);

    /* Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    @Resource
    private SessionContext sessionContext;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal keyBindMgmtSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private CaIDCacheBean caIDCache;

    private CaSessionLocal caSession;

    @PostConstruct
    public void postConstruct() {
    	// Install BouncyCastle provider if not available
    	CryptoProviderTools.installBCProviderIfNotAvailable();
    	// It is not possible to @EJB-inject our self on all application servers so we need to do a lookup
    	caSession = sessionContext.getBusinessObject(CaSessionLocal.class);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<CAData> findAll() {
        final TypedQuery<CAData> query = entityManager.createQuery("SELECT a FROM CAData a", CAData.class);
        return query.getResultList();
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CAData findById(final Integer cAId) {
        return entityManager.find(CAData.class, cAId);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CAData findByIdOrThrow(final Integer cAId) throws CADoesntExistsException {
        final CAData ret = findById(cAId);
        if (ret == null) {
            throw new CADoesntExistsException("CA id: " + cAId);
        }
        return ret;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CAData findByName(final String name) {
        final Query query = entityManager.createQuery("SELECT a FROM CAData a WHERE a.name=:name");
        query.setParameter("name", name);
        return (CAData) QueryResultWrapper.getSingleResult(query);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CAData findByNameOrThrow(final String name) throws CADoesntExistsException {
        final CAData ret = findByName(name);
        if (ret == null) {
            throw new CADoesntExistsException("CA name: " + name);
        }
        return ret;
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CAData findBySubjectDN(final String subjectDN) {
        final Query query = entityManager.createQuery("SELECT a FROM CAData a WHERE a.subjectDN=:subjectDN");
        query.setParameter("subjectDN", subjectDN);
        return (CAData) QueryResultWrapper.getSingleResult(query);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public void flushCACache() {
        CaCache.INSTANCE.flush();
        caIDCache.forceCacheExpiration();
        if (log.isDebugEnabled()) {
            log.debug("Flushed CA cache.");
        }
    }

    @Override
    public void addCA(final AuthenticationToken admin, final CACommon ca) throws CAExistsException, AuthorizationDeniedException {
        if (ca != null) {
            final int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            if (!authorizationSession.isAuthorized(admin, StandardRules.CAADD.resource(), CryptoTokenRules.USE.resource() + "/" + cryptoTokenId)) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoaddca", admin.toString(), ca.getCAId());
                throw new AuthorizationDeniedException(msg);
            }
            CAInfo cainfo = ca.getCAInfo();
            // The CA needs a name and a subject DN in order to store it
            if ((ca.getName() == null) || (ca.getSubjectDN() == null)) {
                throw new CAExistsException("Null CA name or SubjectDN. Name: '"+ca.getName()+"', SubjectDN: '"+ca.getSubjectDN()+"'.");
            }
            if (findByName(cainfo.getName()) != null) {
                String msg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
                throw new CAExistsException(msg);
            }
            if (findById(ca.getCAId()) != null) {
                String msg = intres.getLocalizedMessage("caadmin.caexistsid", ca.getCAId());
                throw new CAExistsException(msg);
            }
            final CAData caData = new CAData(cainfo.getSubjectDN(), cainfo.getName(), cainfo.getStatus(), ca);
            entityManager.persist(caData);
            caIDCache.forceCacheExpiration(); // Clear ID cache so this one will be reloaded as well.
            String msg = intres.getLocalizedMessage("caadmin.addedca", ca.getCAId(), cainfo.getName(), cainfo.getStatus());
            final Map<String, Object> details = new LinkedHashMap<>();
            details.put("msg", msg);
            details.put("tokenproperties", ca.getCAToken().getProperties());
            details.put("tokensequence", ca.getCAToken().getKeySequence());
            logSession.log(EventTypes.CA_CREATION, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(ca.getCAId()), null, null, details);
        } else {
            log.debug("Trying to add null CA, nothing done.");
        }
    }

    @Override
    public void editCA(final AuthenticationToken admin, final CAInfo cainfo) throws CADoesntExistsException, AuthorizationDeniedException, InternalKeyBindingNonceConflictException {
        if (cainfo != null) {
        	if (log.isTraceEnabled()) {
        		log.trace(">editCA (CAInfo): "+cainfo.getName());
        	}
    		try {
    			final CACommon ca = getCAInternal(cainfo.getCAId(), null, null, false);
    			// Check if we can edit the CA (also checks authorization)
                checkForPreProductionAndNonceConflict(cainfo, ca);
    			int newCryptoTokenId = ca.getCAToken().getCryptoTokenId();
    			if (cainfo.getCAToken() != null) {
    			    newCryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
    			}
                assertAuthorizationAndTarget(admin, cainfo.getName(), cainfo.getSubjectDN(), newCryptoTokenId, ca);
                @SuppressWarnings("unchecked")
                final Map<Object, Object> orgmap = (Map<Object, Object>)ca.saveData();
                AvailableCustomCertificateExtensionsConfiguration cceConfig = (AvailableCustomCertificateExtensionsConfiguration)
                        globalConfigurationSession.getCachedConfiguration(AvailableCustomCertificateExtensionsConfiguration.CONFIGURATION_ID);
                ca.updateCA(cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId()), cainfo, cceConfig);
                // Audit log
                @SuppressWarnings("unchecked")
                final Map<Object, Object> newmap = (Map<Object, Object>)ca.saveData();
    			// Get the diff of what changed
                final Map<Object, Object> diff = UpgradeableDataHashMap.diffMaps(orgmap, newmap);
                final String msg = intres.getLocalizedMessage("caadmin.editedca", ca.getCAId(), ca.getName(), ca.getStatus());
    			// Use a LinkedHashMap because we want the details logged (in the final log string) in the order we insert them, and not randomly
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);
    			for (final Map.Entry<Object,Object> entry : diff.entrySet()) {
    				details.put(entry.getKey().toString(), entry.getValue().toString());
    			}
                details.put("tokenproperties", ca.getCAToken().getProperties());
                details.put("tokensequence", ca.getCAToken().getKeySequence());
                logSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(ca.getCAId()), null, null, details);
                // Store it
                mergeCa(ca);
    		} catch (InvalidAlgorithmException e) {
                throw new CADoesntExistsException(e);
            } 
        	if (log.isTraceEnabled()) {
        		log.trace("<editCA (CAInfo): "+cainfo.getName());
        	}
        } else {
            log.debug("Trying to edit null CAInfo, nothing done.");
        }
    }

    private void checkForPreProductionAndNonceConflict(final CAInfo cainfo, final CACommon ca) throws InternalKeyBindingNonceConflictException {
        if (CAInfo.CATYPE_X509 == ca.getCAInfo().getCAType() && ((X509CAInfo)cainfo).isDoPreProduceOcspResponses()) {
            final List<InternalKeyBindingInfo> keyBindingInfos = keyBindMgmtSession.getAllInternalKeyBindingInfos("OcspKeyBinding");
            for (InternalKeyBindingInfo keyBindInfo : keyBindingInfos) {
                final DynamicUiProperty<? extends Serializable> property = keyBindInfo.getProperty("enableNonce");
                if (keyBindInfo.getCertificateId() != null && property != null && "true".equals(property.getValue().toString())) {
                    final CertificateDataWrapper certDataWrapper = certificateStoreSession.getCertificateData(keyBindInfo.getCertificateId());
                    if (certDataWrapper == null) {
                        continue;
                    }
                    final BaseCertificateData baseCertData = certDataWrapper.getBaseCertificateData();
                    if (baseCertData == null) {
                        continue;
                    }
                    final String caFingerPrint = baseCertData.getCaFingerprint();
                    final CertificateDataWrapper caCertDataWrapper = certificateStoreSession.getCertificateData(caFingerPrint);
                    if (caCertDataWrapper == null) {
                        continue;
                    }
                    final Certificate caCert = caCertDataWrapper.getCertificate();
                    if (ca.getCACertificate() != null && ca.getCACertificate().equals(caCert)) {
                        throw new InternalKeyBindingNonceConflictException("CA can't have pre-production of OCSP responses enabled while there are OCSPKeybindings "
                                + "related to that CA with nonce enabled in response.");
                    }
                }
            }
        }
    }

    @Override
    public void editCA(final AuthenticationToken admin, final CACommon ca, boolean auditlog) throws CADoesntExistsException, AuthorizationDeniedException {
        if (ca != null) {
            if (log.isTraceEnabled()) {
                log.trace(">editCA (CA): "+ca.getName());
            }
            final CACommon orgca = getCAInternal(ca.getCAId(), null, null, true);
            // Check if we can edit the CA (also checks authorization)
            assertAuthorizationAndTarget(admin, ca.getName(), ca.getSubjectDN(), ca.getCAToken().getCryptoTokenId(), orgca);
            if (auditlog) {
                // Get the diff of what changed
                final Map<Object, Object> diff = orgca.diff((UpgradeableDataHashMap) ca);
                String msg = intres.getLocalizedMessage("caadmin.editedca", ca.getCAId(), ca.getName(), ca.getStatus());
                // Use a LinkedHashMap because we want the details logged (in the final log string) in the order we insert them, and not randomly
                final Map<String, Object> details = new LinkedHashMap<>();
                details.put("msg", msg);
                for (Map.Entry<Object,Object> entry : diff.entrySet()) {
                    details.put(entry.getKey().toString(), entry.getValue().toString());
                }
                details.put("tokenproperties", ca.getCAToken().getProperties());
                details.put("tokensequence", ca.getCAToken().getKeySequence());
                logSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(ca.getCAId()), null, null, details);
            }
            if (log.isTraceEnabled()) {
                log.trace("<editCA (CA): "+ca.getName());
            }
            // Store it
            mergeCa(ca);
        } else {
            log.debug("Trying to edit null CA, nothing done.");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsCa(final int caId) {
        return entityManager.find(CAData.class, caId) != null;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean existsCa(final String name) {
        return findByName(name) != null;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public boolean existsKeyValidatorInCAs(int keyValidatorId) {
        for (final Integer caId : getAllCaIds()) {
            final Collection<Integer> ids = getCAInfoInternal(caId).getValidators();
            if (ids != null) {
                for (final Integer id : ids) {
                    if (id == keyValidatorId) {
                        // We have found a match. No point in looking for more.
                        return true;
                    }
                }
            }
        }
        return false;
    }

	/** Ensure that the caller is authorized to the CA we are about to edit and that the CA name and subjectDN matches. */
	private void assertAuthorizationAndTarget(AuthenticationToken admin, final String name, final String subjectDN, final int cryptoTokenId, final CACommon ca)
			throws CADoesntExistsException, AuthorizationDeniedException {
		assertAuthorizationAndTargetWithNewSubjectDn(admin, name, subjectDN, cryptoTokenId, ca);
        if (!StringUtils.equals(subjectDN, ca.getSubjectDN()) && ca.getCAInfo().getStatus() != CAConstants.CA_UNINITIALIZED) {
            throw new CADoesntExistsException("Not same CA subject DN.");
        }
	}

	/** Ensure that the caller is authorized to the CA we are about to edit and that the CA name matches. */
    private void assertAuthorizationAndTargetWithNewSubjectDn(AuthenticationToken admin, final String name, final String subjectDN, final int cryptoTokenId, final CACommon ca)
            throws CADoesntExistsException, AuthorizationDeniedException {
        // Check if we are authorized to edit CA and authorization to specific CA
        if (cryptoTokenId == ca.getCAToken().getCryptoTokenId() || cryptoTokenId==0) {
            if (!authorizationSession.isAuthorized(admin, StandardRules.CAEDIT.resource(), StandardRules.CAACCESS.resource() + ca.getCAId())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", admin.toString(), ca.getCAId());
                throw new AuthorizationDeniedException(msg);
            }
        } else {
            // We only need to check usage authorization if we change CryptoToken reference (and not to 0 which means "removed").
            if (!authorizationSession.isAuthorized(admin, StandardRules.CAEDIT.resource(), StandardRules.CAACCESS.resource() + ca.getCAId(), CryptoTokenRules.USE.resource() + "/" + cryptoTokenId)) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", admin.toString(), ca.getCAId());
                throw new AuthorizationDeniedException(msg);
            }
        }
        // The CA needs the same name and subject DN in order to store it
        if (name == null || subjectDN == null) {
            throw new CADoesntExistsException("Null CA name or SubjectDN");
        } else if (!StringUtils.equals(name, ca.getName())) {
            throw new CADoesntExistsException("Not same CA name.");
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CACommon getCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        return getCA(admin, caid, null);
    }
    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CACommon getCA(final AuthenticationToken admin, final int caid, final String keySequence) throws AuthorizationDeniedException {
        if (!authorizedToCA(admin, caid)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
        return getCAInternal(caid, null, keySequence, true);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CACommon getCA(final AuthenticationToken admin, final String name) throws AuthorizationDeniedException {
        CACommon ca = getCAInternal(-1, name, null, true);
        if(ca != null) { 
            if (!authorizedToCA(admin, ca.getCAId())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), name);
                throw new AuthorizationDeniedException(msg);
            }
        }
        return ca;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CACommon getCANoLog(final AuthenticationToken admin, final int caid, final String keySequence) throws AuthorizationDeniedException {
        if (!authorizedToCANoLogging(admin, caid)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
        return getCAInternal(caid, null, keySequence, true);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CACommon getCAForEdit(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        CACommon ca = getCAInternal(caid, null, null, false);
        if (ca != null) {
            if (!authorizedToCA(admin, ca.getCAId())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
                throw new AuthorizationDeniedException(msg);
            }
        }
        return ca;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CACommon getCAForEdit(final AuthenticationToken admin, final String name) throws AuthorizationDeniedException {
        CACommon ca = getCAInternal(-1, name, null, false);
        if(ca == null) {
            return null;
        }
        if (!authorizedToCA(admin, ca.getCAId())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), name);
            throw new AuthorizationDeniedException(msg);
        }
        return ca;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfo(final AuthenticationToken admin, final String name) throws AuthorizationDeniedException {
        // Authorization is handled by getCA
        CACommon ca = getCA(admin, name);
        if (ca == null) {
            return null;
        } else {
            return ca.getCAInfo();
        }
    }


    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfo(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        // Authorization is handled by getCA
        CACommon ca = getCA(admin, caid, null);
        if (ca == null) {
            return null;
        } else {
            return ca.getCAInfo();
        }   
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfoInternal(final int caid) {
        // Authorization is handled by getCA
        CACommon ca = getCAInternal(caid, null, null, true);
        if (ca == null) {
            return null;
        } else {
            return ca.getCAInfo();
        } 
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<CertificateWrapper> getCaChain(AuthenticationToken authenticationToken, String caName)
            throws AuthorizationDeniedException, CADoesntExistsException {
        final CAInfo info = getCAInfo(authenticationToken, caName);
        if(info == null) {
            throw new CADoesntExistsException("CA with name " + caName + " doesn't exist.");
        }
        final List<CertificateWrapper> result = new ArrayList<>();
        if (info.getStatus() != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
            result.addAll(EJBTools.wrapCertCollection(info.getCertificateChain()));   
        }
        if (log.isDebugEnabled()) {
            log.debug("CA chain request by admin " + authenticationToken.getUniqueId() + " " + result);
        }
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfoInternal(final int caid, final String name, boolean fromCache) {
        // Authorization is handled by getCA
        CACommon ca = getCAInternal(caid, name, null, fromCache);
        if (ca == null) {
            return null;
        } else {
            return ca.getCAInfo();
        }         
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public String getCaSubjectDn(final String caName) {
        final CAInfo caInfo = getCAInfoInternal(-1, caName, true);
        return (caInfo != null ? caInfo.getSubjectDN() : "");
    }

    @Override
    public void removeCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        // check authorization
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAREMOVE.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoremoveca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
        // Get CA from database if it does not exist, ignore
        CAData cadata = findById(caid);
        if (cadata != null) {
            // Remove CA
            entityManager.remove(cadata);
            // Invalidate CA cache to refresh information
            CaCache.INSTANCE.removeEntry(caid);
            caIDCache.forceCacheExpiration(); // Clear ID cache so this one will be reloaded as well.
            final String detailsMsg = intres.getLocalizedMessage("caadmin.removedca", caid, cadata.getName());
            logSession.log(EventTypes.CA_DELETION, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(caid), null, null, detailsMsg);
        }
    }

    @Override
    public void renameCA(final AuthenticationToken admin, final String oldname, final String newname) throws CAExistsException,
            CADoesntExistsException, AuthorizationDeniedException {
        // Get CA from database
        CAData cadata = findByNameOrThrow(oldname);
        // Check authorization, to rename we need remove (for the old name) and add for the new name)
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAREMOVE.resource(), StandardRules.CAADD.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenameca", admin.toString(), cadata.getCaId());
            throw new AuthorizationDeniedException(msg);
        }
        if (findByName(newname) == null) {
            // The new CA doesn't exist, it's okay to rename old one.
            cadata.setName(newname);
            // Invalidate CA cache to refresh information
            int caid = cadata.getCaId();
            CaCache.INSTANCE.removeEntry(caid);
            caIDCache.forceCacheExpiration(); // Clear ID cache so this one will be reloaded as well.
            final String detailsMsg = intres.getLocalizedMessage("caadmin.renamedca", oldname, cadata.getCaId(), newname);
            logSession.log(EventTypes.CA_RENAMING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(caid), null, null, detailsMsg);
        } else {
            throw new CAExistsException("CA " + newname + " already exists.");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getAllCaIds() {
        // We need a cache of these, to not list from the database all the time
        return caIDCache.getIdCacheContent();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getCAIdToNameMap() {
        // We need a cache of these, to not list from the database all the time
        return caIDCache.getIdNameCacheContent();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<String> getActiveCANames(final AuthenticationToken admin) {
        return new ArrayList<>(getActiveCAIdToNameMap(admin).values());
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getActiveCAIdToNameMap(final AuthenticationToken authenticationToken) {
        final HashMap<Integer, String> returnval = new HashMap<>();
        for (int caId : getAllCaIds()) {
            if (authorizedToCANoLogging(authenticationToken, caId)) {
                CAInfo caInfo = getCAInfoInternal(caId);
                if (caInfo != null && (caInfo.getStatus() == CAConstants.CA_ACTIVE || caInfo.getStatus() == CAConstants.CA_UNINITIALIZED)) {
                    returnval.put(caInfo.getCAId(), caInfo.getName());
                }
            }
        }

        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getAuthorizedCaIds(final AuthenticationToken admin) {
        final Collection<Integer> availableCaIds = getAllCaIds();
        final ArrayList<Integer> returnval = new ArrayList<>();
        for (Integer caid : availableCaIds) {
            if (authorizedToCANoLogging(admin, caid)) {
                returnval.add(caid);
            }
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<String> getAuthorizedCaNames(final AuthenticationToken admin) {
        final Collection<Integer> availableCaIds = getAllCaIds();
        final TreeSet<String> names = new TreeSet<>();
        for (Integer caid : availableCaIds) {
            if (authorizedToCANoLogging(admin, caid)) {
                names.add(getCAInfoInternal(caid).getName());
            }
        }
        return names;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public TreeMap<String,Integer> getAuthorizedCaNamesToIds(final AuthenticationToken admin) {
        final Collection<Integer> availableCaIds = getAllCaIds();
        final TreeMap<String,Integer> names = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (Integer caid : availableCaIds) {
            if (authorizedToCANoLogging(admin, caid)) {
                final CAInfo caInfo = getCAInfoInternal(caid);
                if (caInfo != null) {
                    names.put(caInfo.getName(), caInfo.getCAId());
                }
            }
        }
        return names;
    }


    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<CAInfo> getAuthorizedAndEnabledCaInfos(AuthenticationToken authenticationToken) {
        List<CAInfo> result = new ArrayList<>();
        for (int caId : getAuthorizedCaIds(authenticationToken)) {
            CAInfo caInfo = getCAInfoInternal(caId);
            if ( caInfo != null && caInfo.getStatus() != CAConstants.CA_EXTERNAL
                    && caInfo.getStatus() != CAConstants.CA_UNINITIALIZED
                    && caInfo.getStatus() != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE ) {
                result.add(caInfo);
            }
        }
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<CAInfo> getAuthorizedAndNonExternalCaInfos(AuthenticationToken authenticationToken) {
        List<CAInfo> result = new ArrayList<>();
        for (Integer caId : getAuthorizedCaIds(authenticationToken)) {
            CAInfo caInfo = getCAInfoInternal(caId);
            if ( caInfo != null && caInfo.getStatus() != CAConstants.CA_EXTERNAL ) {
                result.add(caInfo);
            }
        }
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<CAInfo> getAuthorizedCaInfos(AuthenticationToken authenticationToken) {
        List<CAInfo> result = new ArrayList<>();
        for (Integer caId : getAuthorizedCaIds(authenticationToken)) {
            CAInfo caInfo = getCAInfoInternal(caId);
            if (caInfo != null) {
                result.add(caInfo);
            }
        }
        return result;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void verifyExistenceOfCA(int caid) throws CADoesntExistsException {
        if( getCAInternal(caid, null, null, true) == null) {
            throw new CADoesntExistsException("CA with id " + caid + " does not exist.");
        }
       
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
	public CACommon getCAInternal(int caid, final String name, final String keySequence, boolean fromCache) {
	    if (log.isTraceEnabled()) {
	        log.trace(">getCAInternal: " + caid + ", " + name + ", " + keySequence);
	    }
	    Integer caIdValue = caid;
	    if (caid == -1) {
	        caIdValue = CaCache.INSTANCE.getNameToIdMap().get(name);
	    }
	    CACommon ca = null;
	    if (fromCache && caIdValue != null) {
	        ca = getCa(caIdValue, keySequence);
	        if (ca != null && hasCAExpiredNow(ca)) {
	            // CA has expired, re-read from database with the side affect that the status will be updated
	            log.trace("getCAData 1");
	            ca = getCAData(caid, name, keySequence).getCA();
	        }
	    } else {
            log.trace("getCAData 2");
            CAData caData = getCAData(caid, name, keySequence);
            if (caData != null) {
                ca = caData.getCA();
            }
        }
	    if (log.isTraceEnabled()) {
	        log.trace("<getCAInternal: " + caid + ", " + name+ ", " + keySequence);
	    }
	    return ca;
	}

	/**
     * Checks if the CA certificate has expired (or is not yet valid) since last check.
     * Logs an info message first time that the CA certificate has expired, or every time when not yet valid.
     *
     * @return the true if the CA is expired
     */
    private boolean hasCAExpiredNow(final CACommon ca) {
        boolean expired = false;
        // Check that CA hasn't expired.
        try {
            CertTools.checkValidity(ca.getCACertificate(), new Date());
        } catch (CertificateExpiredException cee) {
            // Signers Certificate has expired, we want to make sure that the
            // status in the database is correctly EXPIRED for this CA
            // Don't set external CAs to expired though, because they should always be treated as external CAs
            if (ca.getStatus()!=CAConstants.CA_EXPIRED && ca.getStatus()!=CAConstants.CA_EXTERNAL) {
                log.info(intres.getLocalizedMessage("caadmin.caexpired", ca.getSubjectDN()) + " " + cee.getMessage());
                expired = true;
            }
        } catch (CertificateNotYetValidException e) {
            // Signers Certificate is not yet valid.
            log.warn(intres.getLocalizedMessage("caadmin.canotyetvalid", ca.getSubjectDN()) + " " + e.getMessage());
        }
        return expired;
    }

    /**
     * Internal method for getting CAData. Tries to find the CA even if the CAId is wrong due to CA certificate DN not being the same as CA DN,
     * i.e. using a subject of the CA DN in the actual issues CA certificate. This can be the case if you want to add more meta-data to the CA DN, or
     * it can be the case if you have EAC (CVC CAs) DVs where the same mnemonic and country is used for multiple DVs, signed by different countred CVCAs.
     * 
     * CVC Example: CA DNs "C=SE,OU=Norway,CN=DVCA - sequence (serialNo) = NO002" for a DV signed by Norways vs "C=SE,OU=Finland,CN=DVCA - sequence (serialNo) = FI002" for a DV signed by Finland,
     * in this case the CA certificate DN is only "C=SE,CN=DVCA - sequence (serialNo) = NO002" and "C=SE,CN=DVCA - sequence (serialNo) = FI002" as
     * CVC (EAC BSI TR 03-110) only allow country (C) and mnemonic (CN) in the certificate
     *
     * The returned CAData object is guaranteed to be upgraded and these upgrades merged back to the database.
     *
     * @param caid numerical id of CA (subjectDN.hashCode()) that we search for, or -1 of a name is to ge used instead
     * @param name human readable name of CA, used instead of caid if caid == -1, can be null of caid != -1
     * 
     * @return the CA, or null if it was not found
     */
    private CAData getCAData(final int caid, final String name, final String keySequence)  {
        if (log.isTraceEnabled()) {
            log.trace(">getCAData: " + caid + ", " + name + ", " + keySequence);
        }
        CAData cadata = null;
        if (caid != -1) {
            cadata = upgradeAndMergeToDatabase(findById(caid));
            if (log.isDebugEnabled() && cadata == null) {
                log.debug("Unable to get CAData with ID (from SubjectDN): "+caid);
            }
        } else {
            cadata = upgradeAndMergeToDatabase(findByName(name));
            if (log.isDebugEnabled() && cadata == null) {
                log.debug("Unable to get CAData with name: "+name);
            }
        }
        // Do we have a keySequence? In that case we're in trouble, the CA ID we just might have been the completely wrong one. 
        // Using CVC, especially with multiple DVs using the same mnemonic (CN), messes up caching big time
        if (keySequence != null && cadata != null) {
            final List<Certificate> certChain = cadata.getCA().getCertificateChain();
            final String sequence;
            if (certChain != null && certChain.size() > 0) { // make sure it's not a CA without certs, no NPEs here
                sequence = CertTools.getSerialNumberAsString(certChain.get(0));
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Found a cached CA for " + caid + "/" + name + " that didn't have any certificate chain.");
                }
                // If this CA didn't have any certificates, it surely wasn't the right one if we are looking for a specific key sequence
                sequence = null;
            }
            if (!StringUtils.equals(keySequence, sequence)) {
                // it was not the right CA, remove it from cache so we will find the right one instead
                if (log.isDebugEnabled()) {
                    log.debug("We had a cached CA already for " + caid + "/" + name + " but it was not the right with the right keySequence (" + keySequence + "), so ignoring this find and looking again...");
                }
                cadata = null;
            }
        }
        if (cadata == null) {
            if (log.isDebugEnabled()) {
                log.debug("cadata is null, trying to find a mapping from CA ID "+caid+" to another CA ID");
            }
            // We should never get to here if we are searching for name, in any
            // case if the name does not exist, the CA really does not exist
            // We don't have to try to find another mapping for the CAId
            if (caid != -1) {
                // subject DN of the CA certificate might not have all objects
                // that is the DN of the certificate data.
                final Integer oRealCAId = CACacheHelper.getCaCertHash(caid);
                // has the "real" CAID been mapped to the certificate subject
                // hash by a previous call?
                if (oRealCAId != null) {
                    // yes, using cached value of real caid.
                	if (log.isDebugEnabled()) {
                		log.debug("Found a mapping from caid "+caid+" to realCaid "+oRealCAId);
                	}
                    cadata = findById(oRealCAId);
                } else {
                    // no, we have to search for it among all CA certs
                    for (final CAData currentCaData : findAll()) {
                        final CAData currentUpgradedCaData = upgradeAndMergeToDatabase(currentCaData);
                        final CACommon ca = currentUpgradedCaData.getCA();
                        if (ca == null) {
                            // This happens if Community Edition is deployed with CVCA's in the database. That won't work,
                            // but let's print a useful error so you can delete the CA from the database (or deploy EE instead) 
                            log.error("Implementation class for CA '" + currentUpgradedCaData.getName() + "' was not found, perhaps it is not available in this edition of EJBCA?");
                            continue;
                        }
                        final Certificate caCert = ca.getCACertificate();
                        if (caCert != null && caid == CertTools.getSubjectDN(caCert).hashCode()) {
                            // we may have several to choose from here, this is the tricky part, how to 
                            // figure out which of the multiple DVs that is the right one?
                            // We will use the serial number (CVC sequence that is) for that, which gives one remaining limitation, that they can not use the same 
                            // sequence, i.e. a DV signed by Finland can not have the same sequence as a DV signed by Norway, _if_ they share the same country+mnemonic (C and CN)
                            final String caKeySeq = CertTools.getSerialNumberAsString(caCert);
                            if (log.isDebugEnabled()) {
                                log.debug("CA cert type " + caCert.getType() + ", sequence: " + caKeySeq + ", sought keySequence: " + keySequence);
                            }
                            if (caCert.getType().equals("CVC")) {
                                // It's a CVC certificate, check that the sequence (if we passed one as argument) matches the CA
                                if (StringUtils.isNotEmpty(keySequence)) {
                                    if (StringUtils.equals(keySequence, caKeySeq)) {
                                        // Yes, we were looking for exactly this CA certificate
                                        if (log.isDebugEnabled()) {
                                            log.debug("We were looking for a CA with ID " + caid + " and keySequence " + keySequence + ", and found another CA to map to with the same keySequence and CA ID " + currentUpgradedCaData.getCaId());
                                        }
                                    } else {
                                        // No, we were not looking for exactly this CA certificate/CA
                                        // move on and look for another CA
                                        if (log.isDebugEnabled()) {
                                            log.debug("We were looking for a CA with ID " + caid + " and keySequence " + keySequence + ", but found another CA with keySequence " + caKeySeq + ", not found continuing search...");
                                        }
                                        continue;
                                    }
                                }
                            }
                            cadata = currentUpgradedCaData; // found.
                            // Do also cache it if someone else is needing it later
                        	if (log.isDebugEnabled()) {
                        		log.debug("Adding a mapping from caid "+caid+" to realCaid "+cadata.getCaId());
                        	}
                            CACacheHelper.putCaCertHash(caid, cadata.getCaId());
                        }
                        if (cadata != null) {
                            break;
                        }
                    }
                }
            }
            if (cadata == null) {
                String msg;
                if (caid != -1) {
                    msg = intres.getLocalizedMessage("caadmin.canotexistsid", caid);
                } else {
                    msg = intres.getLocalizedMessage("caadmin.canotexistsname", name);
                }
                log.info(msg);
            }
        }
        return cadata;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean authorizedToCANoLogging(final AuthenticationToken admin, final int caid) {
        final boolean ret = authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid);
        if (log.isDebugEnabled() && !ret) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            log.debug(msg);
        }
        return ret;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public boolean authorizedToCA(final AuthenticationToken admin, final int caid) {
    	final boolean ret = authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid);
        if (log.isDebugEnabled() && !ret) {
        	final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
        	log.debug(msg);
        }
        return ret;
    }

    /** @return the CA object, from the database (including any upgrades) is necessary */
    private CACommon getCa(int caId, final String keySequence) {
        final Integer realCAId = CACacheHelper.getCaCertHash(caId);
        if (realCAId != null) {
            // Since we have found a cached "real" CA Id and the cache will use this one (if cached)
            caId = realCAId;
        }
        // 0. Do we have a keySequence? In that case we're in trouble, the CA ID we just have might be the completely wrong one. 
        // Using CVC (especially with multiple DVs using the same mnemoinc (CN), messes up caching big time
        if (keySequence != null && CaCache.INSTANCE.getEntry(caId) != null) {
            final CACommon ca = CaCache.INSTANCE.getEntry(caId);
            if (ca != null && ca.getCertificateChain() != null && ca.getCertificateChain().get(0) != null) {
                final String sequence = CertTools.getSerialNumberAsString(ca.getCertificateChain().get(0));
                if (!StringUtils.equals(keySequence, sequence)) {
                    // it was not the right CA, remove it from cache so we will find the right one instead
                    if (log.isDebugEnabled()) {
                        log.debug("We had a cached CA already for " + caId + " but it was not the right with the right keySequence (" + keySequence + "), so purging from cache and looking in database.");
                    }
                    CaCache.INSTANCE.removeEntry(caId);
                }
            }
        }
        // 1. Check (new) CaCache if it is time to sync-up with database (or it does not exist)
        if (CaCache.INSTANCE.shouldCheckForUpdates(caId)) {
            if (log.isDebugEnabled()) {
                log.debug("CA with ID " + caId + " will be checked for updates.");
            }
            // 2. If cache is expired or missing, first thread to discover this reloads item from database and sends it to the cache         
            final CAData caData = getCAData(caId, null, keySequence);
            if (caData != null) {
                final int digest = caData.getProtectString(0).hashCode();
                // Special for splitting out the CAToken and committing it..
                // Since getCAData has already run upgradeAndMergeToDatabase we can just get the CA here..
                final CACommon ca = caData.getCA();
                if (ca != null) {
                    // Note that we store using the "real" CAId in the cache.
                    CaCache.INSTANCE.updateWith(caData.getCaId(), digest, ca.getName(), ca);
                }
                // Since caching might be disabled, we return the value returned from the database here
                return ca;
            } else {
                // Ensure that it is removed from cache
                CaCache.INSTANCE.removeEntry(caId);
            }
            // 3. The cache compares the database data with what is in the cache
            // 4. If database is different from cache, replace it in the cache
        }
        // 5. Get CA from cache (or null) and be merry
        if (log.isDebugEnabled()) {
            log.debug("Returning CA from cache for CA ID: " + caId);
        }
        return CaCache.INSTANCE.getEntry(caId);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public int mergeCa(final CACommon ca) {
        final int caId = ca.getCAId();
        CAData caData = entityManager.find(CAData.class, caId);
        if (caData == null) {
            caData = new CAData(ca.getSubjectDN(), ca.getName(), ca.getStatus(), ca);
        } else {
            // It might be the case that the calling transaction has already loaded a reference to this object
            // and hence we need to get the same one and perform updates on this object instead of trying to
            // merge a new object.
            caData.setCA(ca);
        }
        entityManager.merge(caData);
        // Since loading a CA is quite complex (populating CAInfo etc), we simple purge the cache here
        CaCache.INSTANCE.removeEntry(caId);
        caIDCache.forceCacheExpiration();
        return caId;
    }

    /** Performs upgrades on the entity if needed within a transaction. */
    private CAData upgradeAndMergeToDatabase(CAData cadata) {
        if (cadata == null) {
            return null;
        }
        CAData caDataReturn = cadata;
        final LinkedHashMap<Object, Object> caDataMap = cadata.getDataMap();
        // If CA-data is upgraded we want to save the new data, so we must get the old version before loading the data
        // and perhaps upgrading
        final float oldversion = ((Float) caDataMap.get(UpgradeableDataHashMap.VERSION)).floatValue();
        // Perform "live" upgrade from 5.0.x and earlier
        boolean adhocUpgrade = adhocUpgradeFrom50(cadata.getCaId().intValue(), caDataMap, cadata.getName());
        if (adhocUpgrade) {
            // Convert map into storage friendly format now since we changed it
            cadata.setDataMap(caDataMap);
        }
        // Fetching the CA object will trigger UpgradableHashMap upgrades
        CACommon ca = cadata.getCA();
        if (ca != null) {
            final boolean expired = hasCAExpiredNow(ca);
            if (expired) {
                ca.setStatus(CAConstants.CA_EXPIRED);
            }
            final boolean upgradedExtendedService = ca.upgradeExtendedCAServices();
            // Compare old version with current version and save the data if there has been a change
            final boolean upgradeCA = (Float.compare(oldversion, ca.getVersion()) != 0);
            if (adhocUpgrade || upgradedExtendedService || upgradeCA || expired) {
                if (log.isDebugEnabled()) {
                    log.debug("Merging CA to database. Name: " + cadata.getName() + ", id: " + cadata.getCaId() +
                            ", adhocUpgrade: " + adhocUpgrade+", upgradedExtendedService: " + upgradedExtendedService +
                            ", upgradeCA: " + upgradeCA + ", expired: " + expired);
                }
                ca.getCAToken();
                final int caId = caSession.mergeCa(ca);
                caDataReturn = entityManager.find(CAData.class, caId);
            }            
        }
        return caDataReturn;
    }

    /**
     * Extract keystore or keystore reference and store it as a CryptoToken. Add a reference to the keystore.
     * @return true if any changes where made
     */
    @SuppressWarnings("unchecked")
    @Deprecated // Remove when we no longer need to support upgrades from 5.0.x
    private boolean adhocUpgradeFrom50(int caid, LinkedHashMap<Object, Object> data, String caName) {
        HashMap<String, String> tokendata = (HashMap<String, String>) data.get(CABase.CATOKENDATA);
        if (tokendata.get(CAToken.CRYPTOTOKENID) != null) {
            // Already upgraded
            if (!CesecoreConfiguration.isKeepInternalCAKeystores()) {
                // All nodes in the cluster has been upgraded so we can remove any internal CA keystore now
                if (tokendata.get(CAToken.KEYSTORE)!=null) {
                    tokendata.remove(CAToken.KEYSTORE);
                    tokendata.remove(CAToken.CLASSPATH);
                    log.info("Removed duplicate of upgraded CA's internal keystore for CA '" + caName + "' with id: " + caid);
                    return true;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("CA '" + caName + "' already has cryptoTokenId and will not have it's token split of to a different db table because db.keepinternalcakeystores=true: " + caid);
                }
            }
            return false;
        }
        // Perform pre-upgrade of CATokenData to correct classpath changes (org.ejbca.core.model.ca.catoken.SoftCAToken)
        tokendata = (LinkedHashMap<String, String>) new CAToken(tokendata).saveData();
        data.put(CABase.CATOKENDATA, tokendata);
        log.info("Pulling CryptoToken out of CA '" + caName + "' with id " + caid + " into a separate database table.");
        final String str = tokendata.get(CAToken.KEYSTORE);
        byte[] keyStoreData = null;
        if (StringUtils.isNotEmpty(str)) {
            keyStoreData = Base64.decode(str.getBytes());
        }
        String propertyStr = tokendata.get(CAToken.PROPERTYDATA);
        final Properties prop = new Properties();
        if (StringUtils.isNotEmpty(propertyStr)) {
            try {
                // If the input string contains \ (backslash on windows) we must convert it to \\
                // Otherwise properties.load will parse it as an escaped character, and that is not good
                propertyStr = StringUtils.replace(propertyStr, "\\", "\\\\");
                prop.load(new ByteArrayInputStream(propertyStr.getBytes()));
            } catch (IOException e) {
                log.error("Error getting CA token properties: ", e);
            }
        }
        final String classpath = tokendata.get(CAToken.CLASSPATH);
        if (log.isDebugEnabled()) {
            log.debug("CA token classpath: " + classpath);
        }
        // Upgrade the properties value
        final Properties upgradedProperties = PKCS11CryptoToken.upgradePropertiesFileFrom5_0_x(prop);
        // If it is an P11 we are using and the library and slot are the same as an existing CryptoToken we use that CryptoToken's id.
        int cryptoTokenId = 0;
        if (PKCS11CryptoToken.class.getName().equals(classpath)) {
            if (upgradedProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE)==null) {
                log.error("Upgrade of CA '" + caName + "' failed due to failed upgrade of PKCS#11 CA token properties.");
                return false;
            }
            for (final Integer currentCryptoTokenId : cryptoTokenSession.getCryptoTokenIds()) {
                final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(currentCryptoTokenId);
                final Properties cryptoTokenProperties = cryptoToken.getProperties();
                if (StringUtils.equals(upgradedProperties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY), cryptoTokenProperties.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY))
                        && StringUtils.equals(upgradedProperties.getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY), cryptoTokenProperties.getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY))
                        && StringUtils.equals(upgradedProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE), cryptoTokenProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE))
                        && StringUtils.equals(upgradedProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE), cryptoTokenProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE))) {
                    // The current CryptoToken point to the same HSM slot in the same way.. re-use this id!
                    cryptoTokenId = currentCryptoTokenId;
                    break;
                }
            }
        }
        if (cryptoTokenId == 0) {
            final String cryptoTokenName = "Upgraded CA CryptoToken for " + caName;
            try {
                cryptoTokenId = cryptoTokenSession.mergeCryptoToken(CryptoTokenFactory.createCryptoToken(classpath, upgradedProperties, keyStoreData, caid, cryptoTokenName, true));
            } catch (CryptoTokenNameInUseException e) {
                final String msg = "Crypto token name already in use upgrading (adhocUpgradeFrom50) crypto token for CA '"+caName+"', cryptoTokenName '"+cryptoTokenName+"'.";
                log.info(msg, e);
                throw new RuntimeException(msg, e);  // Since we have a constraint on CA names to be unique, this should never happen
            } catch (NoSuchSlotException e) {
                final String msg = "Slot as defined by " + upgradedProperties.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE) + " for CA '" + caName + "' could not be found.";
                log.error(msg, e);
                throw new RuntimeException(msg, e);
            }
        }
        // Mark this CA as upgraded by setting a reference to the CryptoToken if the merge was successful
        tokendata.put(CAToken.CRYPTOTOKENID, String.valueOf(cryptoTokenId));
        // Note: We did not remove the keystore in the CA properties here, so old versions running in parallel will still work
        log.info("CA '" + caName + "' with id " + caid + " is now using CryptoToken with cryptoTokenId " + cryptoTokenId);
        return true;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Certificate getFutureRolloverCertificate(int cAId) throws CADoesntExistsException {
        final CACommon ca = getCa(cAId, null);
        if (ca == null) {
            throw new CADoesntExistsException("CA ID: " + cAId);
        }
        final List<Certificate> chain = ca.getRolloverCertificateChain();
        if (log.isDebugEnabled()) {
            log.debug("Found a RolloverCertificateChain of length " + (chain != null ? chain.size() : null) + ", for CA ID: " + cAId);
        }
        if (chain == null) {
            return null; 
        }
        return chain.get(0);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public int determineCrlPartitionIndex(final int caid, final CertificateWrapper cert) {
        final CACommon ca = getCa(caid, null);
        return ca.getCAInfo().determineCrlPartitionIndex(EJBTools.unwrap(cert));
    }
}
