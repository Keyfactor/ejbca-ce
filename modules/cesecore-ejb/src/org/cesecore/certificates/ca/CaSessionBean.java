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
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.internal.CACacheHelper;
import org.cesecore.certificates.ca.internal.CaCache;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

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
    private AccessControlSessionLocal accessSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    
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
    public void flushCACache() {
        CaCache.INSTANCE.flush();
        if (log.isDebugEnabled()) {
            log.debug("Flushed CA cache.");
        }
    }

    @Override
    public void addCA(final AuthenticationToken admin, final CA ca) throws CAExistsException, AuthorizationDeniedException {
        if (ca != null) {
            final int cryptoTokenId = ca.getCAToken().getCryptoTokenId();
            if (!accessSession.isAuthorized(admin, StandardRules.CAADD.resource(), CryptoTokenRules.USE.resource() + "/" + cryptoTokenId)) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoaddca", admin.toString(), Integer.valueOf(ca.getCAId()));
                throw new AuthorizationDeniedException(msg);
            }
            CAInfo cainfo = ca.getCAInfo();
            // The CA needs a name and a subject DN in order to store it
            if ((ca.getName() == null) || (ca.getSubjectDN() == null)) {
                throw new CAExistsException("Null CA name or SubjectDN. Name: '"+ca.getName()+"', SubjectDN: '"+ca.getSubjectDN()+"'.");
            }
            if (CAData.findByName(entityManager, cainfo.getName()) != null) {
                String msg = intres.getLocalizedMessage("caadmin.caexistsname", cainfo.getName());
                throw new CAExistsException(msg);
            }
            if (CAData.findById(entityManager, ca.getCAId()) != null) {
                String msg = intres.getLocalizedMessage("caadmin.caexistsid", Integer.valueOf(ca.getCAId()));
                throw new CAExistsException(msg);
            }
            entityManager.persist(new CAData(cainfo.getSubjectDN(), cainfo.getName(), cainfo.getStatus(), ca));
            String msg = intres.getLocalizedMessage("caadmin.addedca", ca.getCAId(), cainfo.getName(), cainfo.getStatus());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            details.put("tokenproperties", ca.getCAToken().getProperties());
            details.put("tokensequence", ca.getCAToken().getKeySequence());
            logSession.log(EventTypes.CA_CREATION, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(ca.getCAId()), null, null, details);
        } else {
            log.debug("Trying to add null CA, nothing done.");
        }
    }

    @Override
    public void editCA(final AuthenticationToken admin, final CAInfo cainfo) throws CADoesntExistsException, AuthorizationDeniedException {
        if (cainfo != null) {
        	if (log.isTraceEnabled()) {
        		log.trace(">editCA (CAInfo): "+cainfo.getName());
        	}
    		try {
    			final CA ca = getCAInternal(cainfo.getCAId(), null, false);
    			// Check if we can edit the CA (also checks authorization)
    			int newCryptoTokenId = ca.getCAToken().getCryptoTokenId();
    			if (cainfo.getCAToken() != null) {
    			    newCryptoTokenId = cainfo.getCAToken().getCryptoTokenId();
    			}
                assertAuthorizationAndTarget(admin, cainfo.getName(), cainfo.getSubjectDN(), newCryptoTokenId, ca);
                @SuppressWarnings("unchecked")
                final Map<Object, Object> orgmap = (Map<Object, Object>)ca.saveData();
                ca.updateCA(cryptoTokenManagementSession.getCryptoToken(ca.getCAToken().getCryptoTokenId()), cainfo);
                // Audit log
                @SuppressWarnings("unchecked")
                final Map<Object, Object> newmap = (Map<Object, Object>)ca.saveData();             
    			// Get the diff of what changed
                final Map<Object, Object> diff = UpgradeableDataHashMap.diffMaps(orgmap, newmap);
                final String msg = intres.getLocalizedMessage("caadmin.editedca", ca.getCAId(), ca.getName(), ca.getStatus());
    			// Use a LinkedHashMap because we want the details logged (in the final log string) in the order we insert them, and not randomly 
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
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
    
    @Override
    public void editCA(final AuthenticationToken admin, final CA ca, boolean auditlog) throws CADoesntExistsException, AuthorizationDeniedException {
    if (ca != null) {
        	if (log.isTraceEnabled()) {
        		log.trace(">editCA (CA): "+ca.getName());
        	}
        	final CA orgca = getCAInternal(ca.getCAId(), null, true);
        	// Check if we can edit the CA (also checks authorization)
        	assertAuthorizationAndTarget(admin, ca.getName(), ca.getSubjectDN(), ca.getCAToken().getCryptoTokenId(), orgca);
        	if (auditlog) {
        	    // Get the diff of what changed
        	    final Map<Object, Object> diff = orgca.diff(ca);
        	    String msg = intres.getLocalizedMessage("caadmin.editedca", ca.getCAId(), ca.getName(), ca.getStatus());
        	    // Use a LinkedHashMap because we want the details logged (in the final log string) in the order we insert them, and not randomly 
        	    final Map<String, Object> details = new LinkedHashMap<String, Object>();
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
    
    @Override
    public boolean existsCa(final int caId) {
        return entityManager.find(CAData.class, caId) != null;
    }
    @Override
    public boolean existsCa(final String name) {
        return CAData.findByName(entityManager, name) != null;
    }

	/** Ensure that the caller is authorized to the CA we are about to edit and that the CA name and subjectDN matches. */
	private void assertAuthorizationAndTarget(AuthenticationToken admin, final String name, final String subjectDN, final int cryptoTokenId, final CA ca)
			throws CADoesntExistsException, AuthorizationDeniedException {
        // Check if we are authorized to edit CA and authorization to specific CA
        if (cryptoTokenId == ca.getCAToken().getCryptoTokenId() || cryptoTokenId==0) {
            if (!accessSession.isAuthorized(admin, StandardRules.CAEDIT.resource(), StandardRules.CAACCESS.resource())) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", admin.toString(), Integer.valueOf(ca.getCAId()));
                throw new AuthorizationDeniedException(msg);
            }
        } else {
            // We only need to check usage authorization if we change CryptoToken reference (and not to 0 which means "removed").
            if (!accessSession.isAuthorized(admin, StandardRules.CAEDIT.resource(), StandardRules.CAACCESS.resource(), CryptoTokenRules.USE.resource() + "/" + cryptoTokenId)) {
                String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", admin.toString(), Integer.valueOf(ca.getCAId()));
                throw new AuthorizationDeniedException(msg);
            }
        }
		// The CA needs the same name and subject DN in order to store it
		if (name == null || subjectDN == null) {
		    throw new CADoesntExistsException("Null CA name or SubjectDN");
		} else if (!StringUtils.equals(name, ca.getName())) {
		    throw new CADoesntExistsException("Not same CA name.");
		} else if (!StringUtils.equals(subjectDN, ca.getSubjectDN()) && ca.getCAInfo().getStatus() != CAConstants.CA_UNINITIALIZED) {
            throw new CADoesntExistsException("Not same CA subject DN.");
        }
	}

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CA getCA(final AuthenticationToken admin, final int caid) throws CADoesntExistsException, AuthorizationDeniedException {
        if (!authorizedToCA(admin, caid)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), Integer.valueOf(caid));
            throw new AuthorizationDeniedException(msg);
        }
        return getCAInternal(caid, null, true);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CA getCA(final AuthenticationToken admin, final String name) throws CADoesntExistsException, AuthorizationDeniedException {
        CA ca = getCAInternal(-1, name, true);
        if (!authorizedToCA(admin, ca.getCAId())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), name);
            throw new AuthorizationDeniedException(msg);
        }
        return ca;
    }
       
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CA getCANoLog(final AuthenticationToken admin, final int caid) throws CADoesntExistsException, AuthorizationDeniedException {
        if (!authorizedToCANoLogging(admin, caid)) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), Integer.valueOf(caid));
            throw new AuthorizationDeniedException(msg);
        }
        return getCAInternal(caid, null, true);
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CA getCAForEdit(final AuthenticationToken admin, final int caid) throws CADoesntExistsException, AuthorizationDeniedException {
        CA ca = getCAInternal(caid, null, false);
        if (!authorizedToCA(admin, ca.getCAId())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), Integer.valueOf(caid));
            throw new AuthorizationDeniedException(msg);
        }
        return ca;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public CA getCAForEdit(final AuthenticationToken admin, final String name) throws CADoesntExistsException, AuthorizationDeniedException {
        CA ca = getCAInternal(-1, name, false);
        if (!authorizedToCA(admin, ca.getCAId())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), name);
            throw new AuthorizationDeniedException(msg);
        }
        return ca;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfo(final AuthenticationToken admin, final String name) throws CADoesntExistsException, AuthorizationDeniedException {
    	// Authorization is handled by getCA
        return getCA(admin, name).getCAInfo();
    }


    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfo(final AuthenticationToken admin, final int caid) throws CADoesntExistsException, AuthorizationDeniedException {
    	// Authorization is handled by getCA
        return getCA(admin, caid).getCAInfo();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfoInternal(final int caid) throws CADoesntExistsException {
        return getCAInternal(caid, null, true).getCAInfo();
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfoInternal(final int caid, final String name, boolean fromCache) throws CADoesntExistsException {
        return getCAInternal(caid, name, fromCache).getCAInfo();
    }

    @Override
    public void removeCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        // check authorization
        if (!accessSession.isAuthorized(admin, StandardRules.CAREMOVE.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoremoveca", admin.toString(), Integer.valueOf(caid));
            throw new AuthorizationDeniedException(msg);
        }
        // Get CA from database if it does not exist, ignore
        CAData cadata = CAData.findById(entityManager, Integer.valueOf(caid));
        if (cadata != null) {
            // Remove CA
            entityManager.remove(cadata);
            // Invalidate CA cache to refresh information
            CaCache.INSTANCE.removeEntry(caid);
            final String detailsMsg = intres.getLocalizedMessage("caadmin.removedca", Integer.valueOf(caid), cadata.getName());
            logSession.log(EventTypes.CA_DELETION, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(caid), null, null, detailsMsg);
        }
    }

    @Override
    public void renameCA(final AuthenticationToken admin, final String oldname, final String newname) throws CAExistsException,
            CADoesntExistsException, AuthorizationDeniedException {
        // Get CA from database
        CAData cadata = CAData.findByNameOrThrow(entityManager, oldname);
        // Check authorization, to rename we need remove (for the old name) and add for the new name)
        if (!accessSession.isAuthorized(admin, StandardRules.CAREMOVE.resource(), StandardRules.CAADD.resource())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtorenameca", admin.toString(), cadata.getCaId());
            throw new AuthorizationDeniedException(msg);
        }
        if (CAData.findByName(entityManager, newname) == null) {
            // new CA doesn't exits, it's ok to rename old one.
            cadata.setName(newname);
            // Invalidate CA cache to refresh information
            int caid = cadata.getCaId().intValue();
            CaCache.INSTANCE.removeEntry(caid);
            final String detailsMsg = intres.getLocalizedMessage("caadmin.renamedca", oldname, cadata.getCaId(), newname);
            logSession.log(EventTypes.CA_RENAMING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(caid), null, null, detailsMsg);
        } else {
            throw new CAExistsException("CA " + newname + " already exists.");
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getAllCaIds() {
        return CAData.findAllCaIds(entityManager);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<String> getActiveCANames(final AuthenticationToken admin) {
        final ArrayList<String> returnval = new ArrayList<String>();
        for (int caiId : getAllCaIds()) {
            if (authorizedToCA(admin, caiId)) {
                CAInfo caInfo;
                try {
                    caInfo = getCAInfoInternal(caiId);
                    if (caInfo.getStatus() == CAConstants.CA_ACTIVE) {
                        returnval.add(caInfo.getName());
                    }
                } catch (CADoesntExistsException e) {
                    //NOPMD: This can never happen
                }
            }
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Map<Integer, String> getActiveCAIdToNameMap(final AuthenticationToken authenticationToken) {
        final HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        for (int caiId : getAllCaIds()) {
            if (authorizedToCA(authenticationToken, caiId)) {
                CAInfo caInfo;
                try {
                    caInfo = getCAInfoInternal(caiId);
                    if (caInfo.getStatus() == CAConstants.CA_ACTIVE) {
                        returnval.put(caInfo.getCAId(), caInfo.getName());
                    }
                } catch (CADoesntExistsException e) {
                    //NOPMD: This can never happen
                }
            }
        }
     
        return returnval;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Integer> getAuthorizedCaIds(final AuthenticationToken admin) {
        final Collection<Integer> availableCaIds = getAllCaIds();
        final ArrayList<Integer> returnval = new ArrayList<Integer>();
        for (Integer caid : availableCaIds) {
            if (authorizedToCANoLogging(admin, caid)) {
                returnval.add(caid);
            }
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<CAInfo> getAuthorizedAndEnabledCaInfos(AuthenticationToken authenticationToken) {
        List<CAInfo> result = new ArrayList<CAInfo>();
        for (int caId : getAuthorizedCaIds(authenticationToken)) {
            CAInfo caInfo;
            try {
                caInfo = getCAInfoInternal(caId);
            } catch (CADoesntExistsException e) {
                throw new IllegalStateException("CA with ID " + caId + " was not found in spite if just being retrieved.");
            }
            int status = caInfo.getStatus();
            if ( status != CAConstants.CA_UNINITIALIZED
                    && status != CAConstants.CA_EXTERNAL && status != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
                result.add(caInfo);
            }
        }
        return result;
    }
    

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public void verifyExistenceOfCA(int caid) throws CADoesntExistsException {
        getCAInternal(caid, null, true);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public HashMap<Integer, String> getCAIdToNameMap() {
        final HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        for (final CAData cadata : CAData.findAll(entityManager)) {
            returnval.put(cadata.getCaId(), cadata.getName());
        }
        return returnval;
    }


    /**
     * Internal method for getting CA, to avoid code duplication. Tries to find the CA even if the CAId is wrong due to CA certificate DN not being
     * the same as CA DN. Uses CACache directly if configured to do so in ejbca.properties.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for, or -1 if a name is to be used instead
     * @param name
     *            human readable name of CA, used instead of caid if caid == -1, can be null if caid != -1
     * @param fromCache if we should use the CA cache or return a new, decoupled, instance from the database, to be used when you need
     *             a completely distinct object, for edit, and not a shared cached instance.
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if no CA was found
     */
	private CA getCAInternal(int caid, final String name, boolean fromCache) throws CADoesntExistsException {
	    if (log.isTraceEnabled()) {
	        log.trace(">getCAInternal: " + caid + ", " + name);
	    }
	    Integer caIdValue = Integer.valueOf(caid);
	    if (caid == -1) {
	        caIdValue = CaCache.INSTANCE.getNameToIdMap().get(name);
	    }
	    CA ca;
	    if (fromCache && caIdValue!=null) {
	        ca = getCa(caIdValue.intValue());
	        if (ca != null && hasCAExpiredNow(ca)) {
	            // CA has expired, re-read from database with the side affect that the status will be updated
	            ca = getCAData(caid, name).getCA();
	        }
	    } else {
	        ca = getCAData(caid, name).getCA();
	    }
	    if (log.isTraceEnabled()) {
	        log.trace("<getCAInternal: " + caid + ", " + name);
	    }
	    if (ca==null) {
	        throw new CADoesntExistsException("Could not find CA with name " + name + " and ID " + caid);
	    }
	    return ca;
	}

	/**
     * Checks if the CA certificate has expired (or is not yet valid) since last check.
     * Logs an info message first time that the CA certificate has expired, or every time when not yet valid.
     * 
     * @return the true if the CA is expired
     */
    private boolean hasCAExpiredNow(final CA ca) {
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
     * Internal method for getting CAData. Tries to find the CA even if the CAId is wrong due to CA certificate DN not being the same as CA DN.
     * 
     * The returned CAData object is guaranteed to be upgraded and these upgrades merged back to the database.
     * 
     * @param caid numerical id of CA (subjectDN.hashCode()) that we search for, or -1 of a name is to ge used instead
     * @param name human readable name of CA, used instead of caid if caid == -1, can be null of caid != -1
     * @throws CADoesntExistsException if no CA was found
     */
    private CAData getCAData(final int caid, final String name) throws CADoesntExistsException {
        CAData cadata = null;
        if (caid != -1) {
            cadata = upgradeAndMergeToDatabase(CAData.findById(entityManager, Integer.valueOf(caid)));
        } else {
            cadata = upgradeAndMergeToDatabase(CAData.findByName(entityManager, name));
        }
        if (cadata == null) {
            // We should never get to here if we are searching for name, in any
            // case if the name does not exist, the CA really does not exist
            // We don't have to try to find another mapping for the CAId
            if (caid != -1) {
                // subject DN of the CA certificate might not have all objects
                // that is the DN of the certificate data.
                final Integer oRealCAId = (Integer) CACacheHelper.getCaCertHash(Integer.valueOf(caid));
                // has the "real" CAID been mapped to the certificate subject
                // hash by a previous call?
                if (oRealCAId != null) {
                    // yes, using cached value of real caid.
                	if (log.isDebugEnabled()) {
                		log.debug("Found a mapping from caid "+caid+" to realCaid "+oRealCAId);
                	}
                    cadata = CAData.findById(entityManager, oRealCAId);
                } else {
                    // no, we have to search for it among all CA certs
                    for (final CAData currentCaData : CAData.findAll(entityManager)) {
                        final CAData currentUpgradedCaData = upgradeAndMergeToDatabase(currentCaData);
                        final Certificate caCert = currentUpgradedCaData.getCA().getCACertificate();
                        if (caCert != null && caid == CertTools.getSubjectDN(caCert).hashCode()) {
                            cadata = currentUpgradedCaData; // found.
                            // Do also cache it if someone else is needing it later
                        	if (log.isDebugEnabled()) {
                        		log.debug("Adding a mapping from caid "+caid+" to realCaid "+cadata.getCaId());
                        	}
                            CACacheHelper.putCaCertHash(Integer.valueOf(caid), Integer.valueOf(cadata.getCaId()));
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
                    msg = intres.getLocalizedMessage("caadmin.canotexistsid", Integer.valueOf(caid));
                } else {
                    msg = intres.getLocalizedMessage("caadmin.canotexistsname", name);
                }
                log.info(msg);
                throw new CADoesntExistsException(msg);
            }
        }
        return cadata;
    }
    
    @Override
    public boolean authorizedToCANoLogging(final AuthenticationToken admin, final int caid) {
        final boolean ret = accessSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid);
        if (log.isDebugEnabled() && !ret) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            log.debug(msg);
        }
        return ret;
    }

    @Override
    public boolean authorizedToCA(final AuthenticationToken admin, final int caid) {
    	final boolean ret = accessSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid);
        if (log.isDebugEnabled() && !ret) {
        	final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
        	log.debug(msg);
        }
        return ret;
    }

    /** @return the CA object, from the database (including any upgrades) is necessary */
    private CA getCa(int caId) {
        final Integer realCAId = CACacheHelper.getCaCertHash(Integer.valueOf(caId));
        if (realCAId!=null) {
            // Since we have found a cached "real" CA Id and the cache will use this one (if cached)
            caId = realCAId.intValue();
        }
        // 1. Check (new) CaCache if it is time to sync-up with database
        if (CaCache.INSTANCE.shouldCheckForUpdates(caId)) {
            log.debug("CA with ID " + caId + " will be checked for updates.");
            // 2. If cache is expired or missing, first thread to discover this reloads item from database and sends it to the cache
            try {
                CAData caData = getCAData(caId, null);
                final int digest = caData.getProtectString(0).hashCode();
                // Special for splitting out the CAToken and committing it..
                // Since getCAData has already run upgradeAndMergeToDatabase we can just get the CA here..
                CA ca = caData.getCA();
                // Note that we store using the "real" CAId in the cache.
                CaCache.INSTANCE.updateWith(caData.getCaId(), digest, ca.getName(), ca);
                // Since caching might be disabled, we return the value returned from the database here
                return ca;
            } catch (CADoesntExistsException e) {
                // Ensure that it is removed from cache
                CaCache.INSTANCE.removeEntry(caId);
            }
            // 3. The cache compares the database data with what is in the cache
            // 4. If database is different from cache, replace it in the cache
        }
        // 5. Get CA from cache (or null) and be merry
        return CaCache.INSTANCE.getEntry(caId);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public int mergeCa(final CA ca) {
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
        caData = entityManager.merge(caData);
        // Since loading a CA is quite complex (populating CAInfo etc), we simple purge the cache here
        CaCache.INSTANCE.removeEntry(caId);
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
        CA ca = cadata.getCA();
        final boolean expired = hasCAExpiredNow(ca);
        if (expired) {
            ca.setStatus(CAConstants.CA_EXPIRED);
        }
        final boolean upgradedExtendedService = ca.upgradeExtendedCAServices();
        // Compare old version with current version and save the data if there has been a change
        final boolean upgradeCA = (Float.compare(oldversion, ca.getVersion()) != 0);
        if (adhocUpgrade || upgradedExtendedService || upgradeCA || expired) {
            if (log.isDebugEnabled()) {
                log.debug("Merging CA to database. Name: "+cadata.getName()+", id: "+cadata.getCaId()+", adhocUpgrade: "+adhocUpgrade+", upgradedExtendedService: "+upgradedExtendedService+", upgradeCA: "+upgradeCA+", expired: "+expired);
            }
            ca.getCAToken();
            final int caId = caSession.mergeCa(ca);
            caDataReturn = entityManager.find(CAData.class, caId);
        }
        return caDataReturn;
    }

    /**
     * Extract keystore or keystore reference and store it as a CryptoToken. Add a reference to the keystore.
     * @return true if any changes where made
     */
    @Deprecated // Remove when we no longer need to support upgrades from 5.0.x
    private boolean adhocUpgradeFrom50(int caid, LinkedHashMap<Object, Object> data, String caName) {
        @SuppressWarnings("unchecked")
        HashMap<String, String> tokendata = (HashMap<String, String>) data.get(CA.CATOKENDATA);
        if (tokendata.get(CAToken.CRYPTOTOKENID) != null) {
            // Already upgraded
            if (!CesecoreConfiguration.isKeepInternalCAKeystores()) {
                // All nodes in the cluster has been upgraded so we can remove any internal CA keystore now
                if (tokendata.get(CAToken.KEYSTORE)!=null) {
                    tokendata.remove(CAToken.KEYSTORE);
                    tokendata.remove(CAToken.CLASSPATH);
                    log.info("Removed duplicate of upgraded CA's internal keystore for CA with id: " + caid);
                    return true;
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("CA already has cryptoTokenId and will not have it's token split of to a different db table because db.keepinternalcakeystores=true: " + caid);
                }
            }
            return false;
        }
        // Perform pre-upgrade of CATokenData to correct classpath changes (org.ejbca.core.model.ca.catoken.SoftCAToken)
        tokendata = (LinkedHashMap<String, String>) new CAToken(tokendata).saveData();
        data.put(CA.CATOKENDATA, tokendata);
        log.info("Pulling CryptoToken out of CA with id " + caid + " into a separate database table.");
        final String str = (String) tokendata.get(CAToken.KEYSTORE);
        byte[] keyStoreData = null;
        if (StringUtils.isNotEmpty(str)) {
            keyStoreData = Base64.decode(str.getBytes());
        }
        String propertyStr = (String) tokendata.get(CAToken.PROPERTYDATA);
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
        final String classpath = (String) tokendata.get(CAToken.CLASSPATH);
        if (log.isDebugEnabled()) {
            log.debug("CA token classpath: " + classpath);
        }
        // If it is an P11 we are using and the library and slot are the same as an existing CryptoToken we use that CryptoToken's id.
        int cryptoTokenId = 0;
        if (PKCS11CryptoToken.class.getName().equals(classpath)) {
            for (Integer currentCryptoTokenId : cryptoTokenSession.getCryptoTokenIds()) {
                CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(currentCryptoTokenId.intValue());
                if (StringUtils.equals(prop.getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY), cryptoToken.getProperties().getProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY))
                        && StringUtils.equals(prop.getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY), cryptoToken.getProperties().getProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY))
                        && StringUtils.equals(prop.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE), cryptoToken.getProperties().getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE))
                        && StringUtils.equals(prop.getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE), cryptoToken.getProperties().getProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE))) {
                    // The current CryptoToken point to the same HSM slot in the same way.. re-use this id!
                    cryptoTokenId = currentCryptoTokenId.intValue();
                    break;
                }
            }
        }
        if (cryptoTokenId == 0) {
            final String cryptoTokenName = "Upgraded CA CryptoToken for " + caName;
            try {
                //Upgrade the properties value
                Properties upgradedProperties = PKCS11CryptoToken.upgradePropertiesFileFrom5_0_x(prop);
                cryptoTokenId = cryptoTokenSession.mergeCryptoToken(CryptoTokenFactory.createCryptoToken(classpath, upgradedProperties, keyStoreData, caid, cryptoTokenName));
            } catch (CryptoTokenNameInUseException e) {
                String msg = "Crypto token name already in use upgrading (adhocUpgradeFrom50) crypto token for CA '"+caName+"', cryptoTokenName '"+cryptoTokenName+"'.";
                log.info(msg, e);
                throw new RuntimeException(msg, e);  // Since we have a constraint on CA names to be unique, this should never happen
            } catch (NoSuchSlotException e) {
                String msg = "Slot as defined by " + prop.getProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE) + " could not be found.";
                log.error(msg, e);
                throw new RuntimeException(msg, e);
            }
                
        }
        tokendata.put(CAToken.CRYPTOTOKENID, String.valueOf(cryptoTokenId));
        // Note: We did not remove the keystore in the CA properties here, so old versions running in parallel will still work
        return true;
    }

 
   
}
