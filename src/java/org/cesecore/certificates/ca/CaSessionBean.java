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

import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.EJBException;
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
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.certificates.ca.internal.CACacheHelper;
import org.cesecore.certificates.ca.internal.CACacheManager;
import org.cesecore.certificates.ca.internal.CATokenCacheManager;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;

/**
 * Implementation of CaSession, i.e takes care of all CA related CRUD operations.
 * 
 * Based on EJBCA version: CaSessionBean.java 10861 2010-12-14 16:00:17Z anatom
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
        CACacheHelper.setLastCACacheUpdateTime(-1);
        CACacheManager.instance().removeAll();
        if (log.isDebugEnabled()) {
            log.debug("Flushed CA cache.");
        }
    }

    @Override
    public void addCA(final AuthenticationToken admin, final CA ca) throws CAExistsException, AuthorizationDeniedException, IllegalCryptoTokenException {
        if (ca != null) {
            if (!accessSession.isAuthorized(admin, StandardRules.CAADD.resource())) {
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
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
    		CATokenInfo info = ca.getCAToken().getTokenInfo();
    		Properties prop = info.getProperties();
    		String sequence = info.getKeySequence();
            details.put("tokenproperties", prop);
            details.put("tokensequence", sequence);
            logSession.log(EventTypes.CA_CREATION, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(ca.getCAId()), null, null, details);
        } else {
            log.debug("Trying to add null CA, nothing done.");
        }
    }

    @Override
    public void editCA(final AuthenticationToken admin, final CAInfo cainfo) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException {
        if (cainfo != null) {
        	if (log.isTraceEnabled()) {
        		log.trace(">editCA (CAInfo): "+cainfo.getName());
        	}
        	// canEditCA checks authorization
    		try {
    			CAData data = getCADataBean(cainfo.getCAId(), null);
                CA ca = data.getCA();
                // Check if we can edit the CA
                canEditCA(admin, cainfo.getName(), cainfo.getSubjectDN(), ca);
                @SuppressWarnings("unchecked")
                Map<Object, Object> orgmap = (Map<Object, Object>)ca.saveData(); 
                ca.updateCA(cainfo);
                // Store it
    			data.setCA(ca);
    			
                // Audit log
                @SuppressWarnings("unchecked")
                Map<Object, Object> newmap = (Map<Object, Object>)ca.saveData();             
    			// Get the diff of what changed
    			Map<Object, Object> diff = UpgradeableDataHashMap.diffMaps(orgmap, newmap);
                String msg = intres.getLocalizedMessage("caadmin.editedca", ca.getCAId(), ca.getName(), ca.getStatus());
    			// Use a LinkedHashMap because we want the details logged (in the final log string) in the order we insert them, and not randomly 
                Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
    			for (Map.Entry<Object,Object> entry : diff.entrySet()) {
    				details.put(entry.getKey().toString(), entry.getValue().toString());				
    			}
        		CATokenInfo info = ca.getCAToken().getTokenInfo();
        		Properties prop = info.getProperties();
        		String sequence = info.getKeySequence();
                details.put("tokenproperties", prop);
                details.put("tokensequence", sequence);
                logSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(ca.getCAId()), null, null, details);    			
    		} catch (UnsupportedEncodingException e) {
    			throw new CADoesntExistsException(e);
    		} catch (IllegalCryptoTokenException e) {
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
    public void editCA(final AuthenticationToken admin, final CA ca, boolean auditlog) throws CADoesntExistsException, AuthorizationDeniedException, IllegalCryptoTokenException {
        if (ca != null) {
        	if (log.isTraceEnabled()) {
        		log.trace(">editCA (CA): "+ca.getName());
        	}
        	// canEditCA checks authorization
    		try {
    			CAData data = getCADataBean(ca.getCAId(), null);
                CA orgca = data.getCA();
                // Check if we can edit the CA
                canEditCA(admin, ca.getName(), ca.getSubjectDN(), orgca);
                // Store it
    			data.setCA(ca);
    			
    			if (auditlog) {
    				// Get the diff of what changed
    				Map<Object, Object> diff = orgca.diff(ca);
    	            String msg = intres.getLocalizedMessage("caadmin.editedca", ca.getCAId(), ca.getName(), ca.getStatus());
    				// Use a LinkedHashMap because we want the details logged (in the final log string) in the order we insert them, and not randomly 
    	            Map<String, Object> details = new LinkedHashMap<String, Object>();
    	            details.put("msg", msg);
    				for (Map.Entry<Object,Object> entry : diff.entrySet()) {
    					details.put(entry.getKey().toString(), entry.getValue().toString());				
    				}
    	    		CATokenInfo info = ca.getCAToken().getTokenInfo();
    	    		Properties prop = info.getProperties();
    	    		String sequence = info.getKeySequence();
    	            details.put("tokenproperties", prop);
    	            details.put("tokensequence", sequence);
    	            logSession.log(EventTypes.CA_EDITING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(ca.getCAId()), null, null, details);				
    			}
    		} catch (UnsupportedEncodingException e) {
    			throw new CADoesntExistsException(e);
    		} catch (IllegalCryptoTokenException e) {
    			throw new CADoesntExistsException(e);
    		}			
        	if (log.isTraceEnabled()) {
        		log.trace("<editCA (CA): "+ca.getName());
        	}
        } else {
            log.debug("Trying to edit null CA, nothing done.");
        }    	
    }

	/**
	 * @param ca
	 * @param orgca
	 * @throws CADoesntExistsException
	 * @throws AuthorizationDeniedException 
	 */
	private void canEditCA(AuthenticationToken admin, final String name, final String subjectDN, final CA orgca)
			throws CADoesntExistsException, AuthorizationDeniedException {
        // Check if we are authorized to edit CA and authorization to specific CA
        if (!accessSession.isAuthorized(admin, StandardRules.CAEDIT.resource(), StandardRules.CAACCESS.resource() + orgca.getCAId())) {
            String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoeditca", admin.toString(), Integer.valueOf(orgca.getCAId()));
            throw new AuthorizationDeniedException(msg);
        }
		// The CA needs the same name and subject DN in order to store it
		if ((name == null) || (subjectDN == null)) {
		    throw new CADoesntExistsException("Null CA name or SubjectDN");
		} else if (!StringUtils.equals(name, orgca.getName()) || !StringUtils.equals(subjectDN, orgca.getSubjectDN())) {
		    throw new CADoesntExistsException("Not same CA name and subject DN.");            	
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
    public CAInfo getCAInfo(final AuthenticationToken admin, final int caid, boolean doSignTest) throws CADoesntExistsException, AuthorizationDeniedException {
    	// Authorization is handled by getCA
        return getCAInfoOrThrowException(getCA(admin, caid), doSignTest);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public CAInfo getCAInfoInternal(final int caid, boolean doSignTest) throws CADoesntExistsException {
        return getCAInfoOrThrowException(getCAInternal(caid, null, true), doSignTest);
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
            CACacheManager.instance().removeCA(caid);
            // Remove an eventual CA token from the token registry
            CATokenCacheManager.instance().removeCAToken(caid);
            String msg = intres.getLocalizedMessage("caadmin.removedca", Integer.valueOf(caid), cadata.getName());
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CA_DELETION, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(caid), null, null, details);
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
            CACacheManager.instance().removeCA(caid);
            String msg = intres.getLocalizedMessage("caadmin.renamedca", oldname, cadata.getCaId(), newname);
            Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            logSession.log(EventTypes.CA_RENAMING, EventStatus.SUCCESS, ModuleTypes.CA, ServiceTypes.CORE,admin.toString(), String.valueOf(caid), null, null, details);
        } else {
            throw new CAExistsException("CA " + newname + " already exists.");
        }

    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAvailableCAs() {
        return CAData.findAllCaIds(entityManager);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<Integer> getAvailableCAs(final AuthenticationToken admin) {
        final Collection<Integer> availableCaIds = getAvailableCAs();
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
    public Collection<String> getAvailableCANames(final AuthenticationToken admin) {
        final Collection<CAData> allCAs = CAData.findAll(entityManager);
        final ArrayList<String> returnval = new ArrayList<String>();
        for (CAData ca : allCAs) {
            if (authorizedToCA(admin, ca.getCaId())) {
                returnval.add(ca.getName());
            }
        }
        return returnval;
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
     * the same as CA DN. Uses CACacheManager directly if configured to do so in ejbca.properties.
     * 
     * Note! No authorization checks performed in this internal method
     * 
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for, or -1 of a name is to ge used instead
     * @param name
     *            human readable name of CA, used instead of caid if caid == -1, can be null if caid != -1
     * @param fromCache if we should use the CA cache or return a new, decoupled, instance from the database, to be used when you need
     *             a completely distinct object, for edit, and not a shared cached instance.
     * @return CA value object, never null
     * @throws CADoesntExistsException
     *             if no CA was found
     */
	private CA getCAInternal(final int caid, final String name, boolean fromCache) throws CADoesntExistsException {
	    if (log.isTraceEnabled()) {
	        log.trace(">getCAInternal: " + caid + ", " + name);
	    }
	    // First check if we already have a cached instance of the CA
	    // This should only be done if we have enabled caching, meaning that
	    // we will not update the CA values until cache time expires
	    CA ca = null;
	    if (fromCache) {
	        if (CACacheHelper.getLastCACacheUpdateTime() + CesecoreConfiguration.getCacheCaTimeInCaSession() > System.currentTimeMillis()) {
	            if (caid != -1) {
	                ca = CACacheManager.instance().getCA(caid);
	            } else {
	                ca = CACacheManager.instance().getCA(name);
	            }
	        }
	    }
	    boolean isDatabaseUpdateRequired = false;
	    if (ca == null) {
	        if (log.isDebugEnabled()) {
	            log.debug("CA not found in cache (or cache time expired), we have to get it: " + caid + ", " + name);
	        }
	        try {
	            final CAData cadata = getCADataBean(caid, name);
	            // this method checks CA data row timestamp to see if CA was
	            // updated by any other cluster nodes
	            // also fills the CACacheManager cache if the CA is not in there
	            if (fromCache) {
	            	ca = cadata.getCA();
	                CACacheHelper.setLastCACacheUpdateTime(System.currentTimeMillis());             
	            } else {
	            	ca = cadata.getCAFromDatabase();
	            }
	            isDatabaseUpdateRequired = cadata.isDatabaseUpgradeRequired();
	        } catch (UnsupportedEncodingException uee) {
	            throw new EJBException(uee);
	        } catch (IllegalCryptoTokenException e) {
	            throw new EJBException(e);
	        }
	    }
	    // Check if CA has expired
	    final boolean expired = checkCAExpireAndUpdateCA(ca);
	    // If we have read CAData from the database we might have upgraded it.
	    // Since the business methods for getting the CA doesn't require a transaction we
	    // cannot be sure that setters on the CAData object has updated the database.
        if (isDatabaseUpdateRequired || expired) {
            // Merge any changes to the CA object
            try {
                caSession.editCA(new AlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal CA Upgrade/Expire")), ca, true);
            } catch (IllegalCryptoTokenException e) {
                throw new EJBException(e);
            } catch (AuthorizationDeniedException e) {
                throw new EJBException(e);
            }
        }
	    if (log.isTraceEnabled()) {
	        log.trace("<getCAInternal: " + caid + ", " + name);
	    }
	    return ca;
	}

	/**
	 * Internal method that get CA info, and optionally performs a sign test
	 * with the CAs test signing key.
	 * 
	 * If doSignTest is true, and the CA is active and the CA is included in
	 * healthcheck (cainfo.getIncludeInHealthCheck()), a signature with the test
	 * keys is performed to set the CA Token status correctly.
	 * 
	 * @param admin
	 *            administrator performing this action
	 * @param caid
	 *            numerical id of CA (subjectDN.hashCode()) that we search for
	 * @param doSignTest
	 *            true if a test signature should be performed, false if only
	 *            the status from token info is checked. Should normally be set
	 *            to false.
	 * @return CAInfo value object, never null
	 * @throws CADoesntExistsException if CA with caid does not exist
	 */
	private CAInfo getCAInfoOrThrowException(final CA ca, final boolean doSignTest) throws CADoesntExistsException {
		final CAInfo cainfo = ca.getCAInfo();
		final int status = cainfo.getStatus();
		final boolean includeInHealthCheck = cainfo.getIncludeInHealthCheck();
		int tokenstatus = CryptoToken.STATUS_OFFLINE;
		if (doSignTest && status == CAConstants.CA_ACTIVE && includeInHealthCheck) {
			// Only do a real test signature if the CA is supposed to be
			// active and if it is included in healthchecking
			// Otherwise we will only waste resources
			if (log.isDebugEnabled()) {
				log.debug("Making test signature with CAs token. CA=" + ca.getName() + ", doSignTest=" + doSignTest + ", CA status=" + status
						+ ", includeInHealthCheck=" + includeInHealthCheck);
			}
			try {
				CAToken catoken = ca.getCAToken();
	    		tokenstatus = catoken.getTokenStatus();
			} catch (IllegalCryptoTokenException e) {
				// this looks bad
				log.error("Illegal crypto token for CA "+ca.getName()+", "+ca.getCAId()+": ", e);
			}
		} else {
			if (log.isTraceEnabled()) {
				log.trace("Not making test signature with CAs token. doSignTest="+doSignTest+", CA status="+status+", includeInHealthCheck="+includeInHealthCheck);
			}
			tokenstatus = cainfo.getCATokenInfo().getTokenStatus();
		}
		// Set a possible new status in the info value object
		cainfo.getCATokenInfo().setTokenStatus(tokenstatus);
		return cainfo;
	}

	/**
     * Checks if the CA certificate has expired (or is not yet valid) and sets CA status to expired if it has (and status is not already expired).
     * Logs an info message first time that the CA certificate has expired, or every time when not yet valid.
     * 
     * Note! Does not update the CA in the database.
     * Note! No authorization checks performed in this internal method
     * 
     * @param ca the CA to check
     * @return the true if the CA just expired
     */
    private boolean checkCAExpireAndUpdateCA(final CA ca) {
        boolean expired = false;
        // Check that CA hasn't expired.
        try {
            CertTools.checkValidity(ca.getCACertificate(), new Date());
        } catch (CertificateExpiredException cee) {
            // Signers Certificate has expired, we want to make sure that the
            // status in the database is correctly EXPIRED for this CA
            // Don't set external CAs to expired though, because they should always be treated as external CAs
            if ( (ca.getStatus() != CAConstants.CA_EXPIRED) && (ca.getStatus() != CAConstants.CA_EXTERNAL) ) {
                ca.setStatus(CAConstants.CA_EXPIRED);
                String msg = intres.getLocalizedMessage("caadmin.caexpired", ca.getSubjectDN());
                msg += " " + cee.getMessage();
                log.info(msg);
                expired = true;
            }
        } catch (CertificateNotYetValidException e) {
            // Signers Certificate is not yet valid.
            String msg = intres.getLocalizedMessage("caadmin.canotyetvalid", ca.getSubjectDN());
            msg += " " + e.getMessage();
            log.warn(msg);
        }
        return expired;
    }

    /**
     * Internal method for getting CADataBean. Tries to find the CA even if the CAId is wrong due to CA certificate DN not being the same as CA DN.
     * 
     * @param caid
     *            numerical id of CA (subjectDN.hashCode()) that we search for, or -1 of a name is to ge used instead
     * @param name
     *            human readable name of CA, used instead of caid if caid == -1, can be null of caid != -1
     * @throws CADoesntExistsException
     *             if no CA was found
     */
    private CAData getCADataBean(final int caid, final String name) throws UnsupportedEncodingException, IllegalCryptoTokenException,
            CADoesntExistsException {
        CAData cadata = null;
        if (caid != -1) {
            cadata = CAData.findById(entityManager, Integer.valueOf(caid));
        } else {
            cadata = CAData.findByName(entityManager, name);
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
                    Iterator<CAData> i = CAData.findAll(entityManager).iterator();
                    while (cadata == null && i.hasNext()) {
                        final CAData tmp = i.next();
                        final Certificate caCert = tmp != null ? tmp.getCA().getCACertificate() : null;
                        if (caCert != null && caid == CertTools.getSubjectDN(caCert).hashCode()) {
                            cadata = tmp; // found. 
                            // Do also cache it if someone else is needing it later
                        	if (log.isDebugEnabled()) {
                        		log.debug("Adding a mapping from caid "+caid+" to realCaid "+cadata.getCaId());
                        	}
                            CACacheHelper.putCaCertHash(Integer.valueOf(caid), Integer.valueOf(cadata.getCaId()));
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

    private boolean authorizedToCANoLogging(final AuthenticationToken admin, final int caid) {
        final boolean ret = accessSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid);
        if (log.isDebugEnabled() && !ret) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            log.debug(msg);
        }
        return ret;
    }

    private boolean authorizedToCA(final AuthenticationToken admin, final int caid) {
    	final boolean ret = accessSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid);
        if (log.isDebugEnabled() && !ret) {
        	final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
        	log.debug(msg);
        }
        return ret;
    }

}
