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

package org.ejbca.core.ejb.ca.revoke;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.BaseCertificateData;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IncompleteIssuanceJournalDataSessionLocal;
import org.cesecore.certificates.certificate.IncompletelyIssuedCertificateInfo;
import org.cesecore.certificates.certificate.NoConflictCertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.BasePublisher;

/**
 * Used for evoking certificates in the system, manages revocation by:
 * - Setting revocation status in the database (using certificate store)
 * - Publishing revocations to publishers 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RevocationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RevocationSessionBean implements RevocationSessionLocal, RevocationSessionRemote {

    private static final Logger log = Logger.getLogger(RevocationSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CrlStoreSessionLocal crlStoreSession;
    @EJB
    private IncompleteIssuanceJournalDataSessionLocal incompleteIssuanceJournalDataSession;
    @EJB
    private NoConflictCertificateStoreSessionLocal noConflictCertificateStoreSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    @EJB
    private PublishingCrlSessionLocal publishCrlSession;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void revokeCertificate(final AuthenticationToken admin, final Certificate cert, final Collection<Integer> publishers, final int reason, final String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
        final Date revokedate = new Date();
        final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(CertTools.getFingerprintAsString(cert));
        if (cdw != null) { 
            revokeCertificate(admin, cdw, publishers, revokedate, reason, userDataDN);
        } else {
            final String msg = intres.getLocalizedMessage("store.errorfindcertserno", CertTools.getSerialNumberAsString(cert));              
            log.info(msg);
            throw new CertificateRevokeException(msg);
        }
    }
 
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    @Override
    public void revokeCertificateInNewTransaction(final AuthenticationToken admin, final CertificateDataWrapper cdw,
            final Collection<Integer> publishers, Date revocationDate, final int reason, final String userDataDN)
            throws CertificateRevokeException, AuthorizationDeniedException {
        revokeCertificate(admin, cdw, publishers, revocationDate, reason, userDataDN);
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void revokeCertificate(final AuthenticationToken admin, final CertificateDataWrapper cdw, final Collection<Integer> publishers,
            Date revocationDate, final int reason, final String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
    	final boolean waschanged = noConflictCertificateStoreSession.setRevokeStatus(admin, cdw, getRevocationDate(cdw, revocationDate, reason), reason);
    	// Only publish the revocation if it was actually performed
    	if (waschanged) {
    	    // Since storeSession.findCertificateInfo uses a native query, it does not pick up changes made above
    	    // that is part if the transaction in the EntityManager, so we need to get the object from the EntityManager.
    	    final BaseCertificateData certificateData = cdw.getBaseCertificateData();
    	    final String username = certificateData.getUsername();
    	    final String password = null;
    		if (!RevokedCertInfo.isRevoked(reason)) {
    			// unrevocation, -1L as revocationDate
    		    final boolean published = publisherSession.storeCertificate(admin, publishers, cdw, password, userDataDN, null);
        		if (published) {
        			log.info(intres.getLocalizedMessage("store.republishunrevokedcert", Integer.valueOf(reason)));
        		} else {
            		// If it is not possible, only log error but continue the operation of not revoking the certificate
                    Map<Integer, BasePublisher> all = publisherSession.getAllPublishers();
                    boolean anySafeDirect = publishers.stream().anyMatch(id -> all.get(id).getSafeDirectPublishing());
                    if (!anySafeDirect) {
                        final String serialNumber = certificateData.getSerialNumberHex();
                        final Map<String, Object> details = new LinkedHashMap<>();
                        final int caid = certificateData.getIssuerDN().hashCode();
                        final String msg = "Unrevoked cert:" + serialNumber + " reason: " + reason + " Could not be republished.";
                        details.put("msg", msg);
                        auditSession.log(EjbcaEventTypes.REVOKE_UNREVOKEPUBLISH, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNumber, username, details);
                    }
        		}    			
    		} else {
    			// revocation
                publisherSession.storeCertificate(admin, publishers, cdw, password, userDataDN, null);
    		}
            postRevokeCertificate(admin, cdw);
    	}
    }
    
    private AuthenticationToken getOrCreateAuthotizedTokenCreateCrl(final AuthenticationToken admin, String caName) {
        // ca_access permission is checked already
        if (!authorizationSession.isAuthorized(admin, StandardRules.CREATECRL.resource())) {
            log.warn("Admin: " + admin + " is not authorized to create CRL for CA: " + caName + ", creating pseudo-token.");
            return new AlwaysAllowLocalAuthenticationToken("" + admin.toString());
        }
        return admin;
    }

    /**
     * Performs post-revocation actions. Currently, it only generates a new CRL, if CRL generation on revocation is configured.
     */
    private void postRevokeCertificate(final AuthenticationToken admin, final CertificateDataWrapper cdw) throws AuthorizationDeniedException {
        final int caId = cdw.getBaseCertificateData().getIssuerDN().hashCode();
        final CAInfo caInfo = caSession.getCAInfo(admin, caId);
        // ECA-9716 caInfo == null with self signed certificates stored in DB before revoking
        // an end entity (found in EndEntityManagementSessionTest.testRevokeEndEntity)
        if (caInfo != null && caInfo.isGenerateCrlUponRevocation()) {
            log.info("Generate new CRL upon revocation for CA '" + caId + "'.");
            AuthenticationToken newAdmin = getOrCreateAuthotizedTokenCreateCrl(admin, caInfo.getName());
            try {
                publishCrlSession.forceCRL(newAdmin, caId);
                publishCrlSession.forceDeltaCRL(newAdmin, caId);
            } catch (CADoesntExistsException | CryptoTokenOfflineException | CAOfflineException e) {
                log.error("Failed to sign new CRL upon revocation: " + e.getMessage());
            } catch (AuthorizationDeniedException e) {
                // Should never happen.
                log.error("Failed to sign new CRL upon revocation because not authorized to CA: " + e.getMessage());
            }
        }
    }

    @Override
    public void revokeCertificates(AuthenticationToken admin, List<CertificateDataWrapper> cdws, Collection<Integer> publishers, final int reason)
            throws CertificateRevokeException, AuthorizationDeniedException {
        CertificateData data = null;
        boolean wasChanged = false;
        Integer caId = null;
        final Map<Integer,ArrayList<CertificateDataWrapper>> generateCrlsForCas = new HashMap<>(); 
        
        for (CertificateDataWrapper cdw : cdws) {
            data = cdw.getCertificateData();
            
            if (data.getStatus() == CertificateConstants.CERT_REVOKED && 
                data.getRevocationReason() != RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
              continue;
            }
                    
            wasChanged = noConflictCertificateStoreSession.setRevokeStatus(admin, cdw, getRevocationDate(
                    cdw, new Date(data.getRevocationDate()), reason), reason);
            
            // Only publish the revocation if it was actually performed
            if (wasChanged) {
                // Since storeSession.findCertificateInfo uses a native query, it does not pick up changes made above
                // that is part if the transaction in the EntityManager, so we need to get the object from the EntityManager.
                final BaseCertificateData certificateData = cdw.getBaseCertificateData();
                final String username = certificateData.getUsername();
                final String password = null;
                if (!RevokedCertInfo.isRevoked(reason)) {
                    // unrevocation, -1L as revocationDate
                    final boolean published = publisherSession.storeCertificate(admin, publishers, cdw, password, data.getSubjectDN(), null);
                    if (published) {
                        log.info(intres.getLocalizedMessage("store.republishunrevokedcert", Integer.valueOf(reason)));
                    } else {
                        final String serialNumber = certificateData.getSerialNumberHex();
                        // If it is not possible, only log error but continue the operation of not revoking the certificate
                        final String msg = "Unrevoked cert:" + serialNumber + " reason: " + reason + " Could not be republished.";
                        final Map<String, Object> details = new LinkedHashMap<>();
                        details.put("msg", msg);
                        final int caid = certificateData.getIssuerDN().hashCode();
                        auditSession.log(EjbcaEventTypes.REVOKE_UNREVOKEPUBLISH, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNumber, username, details);
                    }               
                } else {
                    // revocation
                    publisherSession.storeCertificate(admin, publishers, cdw, password, data.getSubjectDN(), null);
                }
                
                caId = cdw.getBaseCertificateData().getIssuerDN().hashCode();
                if (generateCrlsForCas.get(caId) == null) {
                    generateCrlsForCas.put(caId, new ArrayList<CertificateDataWrapper>());
                }
                generateCrlsForCas.get(caId).add(cdw);
            }            
        }
        
        CAInfo caInfo = null;
        for (ArrayList<CertificateDataWrapper> revokedCertificates : generateCrlsForCas.values()) {
            if (revokedCertificates.size() > 0) {
                caId = revokedCertificates.get(0).getBaseCertificateData().getIssuerDN().hashCode();
                caInfo = caSession.getCAInfo(admin, caId);
                // ECA-9716 caInfo == null with self signed certificates stored in DB before revoking 
                // an end entity (found in EndEntityManagementSessionTest.testRevokeEndEntity) 
                if (caInfo != null && caInfo.isGenerateCrlUponRevocation()) {
                    log.info("Generate new CRL upon revocation for CA '" + caId + "'.");
                    try {
                        publishCrlSession.forceCRL(admin, caId);
                        publishCrlSession.forceDeltaCRL(admin, caId);
                    } catch (CADoesntExistsException | CryptoTokenOfflineException | CAOfflineException e) {
                        log.error("Failed to sign new CRL upon revocation: " + e.getMessage());
                    } catch (AuthorizationDeniedException e) {
                        // Should never happen.
                        log.error("Failed to sign new CRL upon revocation because not authorized to CA: " + e.getMessage());
                    }
                }
            }
        }
    }

    @Override
    public int revokeIncompletelyIssuedCertsBatched(final AuthenticationToken admin, final long maxIssuanceTimeMillis) throws AuthorizationDeniedException {
        // Fetch a list of up to 100 "half-issued" certificates
        final List<IncompletelyIssuedCertificateInfo> incompleteIssuedCerts = incompleteIssuanceJournalDataSession.getIncompleteIssuedCertsBatch(maxIssuanceTimeMillis);
        final Date now = new Date();
        final RevocationReasons revocationReason = RevocationReasons.UNSPECIFIED;
        for (final IncompletelyIssuedCertificateInfo incompleteIssuedCert : incompleteIssuedCerts) {
            final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(incompleteIssuedCert.getCertificateProfileId());
            final List<Integer> publishers = certProfile.getPublisherList();
            try {
                // Add certificate in revoked state
                final Certificate cert = CertTools.getCertfromByteArray(incompleteIssuedCert.getCertBytes(), BouncyCastleProvider.PROVIDER_NAME, Certificate.class);
                final CertificateDataWrapper cdw = certificateStoreSession.storeCertificateRevokedNoAuth(admin, cert, incompleteIssuedCert.getUsername(),
                        incompleteIssuedCert.getCaFingerprint(), null, CertificateConstants.CERT_REVOKED, certProfile.getType(), incompleteIssuedCert.getCertificateProfileId(),
                        incompleteIssuedCert.getEndEntityProfileId(), incompleteIssuedCert.getCrlPartitionIndex(), CertificateConstants.CERT_TAG_PRECERT, now.getTime(),
                        incompleteIssuedCert.getAccountBindingId(), revocationReason, now);
                // Publish revocation information
                final BaseCertificateData certificateData = cdw.getBaseCertificateData();
                final String password = null;
                publisherSession.storeCertificate(admin, publishers, cdw, password, certificateData.getSubjectDN(), null);
                postRevokeCertificate(admin, cdw);
                // The certificate is now in a meaningful state, so it can be removed from IncompleteIssuanceJournalData
                incompleteIssuanceJournalDataSession.removeFromJournal(incompleteIssuedCert.getCaId(), incompleteIssuedCert.getSerialNumber());
            } catch (CertificateParsingException e) {
                log.error("Failed to revoke incompletely issued certificate, with CA ID " + incompleteIssuedCert.getCaId() + " and serial " + incompleteIssuedCert.getSerialNumber().toString(16));
            }
        }
        return incompleteIssuedCerts.size();
    }

    /** @return revocationDate as is, or null if unrevoking a certificate that's not on a base CRL in on hold state. */
    private Date getRevocationDate(final CertificateDataWrapper cdw, final Date revocationDate, final int reason) {
        if (revocationDate == null || (reason != RevokedCertInfo.NOT_REVOKED && reason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL) ||
                (cdw.getBaseCertificateData().getRevocationReason() != RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD)) {
            return revocationDate; // return unmodified
        }
        
        final String issuerDN = cdw.getBaseCertificateData().getIssuerDN();
        final CRLInfo baseCrlInfo = crlStoreSession.getLastCRLInfo(issuerDN, cdw.getBaseCertificateData().getCrlPartitionIndex(), false);
        if (baseCrlInfo == null || baseCrlInfo.getCreateDate().before(revocationDate)) { // if not on base CRL
            return null;
        } else {
            return revocationDate;
        }
    }
    
}
