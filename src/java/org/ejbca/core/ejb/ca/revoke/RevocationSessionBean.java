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

package org.ejbca.core.ejb.ca.revoke;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
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
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Used for evoking certificates in the system, manages revocation by:
 * - Setting revocation status in the database (using certificate store)
 * - Publishing revocations to publishers 
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "RevocationSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class RevocationSessionBean implements RevocationSessionLocal, RevocationSessionRemote {

    private static final Logger log = Logger.getLogger(RevocationSessionBean.class);

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private PublisherSessionLocal publisherSession;

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void revokeCertificate(final AuthenticationToken admin, final String issuerdn, final BigInteger serno, final Date revokedate, final Collection<Integer> publishers, final int reason, final String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
    	if (log.isTraceEnabled()) {
        	log.trace(">setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
    	final Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(issuerdn, serno);
    	if (cert != null) { 
    		revokeCertificate(admin, cert, publishers, revokedate, reason, userDataDN);
    	} else {
    	    final String msg = intres.getLocalizedMessage("store.errorfindcertserno", serno.toString(16));            	
    		log.info(msg);
    		throw new CertificateRevokeException(msg);
    	}
    	if (log.isTraceEnabled()) {
            log.trace("<setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void revokeCertificate(final AuthenticationToken admin, final Certificate cert, final Collection<Integer> publishers, final int reason, final String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
    	revokeCertificate(admin, cert, publishers, new Date(), reason, userDataDN);
    }
    
    private void revokeCertificate(final AuthenticationToken admin, final Certificate cert, final Collection<Integer> publishers, final Date revocationDate, final int reason, final String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
    	if (cert == null) {
    		return;
    	}
    	final boolean waschanged = certificateStoreSession.setRevokeStatus(admin, cert, revocationDate, reason, userDataDN);
    	// Publish the revocation if it was actually performed
    	if (waschanged) {
    	    // Since storeSession.findCertificateInfo uses a native query, it does not pick up changes made above
    	    // that is part if the transaction in the EntityManager, so we need to get the object from the EntityManager.
            CertificateData info = CertificateData.findByFingerprint(entityManager, CertTools.getFingerprintAsString(cert));
    	    final String cafp = info.getCaFingerprint();
    	    final String username = info.getUsername();
    	    final String password = null;
    	    final int status = info.getStatus();
    	    final int type = info.getType();
    	    final String tag = info.getTag();
    	    final long updateTime = info.getUpdateTime(); // Set the date to the same as in the database to ensure that publishing works as expected 
    	    final int certProfile = info.getCertificateProfileId();
    		// Only publish the revocation if it was actually performed
    		if ((reason == RevokedCertInfo.NOT_REVOKED) || (reason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL)) {
    			// unrevocation, -1L as revocationDate
    		    final boolean published = publisherSession.storeCertificate(admin, publishers, cert, username, password, userDataDN,
        				cafp, status, type, -1L, reason, tag, certProfile, updateTime, null);
        		if (published) {
                    final String msg = intres.getLocalizedMessage("store.republishunrevokedcert", Integer.valueOf(reason));
        			log.info(msg);
        		} else {
            		// If it is not possible, only log error but continue the operation of not revoking the certificate
        			final String msg = "Unrevoked cert:" + CertTools.getSerialNumberAsString(cert) + " reason: " + reason + " Could not be republished.";
        			final Map<String, Object> details = new LinkedHashMap<String, Object>();
                	details.put("msg", msg);
                	int caid = CertTools.getIssuerDN(cert).hashCode();
                	auditSession.log(EjbcaEventTypes.REVOKE_UNREVOKEPUBLISH, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), CertTools.getSerialNumberAsString(cert), username, details);
        		}    			
    		} else {
    			// revocation
        		publisherSession.revokeCertificate(admin, publishers, cert, username, userDataDN, cafp, type, reason, revocationDate.getTime(), tag, certProfile, updateTime);    			
    		}
    	}
    }
    
}
