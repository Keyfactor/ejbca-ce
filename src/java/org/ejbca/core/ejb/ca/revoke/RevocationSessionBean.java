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

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.RevokedCertInfo;
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

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RevocationSessionBean.class);

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
    public void revokeCertificate(AuthenticationToken admin, String issuerdn, BigInteger serno, Date revokedate, Collection<Integer> publishers, int reason, String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
    	if (log.isTraceEnabled()) {
        	log.trace(">setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
    	Certificate cert = certificateStoreSession.findCertificateByIssuerAndSerno(issuerdn, serno);
    	if (cert != null) { 
    		revokeCertificate(admin, cert, publishers, revokedate, reason, userDataDN);
    	} else {
    		String msg = intres.getLocalizedMessage("store.errorfindcertserno", serno.toString(16));            	
    		log.info(msg);
    		throw new CertificateRevokeException(msg);
    	}
    	if (log.isTraceEnabled()) {
            log.trace("<setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void revokeCertificate(AuthenticationToken admin, Certificate cert, Collection<Integer> publishers, int reason, String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
    	revokeCertificate(admin, cert, publishers, new Date(), reason, userDataDN);
    }
    
    private void revokeCertificate(AuthenticationToken admin, Certificate cert, Collection<Integer> publishers, Date revocationDate, int reason, String userDataDN) throws CertificateRevokeException, AuthorizationDeniedException {
    	if (cert == null) {
    		return;
    	}
    	boolean waschanged = certificateStoreSession.setRevokeStatus(admin, cert, revocationDate, reason, userDataDN);
    	// Publish the revocation if it was actually performed
    	if (waschanged) {
        	CertificateInfo info = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(cert));
        	String cafp = info.getCAFingerprint();
        	String username = info.getUsername();
        	String password = null;
        	int status = info.getStatus();
        	int type = info.getType();
        	String tag = info.getTag();
        	long now = System.currentTimeMillis();
        	int certProfile = info.getCertificateProfileId();
    		// Only publish the revocation if it was actually performed
    		if ((reason == RevokedCertInfo.NOT_REVOKED) || (reason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL)) {
    			// unrevocation, -1L as revocationDate
        		boolean published = publisherSession.storeCertificate(admin, publishers, cert, username, password, userDataDN,
        				cafp, status, type, -1L, reason, tag, certProfile, now, null);
        		if (published) {
        			final String msg = intres.getLocalizedMessage("store.republishunrevokedcert", Integer.valueOf(reason));
        			log.info(msg);
        		} else {
            		// If it is not possible, only log error but continue the operation of not revoking the certificate
        			final String msg = "Unrevoked cert:" + CertTools.getSerialNumberAsString(cert) + " reason: " + reason + " Could not be republished.";
                	Map<String, Object> details = new LinkedHashMap<String, Object>();
                	details.put("msg", msg);
                	int caid = CertTools.getIssuerDN(cert).hashCode();
                	auditSession.log(EjbcaEventTypes.REVOKE_UNREVOKEPUBLISH, EventStatus.FAILURE, ModuleTypes.CA, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), CertTools.getSerialNumberAsString(cert), username, details);
        		}    			
    		} else {
    			// revocation
        		publisherSession.revokeCertificate(admin, publishers, cert, username, userDataDN, cafp, type, reason, revocationDate.getTime(), tag, certProfile, now);    			
    		}
    	}
    }
    
}
