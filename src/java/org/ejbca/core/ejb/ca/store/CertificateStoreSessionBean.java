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

package org.ejbca.core.ejb.ca.store;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.ejb.CreateException;
import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthenticationFailedException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.cvc.PublicKeyEC;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.StringTools;
import org.ejbca.util.keystore.KeyTools;

/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateStoreSessionBean extends CertificateDataUtil implements CertificateStoreSessionRemote, CertificateStoreSessionLocal {

    private final static Logger log = Logger.getLogger(CertificateStoreSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private LogSessionLocal logSession;
    @EJB
    private PublisherSessionLocal publisherSession;
    
    public CertificateStoreSessionBean() {
        super();
    }
    
    @Override
    public String getDatabaseStatus() {
		String returnval = "";
		try {
			entityManager.createNativeQuery(EjbcaConfiguration.getHealthCheckDbQuery()).getResultList();
			// TODO: Do we need to flush() the connection to avoid that this is executed in a batch after the method returns?
		} catch (Exception e) {
			returnval = "\nDB: Error creating connection to database: " + e.getMessage();
			log.error("Error creating connection to database.",e);
		}
		return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp,
                                    int status, int type, int certificateProfileId, String tag, long updateTime) throws CreateException {
    	if (log.isTraceEnabled()) {
            log.trace(">storeCertificate(" + username + ", " + cafp + ", " + status + ", " + type + ")");
    	}
        // Strip dangerous chars
        username = StringTools.strip(username);

        // We need special handling here of CVC certificate with EC keys, because they lack EC parameters in all certs except the Root certificate (CVCA)
    	PublicKey pubk = incert.getPublicKey();
    	if ((pubk instanceof PublicKeyEC)) {
    		PublicKeyEC pkec = (PublicKeyEC) pubk;
    		// The public key of IS and DV certificate (CVC) do not have any parameters so we have to do some magic to get a complete EC public key
    		ECParameterSpec spec = pkec.getParams();
    		if (spec == null) {
    			// We need to enrich this public key with parameters
    			try {
    				if (cafp != null) {
    					String cafingerp = cafp;
    					CertificateData cacert = CertificateData.findByFingerprint(entityManager, cafp);
    					if (cacert == null) {
    						throw new FinderException();
    					}
    					String nextcafp = cacert.getCaFingerprint();
    					int bar = 0; // never go more than 5 rounds, who knows what strange things can exist in the CAFingerprint column, make sure we never get stuck here
    					while ((!StringUtils.equals(cafingerp, nextcafp)) && (bar++ < 5)) {
        					cacert = CertificateData.findByFingerprint(entityManager, cafp);
        					if (cacert == null) {
        						throw new FinderException();
        					}
    						cafingerp = nextcafp;
    						nextcafp = cacert.getCaFingerprint();
    					}
						// We found a root CA certificate, hopefully ?
						PublicKey pkwithparams = cacert.getCertificate().getPublicKey();
						pubk = KeyTools.getECPublicKeyWithParams(pubk, pkwithparams);
    				}
				} catch (FinderException e) {
					log.info("Can not find CA certificate with fingerprint: "+cafp);
				} catch (Exception e) {
					// This catches NoSuchAlgorithmException, NoSuchProviderException and InvalidKeySpecException and possibly something else (NPE?)
					// because we want to continue anyway
					if (log.isDebugEnabled()) {
						log.debug("Can not enrich EC public key with missing parameters: ", e);
					}
				}
    		}
    	} // finished with ECC key special handling
    	
    	// Create the certificate in one go with all parameters at once. This used to be important in EJB2.1 so the persistence layer only creates *one* single
    	// insert statement. If we do a home.create and the some setXX, it will create one insert and one update statement to the database.
    	// Probably not important in EJB3 anymore
    	final CertificateData data1 = new CertificateData(incert, pubk, username, cafp, status, type, certificateProfileId, tag, updateTime);
    	final String issuerDN = data1.getIssuerDN();
        try {
        	entityManager.persist(data1);
        } catch (Exception e) {
        	// For backward compatibility. We should drop the throw entirely and rely on the return value.
        	CreateException ce = new CreateException();
        	ce.setStackTrace(e.getStackTrace());
        	throw ce;
        }
        final String msg = intres.getLocalizedMessage("store.storecert");            	
        logSession.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new Date(), username, incert, LogConstants.EVENT_INFO_STORECERTIFICATE, msg);
        log.trace("<storeCertificate()");
        return true;
    }

    @Override
    public Collection<String> listAllCertificates(Admin admin, String issuerdn) {
    	log.trace(">listAllCertificates()");
    	// This method was only used from CertificateDataTest and it didn't care about the expireDate, so it will only select fingerprints now.
    	return CertificateData.findFingerprintsByIssuerDN(entityManager, CertTools.stringToBCDNString(StringTools.strip(issuerdn)));
    }

    @Override
    public Collection<RevokedCertInfo> listRevokedCertInfo(Admin admin, String issuerdn, long lastbasecrldate) {
    	log.trace(">listRevokedCertInfo()");
    	return CertificateData.getRevokedCertInfos(entityManager, CertTools.stringToBCDNString(StringTools.strip(issuerdn)), lastbasecrldate);
    }

    @Override
    public Collection<Certificate> findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuerDN) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
    	}
        // First make a DN in our well-known format
        String dn = StringTools.strip(subjectDN);
        dn = CertTools.stringToBCDNString(dn);
        String issuerdn = StringTools.strip(issuerDN);
        issuerdn = CertTools.stringToBCDNString(issuerdn);
        log.debug("Looking for cert with (transformed)DN: " + dn);
        Collection<Certificate> ret = new ArrayList<Certificate>();
        Collection<CertificateData> coll = CertificateData.findBySubjectDNAndIssuerDN(entityManager, dn, issuerdn);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
        	log.trace("<findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
        }
        return ret;
    }

    @Override
    public Set<String> findUsernamesByIssuerDNAndSubjectDN(Admin admin, String issuerDN, String subjectDN) {
        if (log.isTraceEnabled()) {
            log.trace(">findUsernamesByIssuerDNAndSubjectDN(), issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        final String transformedIssuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final String transformedSubjectDN = CertTools.stringToBCDNString(StringTools.strip(subjectDN));
        if ( log.isDebugEnabled() ) {
            log.debug("Looking for user with a certificate with issuer DN(transformed) '" + transformedIssuerDN + "' and subject DN(transformed) '"+transformedSubjectDN+"'.");
        }
        try {
            return CertificateData.findUsernamesBySubjectDNAndIssuerDN(entityManager, transformedSubjectDN, transformedIssuerDN);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<findUsernamesByIssuerDNAndSubjectDN(), issuer='" + issuerDN + "'");
            }
        }
    }

    @Override
    public Set<String> findUsernamesByIssuerDNAndSubjectKeyId(Admin admin, String issuerDN, byte subjectKeyId[]) {
        if (log.isTraceEnabled()) {
            log.trace(">findUsernamesByIssuerDNAndSubjectKeyId(), issuer='" + issuerDN + "'");
        }
        // First make a DN in our well-known format
        final String transformedIssuerDN = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        final String sSubjectKeyId = new String(Base64.encode(subjectKeyId, false));
        if ( log.isDebugEnabled() ) {
            log.debug("Looking for user with a certificate with issuer DN(transformed) '" + transformedIssuerDN + "' and SubjectKeyId '"+sSubjectKeyId+"'.");
        }
        try {
        	return CertificateData.findUsernamesByIssuerDNAndSubjectKeyId(entityManager, transformedIssuerDN, sSubjectKeyId);
        } finally {
            if (log.isTraceEnabled()) {
                log.trace("<findUsernamesByIssuerDNAndSubjectKeyId(), issuer='" + issuerDN + "'");
            }
        }
    }

    @Override
    public Collection<Certificate> findCertificatesBySubject(Admin admin, String subjectDN) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesBySubject(), dn='" + subjectDN + "'");
    	}
        // First make a DN in our well-known format
        String dn = StringTools.strip(subjectDN);
        dn = CertTools.stringToBCDNString(dn);
        log.debug("Looking for cert with (transformed)DN: " + dn);
        Collection<Certificate> ret = new ArrayList<Certificate>();
        Collection<CertificateData> coll = CertificateData.findBySubjectDN(entityManager, dn);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
        	log.trace("<findCertificatesBySubject(), dn='" + subjectDN + "'");
        }
        return ret;
    }

    @Override
    public Collection<Certificate> findCertificatesByExpireTimeWithLimit(Admin admin, Date expireTime) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByExpireTimeWithLimit(), time=" + expireTime);
    	}
        // First make expiretime in well know format
        log.debug("Looking for certs that expire before: " + expireTime);
        Collection<CertificateData> coll = CertificateData.findByExpireDateWithLimit(entityManager, expireTime.getTime());
        Collection<Certificate> ret = new ArrayList<Certificate>();
        if (log.isDebugEnabled()) {
        	log.debug("Found "+coll.size()+" certificates that expire before "+expireTime);            		
        }
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
        if (log.isTraceEnabled()) {
        	log.trace("<findCertificatesByExpireTimeWithLimit(), time=" + expireTime);
        }
        return ret;
    }

    @Override
    public Collection<String>  findUsernamesByExpireTimeWithLimit(Admin admin, Date expiretime) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByExpireTimeWithLimit: "+expiretime);    		
    	}
    	return CertificateData.findUsernamesByExpireTimeWithLimit(entityManager, new Date().getTime(), expiretime.getTime());
    }

    @Override
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) {
    	return findCertificateByIssuerAndSerno(admin, issuerDN, serno, entityManager);
    }

    @Override
    public CertificateInfo findFirstCertificateInfo(final String issuerDN, final BigInteger serno) {
    	return CertificateData.findFirstCertificateInfo(entityManager, CertTools.stringToBCDNString(issuerDN), serno.toString());
    }

    @Override
    public Collection<Certificate> findCertificatesByIssuerAndSernos(Admin admin, String issuerDN, Collection<BigInteger> sernos) {
    	log.trace(">findCertificatesByIssuerAndSernos()");
        List<Certificate> ret = null;
        if (null == admin) {
            throw new IllegalArgumentException();	// TODO: Either check authorization properly or skip the Admin parameter.. this is just wrong..
        }
        if (null == issuerDN || issuerDN.length() <= 0 || null == sernos || sernos.isEmpty()) {
            ret = new ArrayList<Certificate>();
        } else {
            String dn = CertTools.stringToBCDNString(issuerDN);
            if (log.isDebugEnabled()) {
                log.debug("Looking for cert with (transformed)DN: " + dn);
            }
            ret = CertificateData.findCertificatesByIssuerDnAndSerialNumbers(entityManager, dn, sernos);
        }
        log.trace("<findCertificatesByIssuerAndSernos()");
        return ret;
    }

    @Override
    public Collection<Certificate> findCertificatesBySerno(Admin admin, BigInteger serno) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesBySerno(),  serno=" + serno);
    	}
    	ArrayList<Certificate> ret = new ArrayList<Certificate>();
    	Collection<CertificateData> coll = CertificateData.findBySerialNumber(entityManager, serno.toString());
    	Iterator<CertificateData> iter = coll.iterator();
    	while (iter.hasNext()) {
    		ret.add(iter.next().getCertificate());
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<findCertificatesBySerno(), serno=" + serno);
    	}
    	return ret;
    }

    @Override
    public String findUsernameByCertSerno(final Admin admin, final BigInteger serno, final String issuerdn) {
    	if (log.isTraceEnabled()) {
    		log.trace(">findUsernameByCertSerno(), serno: " + serno.toString(16) + ", issuerdn: " + issuerdn);    		
    	}
    	final String ret = CertificateData.findLastUsernameByIssuerDNSerialNumber(entityManager, CertTools.stringToBCDNString(issuerdn), serno.toString());
        if (log.isTraceEnabled()) {
        	log.trace("<findUsernameByCertSerno(), ret=" + ret);
        }
        return ret;
    }

    @Override
    public Collection<Certificate> findCertificatesByUsername(Admin admin, String username) {
    	return findCertificatesByUsername(admin, username, entityManager);
    }

    @Override
    public Collection<Certificate> findCertificatesByUsernameAndStatus(Admin admin, String username, int status) {
    	if (log.isTraceEnabled()) {
        	log.trace(">findCertificatesByUsernameAndStatus(),  username=" + username);
    	}
        ArrayList<Certificate> ret = new ArrayList<Certificate>();
        // Strip dangerous chars
        username = StringTools.strip(username);
        // This method on the entity bean does the ordering in the database
        Collection<CertificateData> coll = CertificateData.findByUsernameAndStatus(entityManager, username, status);
        Iterator<CertificateData> iter = coll.iterator();
        while (iter.hasNext()) {
        	ret.add(iter.next().getCertificate());
        }
    	if (log.isTraceEnabled()) {
            log.trace("<findCertificatesByUsernameAndStatus(), username=" + username);
    	}
        return ret;
    }

    @Override
    public CertificateInfo getCertificateInfo(Admin admin, String fingerprint) {
    	// TODO: Either enforce authorization check or drop the Admin parameter
    	if (log.isTraceEnabled()) {
    		log.trace(">getCertificateInfo(): "+fingerprint);
    	}
    	return CertificateData.getCertificateInfo(entityManager, fingerprint);
    }

    @Override
    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint) {
        return findCertificateByFingerprint(admin, fingerprint, entityManager);
    }

    @Override
    public Collection<Certificate> findCertificatesByType(Admin admin, int type, String issuerDN) throws IllegalArgumentException {
        return findCertificatesByType(admin, type, issuerDN, entityManager);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void setArchivedStatus(Admin admin, String fingerprint) throws AuthorizationDeniedException {
    	if (admin.getAdminType() != Admin.TYPE_INTERNALUSER) {
    		throw new AuthorizationDeniedException("Unauthorized");
    	}
    	CertificateData rev = CertificateData.findByFingerprint(entityManager, fingerprint);
    	if (rev != null) {
    		rev.setStatus(SecConst.CERT_ARCHIVED);
    		if (log.isDebugEnabled()) {
    			log.debug("Set status ARCHIVED for certificate with fp: "+fingerprint+", revocation reason is: "+rev.getRevocationReason());
    		}
    	} else {
    		String msg = intres.getLocalizedMessage("store.errorcertinfo", fingerprint);            	
    		logSession.log(admin, 0, LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_UNKNOWN, msg);
    		throw new EJBException(msg);
    	}
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Collection<Integer> publishers, int reason, String userDataDN) {
    	setRevokeStatus(admin, issuerdn, serno, new Date(), publishers, reason, userDataDN);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Date revokedate, Collection<Integer> publishers, int reason, String userDataDN) {
    	if (log.isTraceEnabled()) {
        	log.trace(">setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
        try {
        	Certificate certificate = findCertificateByIssuerAndSerno(admin, issuerdn, serno);
	        setRevokeStatus(admin, certificate, revokedate, publishers, reason, userDataDN);
        } catch (FinderException e) {
        	String msg = intres.getLocalizedMessage("store.errorfindcertserno", serno.toString(16));            	
            logSession.log(admin, issuerdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_REVOKEDCERT, msg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
            log.trace("<setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno.toString(16)+", reason="+reason);
    	}
    }

    /**
     * Helper method to set the status of certificate to revoked or active. Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     *
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     * 
     * @param admin      Administrator performing the operation
     * @param certificate the certificate to revoke or activate.
     * @param publishers and array of publiserids (Integer) of publishers to revoke/re-publish the certificate in.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     * @throws FinderException 
     */
    private void setRevokeStatus(Admin admin, Certificate certificate, Date revokedate, Collection<Integer> publishers, int reason, String userDataDN) throws FinderException {
    	if (certificate == null) {
    		return;
    	}
    	if (log.isTraceEnabled()) {
        	log.trace(">private setRevokeStatus(Certificate),  issuerdn=" + CertTools.getIssuerDN(certificate) + ", serno=" + CertTools.getSerialNumberAsString(certificate));
    	}
    	CertificateData rev = CertificateData.findByFingerprint(entityManager, CertTools.getFingerprintAsString(certificate));
    	if (rev == null) {
    		throw new FinderException("No certificate with fingerprint " + CertTools.getFingerprintAsString(certificate));
    	}
    	String username = rev.getUsername();
    	String cafp = rev.getCaFingerprint();
    	int type = rev.getType();
    	Date now = new Date();
    	final int caid = rev.getIssuerDN().hashCode();
    	
    	// A normal revocation
    	if ( (rev.getStatus() != SecConst.CERT_REVOKED) 
    			&& (reason != RevokedCertInfo.NOT_REVOKED) && (reason != RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL) ) {
    		rev.setStatus(SecConst.CERT_REVOKED);
    		rev.setRevocationDate(revokedate);
    		rev.setUpdateTime(now.getTime());
    		rev.setRevocationReason(reason);            	  
    		String msg = intres.getLocalizedMessage("store.revokedcert", Integer.valueOf(reason));            	
    		logSession.log(admin, caid, LogConstants.MODULE_CA, new Date(), null, certificate, LogConstants.EVENT_INFO_REVOKEDCERT, msg);
    		// Revoke in all related publishers
    		publisherSession.revokeCertificate(admin, publishers, certificate, username, userDataDN, cafp, type, reason, revokedate.getTime(), rev.getTag(), rev.getCertificateProfileId(), now.getTime());
            // Unrevoke, can only be done when the certificate was previously revoked with reason CertificateHold
    	} else if ( ((reason == RevokedCertInfo.NOT_REVOKED) || (reason == RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL)) 
    			&& (rev.getRevocationReason() == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) ) {
    		// Only allow unrevocation if the certificate is revoked and the revocation reason is CERTIFICATE_HOLD
    		int status = SecConst.CERT_ACTIVE;
    		rev.setStatus(status);
    		long revocationDate = -1L; // A null Date to setRevocationDate will result in -1 stored in long column
    		rev.setRevocationDate(null);
    		rev.setUpdateTime(now.getTime());
    		int revocationReason = RevokedCertInfo.NOT_REVOKED;
    		rev.setRevocationReason(revocationReason);
    		// Republish the certificate if possible
    		// Republishing will not restore a password, for example in AD, it will only re-activate the certificate.
    		String password = null;
    		boolean published = publisherSession.storeCertificate(admin, publishers, certificate, username, password, userDataDN,
    				cafp, status, type, revocationDate, revocationReason, rev.getTag(), rev.getCertificateProfileId(), now.getTime(), null);
    		if (published) {
    			final String msg = intres.getLocalizedMessage("store.republishunrevokedcert", Integer.valueOf(reason));            	
    			logSession.log(admin, caid, LogConstants.MODULE_CA, new Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, msg);
    		} else {
        		// If it is not possible, only log error but continue the operation of not revoking the certificate
    			final String msg = "Unrevoked cert:" + CertTools.getSerialNumberAsString(certificate) + " reason: " + reason + " Could not be republished.";
    			logSession.log(admin, caid, LogConstants.MODULE_CA, new Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, msg);
    		}
    	} else {
    		String msg = intres.getLocalizedMessage("store.ignorerevoke", CertTools.getSerialNumberAsString(certificate), Integer.valueOf(rev.getStatus()), Integer.valueOf(reason));            	
    		logSession.log(admin, caid, LogConstants.MODULE_CA, new Date(), null, certificate, LogConstants.EVENT_INFO_NOTIFICATION, msg);
    	}
    	if (log.isTraceEnabled()) {
        	log.trace("<private setRevokeStatus(),  issuerdn=" + CertTools.getIssuerDN(certificate) + ", serno=" + CertTools.getSerialNumberAsString(certificate));
    	}
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void revokeCertificate(Admin admin, Certificate cert, Collection<Integer> publishers, int reason, String userDataDN) {
        if (cert instanceof X509Certificate) {
            setRevokeStatus(admin, CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert), publishers, reason, userDataDN);
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    // TODO: Does not publish revocations to publishers!!!
	// TODO: Enforce or drop Admin parameter
    public void revokeAllCertByCA(Admin admin, String issuerdn, int reason) {
        int temprevoked = 0;
        int revoked = 0;
        String bcdn = CertTools.stringToBCDNString(issuerdn);
        try {
            // Change all temporaty revoked certificates to permanently revoked certificates
        	temprevoked = CertificateData.revokeOnHoldPermanently(entityManager, bcdn);
            // Revoking all non revoked certificates.
        	revoked = CertificateData.revokeAllNonRevokedCertificates(entityManager, bcdn, reason);
    		String msg = intres.getLocalizedMessage("store.revokedallbyca", issuerdn, Integer.valueOf(revoked + temprevoked), Integer.valueOf(reason));            	
            logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_REVOKEDCERT, msg);
        } catch (Exception e) {
    		String msg = intres.getLocalizedMessage("store.errorrevokeallbyca", issuerdn);            	
            logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_REVOKEDCERT, msg, e);
            throw new EJBException(e);
        }
    }

    @Override
    public boolean checkIfAllRevoked(Admin admin, String username) {
        boolean returnval = true;
        Certificate certificate = null;
        // Strip dangerous chars
        username = StringTools.strip(username);
        Collection<Certificate> certs = findCertificatesByUsername(admin, username);
        // Revoke all certs
        if (!certs.isEmpty()) {
        	Iterator<Certificate> j = certs.iterator();
        	while (j.hasNext()) {
        		certificate = j.next();
        		String fingerprint = CertTools.getFingerprintAsString(certificate);
        		CertificateInfo info = getCertificateInfo(admin, fingerprint);
        		if (info != null && info.getStatus() != SecConst.CERT_REVOKED) {
        			returnval = false;
        			break;
        		}
        	}
        }
        return returnval;
    }

    @Override
    public boolean isRevoked(String issuerDN, BigInteger serno) {
        if (log.isTraceEnabled()) {
        	log.trace(">isRevoked(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        boolean ret = false;
        try {
        	Collection<CertificateData> coll = CertificateData.findByIssuerDNSerialNumber(entityManager, dn, serno.toString());
            if (coll.size() > 0) {
                if (coll.size() > 1) {
                    String msg = intres.getLocalizedMessage("store.errorseveralissuerserno", issuerDN, serno.toString(16));             
                    //adapter.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_DATABASE, msg);
                    log.error(msg);
                }
                Iterator<CertificateData> iter = coll.iterator();
                while (iter.hasNext()) {
                    CertificateData data = iter.next();
                    // if any of the certificates with this serno is revoked, return true
                    if (data.getStatus() == SecConst.CERT_REVOKED) {
                    	ret = true;
                    	break;
                    }
                }
            } else {
                // If there are no certificates with this serial number, return true (=revoked). Better safe than sorry!
            	ret = true;
            	if (log.isTraceEnabled()) {
            		log.trace("isRevoked() did not find certificate with dn "+dn+" and serno "+serno.toString(16));
            	}
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<isRevoked() returned " + ret);
        }
        return ret;
    }

    @Override
    public CertificateStatus getStatus(String issuerDN, BigInteger serno) {
        return getStatus(issuerDN, serno, entityManager);
    }

    @Override
    public void authenticate(X509Certificate certificate, boolean requireAdminCertificateInDatabase) throws AuthenticationFailedException {
        // Check Validity
        try {
            certificate.checkValidity();
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("authentication.certexpired", CertTools.getNotAfter(certificate).toString());            	
            throw new AuthenticationFailedException(msg);
        }
        if (requireAdminCertificateInDatabase) {
            // TODO: Verify Signature on cert? Not really needed since it's one of ou certs in the database.
            // Check if certificate is revoked.
            boolean isRevoked = isRevoked(CertTools.getIssuerDN(certificate),CertTools.getSerialNumber(certificate));
            if (isRevoked) {
                // Certificate revoked or missing in the database
            	String msg = intres.getLocalizedMessage("authentication.revokedormissing");            	
                throw new AuthenticationFailedException(msg);
            }
        } else {
        	// TODO: We should check the certificate for CRL or OCSP tags and verify the certificate status
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addCertReqHistoryData(Admin admin, Certificate cert, UserDataVO useradmindata){
    	final String issuerDN = CertTools.getIssuerDN(cert);
    	final String username = useradmindata.getUsername();
    	if (log.isTraceEnabled()) {
        	log.trace(">addCertReqHistoryData(" + CertTools.getSerialNumberAsString(cert) + ", " + issuerDN + ", " + username + ")");
    	}
        try {
        	entityManager.persist(new CertReqHistoryData(cert, issuerDN, useradmindata));
        	final String msg = intres.getLocalizedMessage("store.storehistory", username);            	
            logSession.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new Date(), username, cert, LogConstants.EVENT_INFO_STORECERTIFICATE, msg);            
        } catch (Exception e) {
        	final String msg = intres.getLocalizedMessage("store.errorstorehistory", useradmindata.getUsername());            	
            logSession.log(admin, issuerDN.hashCode(), LogConstants.MODULE_CA, new Date(), username, cert, LogConstants.EVENT_ERROR_STORECERTIFICATE, msg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<addCertReqHistoryData()");
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeCertReqHistoryData(Admin admin, String certFingerprint){
    	if (log.isTraceEnabled()) {
        	log.trace(">removeCertReqHistData(" + certFingerprint + ")");
    	}
        try {          
        	String msg = intres.getLocalizedMessage("store.removehistory", certFingerprint);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_INFO_STORECERTIFICATE, msg);
            CertReqHistoryData crh = CertReqHistoryData.findById(entityManager, certFingerprint);
            if (crh == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to remove CertReqHistory that does not exist: "+certFingerprint);                		
            	}
            } else {
            	entityManager.remove(crh);
            }
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorremovehistory", certFingerprint);            	
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_STORECERTIFICATE, msg);
            throw new EJBException(e);
        }
        log.trace("<removeCertReqHistData()");       	
    }
    
    // getCertReqHistory() might perform database updates, so we always need to run this in a transaction
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public CertReqHistory getCertReqHistory(Admin admin, BigInteger certificateSN, String issuerDN){
    	CertReqHistory retval = null;
    	Collection<CertReqHistoryData> result = CertReqHistoryData.findByIssuerDNSerialNumber(entityManager, issuerDN, certificateSN.toString());
    	if(result.iterator().hasNext()) {
    		retval = result.iterator().next().getCertReqHistory();
    	}
    	return retval;
    }

    // getCertReqHistory() might perform database updates, so we always need to run this in a transaction
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public List<CertReqHistory> getCertReqHistory(Admin admin, String username){
    	ArrayList<CertReqHistory> retval = new ArrayList<CertReqHistory>();
    	Collection<CertReqHistoryData> result = CertReqHistoryData.findByUsername(entityManager, username);
    	Iterator<CertReqHistoryData> iter = result.iterator();
    	while(iter.hasNext()) {
    		retval.add(iter.next().getCertReqHistory());
    	}
    	return retval;
    }
    
    @Override
    public List<Object[]> findExpirationInfo(String cASelectString, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin) {
    	return CertificateData.findExpirationInfo(entityManager, cASelectString, activeNotifiedExpireDateMin, activeNotifiedExpireDateMax, activeExpireDateMin);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean setStatus(String fingerprint, int status) {
    	return CertificateData.updateStatus(entityManager, fingerprint, status);
    }
}
