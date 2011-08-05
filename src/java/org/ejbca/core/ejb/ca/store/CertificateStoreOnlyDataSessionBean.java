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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.ejb.CreateException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.authorization.AuthenticationFailedException;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateStoreOnlyDataSessionBean extends CertificateDataUtil implements CertificateStoreSessionLocal, CertificateStoreSessionRemote {
    
    private static final Logger log = Logger.getLogger(CertificateStoreOnlyDataSessionBean.class);
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    public CertificateStoreOnlyDataSessionBean() {
        super();
        CryptoProviderTools.installBCProvider();
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

	@Override
    public CertificateStatus getStatus(String issuerDN, BigInteger serno) {
        return getStatus(issuerDN, serno, entityManager);
    }

	@Override
    public Certificate findCertificateByIssuerAndSerno(AuthenticationToken admin, String issuerDN, BigInteger serno) {
    	return findCertificateByIssuerAndSerno(admin, issuerDN, serno, entityManager);
    }

	@Override
    public Collection<Certificate> findCertificatesByType(AuthenticationToken admin, int type, String issuerDN) {
        return findCertificatesByType(admin, type, issuerDN, entityManager);
    }

	@Override
    public Collection<Certificate> findCertificatesByUsername(AuthenticationToken admin, String username) {
    	return findCertificatesByUsername(admin, username, entityManager);
    }

	/* *******************************************************************
	 * The following methods are not implemented in stand alone VA mode! *
	 *********************************************************************/
	
	@Override
	public void addCertReqHistoryData(AuthenticationToken admin, Certificate cert, UserDataVO useradmindata) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void authenticate(X509Certificate certificate, boolean requireAdminCertificateInDatabase) throws AuthenticationFailedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean checkIfAllRevoked(AuthenticationToken admin, String username) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Certificate findCertificateByFingerprint(AuthenticationToken admin, String fingerprint) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesByExpireTimeWithLimit(AuthenticationToken admin, Date expireTime) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesByIssuerAndSernos(AuthenticationToken admin, String issuerDN, Collection<BigInteger> sernos) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesBySerno(AuthenticationToken admin, BigInteger serno) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesBySubject(AuthenticationToken admin, String subjectDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesBySubjectAndIssuer(AuthenticationToken admin, String subjectDN, String issuerDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesByUsernameAndStatus(AuthenticationToken admin, String username, int status) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public List<Object[]> findExpirationInfo(String cASelectString, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public String findUsernameByCertSerno(AuthenticationToken admin, BigInteger serno, String issuerdn) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<String> findUsernamesByExpireTimeWithLimit(AuthenticationToken admin, Date expiretime) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Set<String> findUsernamesByIssuerDNAndSubjectDN(AuthenticationToken admin, String issuerDN, String subjectDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Set<String> findUsernamesByIssuerDNAndSubjectKeyId(AuthenticationToken admin, String issuerDN, byte[] subjectKeyId) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public CertReqHistory getCertReqHistory(AuthenticationToken admin, BigInteger certificateSN, String issuerDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public List<CertReqHistory> getCertReqHistory(AuthenticationToken admin, String username) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public CertificateInfo getCertificateInfo(AuthenticationToken admin, String fingerprint) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean isRevoked(String issuerDN, BigInteger serno) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<String> listAllCertificates(AuthenticationToken admin, String issuerdn) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<RevokedCertInfo> listRevokedCertInfo(AuthenticationToken admin, String issuerdn, long lastbasecrldate) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void removeCertReqHistoryData(AuthenticationToken admin, String certFingerprint) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void revokeAllCertByCA(AuthenticationToken admin, String issuerdn, int reason) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void revokeCertificate(AuthenticationToken admin, Certificate cert, Collection<Integer> publishers, int reason, String userDataDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void setArchivedStatus(AuthenticationToken admin, String fingerprint) throws AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, Collection<Integer> publishers, int reason, String userDataDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, Date revokeDate, Collection<Integer> publishers, int reason, String userDataDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean setStatus(String fingerprint, int status) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String cafp, int status, int type, int certificateProfileId, String tag, long updateTime) throws CreateException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public CertificateInfo findFirstCertificateInfo(String issuerDN, BigInteger serno) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}
}
