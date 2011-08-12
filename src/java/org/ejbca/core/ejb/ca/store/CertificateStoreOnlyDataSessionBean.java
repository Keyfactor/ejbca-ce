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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CryptoProviderTools;

/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertificateStoreOnlyDataSessionBean extends CertificateDataUtil implements CertificateStoreSessionLocal, CertificateStoreSessionRemote {
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    public CertificateStoreOnlyDataSessionBean() {
        super();
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

	@Override
    public CertificateStatus getStatus(String issuerDN, BigInteger serno) {
        return getStatus(issuerDN, serno, entityManager);
    }

	@Override
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno) {
    	return findCertificateByIssuerAndSerno(issuerDN, serno, entityManager);
    }

	@Override
    public Collection<Certificate> findCertificatesByType(int type, String issuerDN) {
        return findCertificatesByType(type, issuerDN, entityManager);
    }

	@Override
    public Collection<Certificate> findCertificatesByUsername(String username) {
    	return findCertificatesByUsername(username, entityManager);
    }

	/* *******************************************************************
	 * The following methods are not implemented in stand alone VA mode! *
	 *********************************************************************/
	
	@Override
	public boolean checkIfAllRevoked(String username) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Certificate findCertificateByFingerprint(String fingerprint) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesByExpireTimeWithLimit(Date expireTime) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesByIssuerAndSernos(String issuerDN, Collection<BigInteger> sernos) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesBySerno(BigInteger serno) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesBySubject(String subjectDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesBySubjectAndIssuer(String subjectDN, String issuerDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesByUsernameAndStatus(String username, int status) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public List<Object[]> findExpirationInfo(String cASelectString, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public String findUsernameByCertSerno(BigInteger serno, String issuerdn) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<String> findUsernamesByExpireTimeWithLimit(Date expiretime) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Set<String> findUsernamesByIssuerDNAndSubjectDN(String issuerDN, String subjectDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Set<String> findUsernamesByIssuerDNAndSubjectKeyId(String issuerDN, byte[] subjectKeyId) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public CertificateInfo getCertificateInfo(String fingerprint) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean isRevoked(String issuerDN, BigInteger serno) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<String> listAllCertificates(String issuerdn) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<RevokedCertInfo> listRevokedCertInfo(String issuerdn, long lastbasecrldate) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public void revokeAllCertByCA(AuthenticationToken admin, String issuerdn, int reason) {
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

	@Override
	public boolean setRevokeStatusNoAuth(AuthenticationToken admin,
			Certificate certificate, Date revokedDate, int reason,
			String userDataDN) throws CertificateRevokeException,
			AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean storeCertificateNoAuth(AuthenticationToken admin,
			Certificate incert, String username, String cafp, int status,
			int type, int certificateProfileId, String tag, long updateTime)
			throws CreateException, AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public Collection<Certificate> findCertificatesBySubjectKeyId(
			byte[] subjectKeyId) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public X509Certificate findLatestX509CertificateBySubject(String subjectDN) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean setRevokeStatus(AuthenticationToken admin, String issuerdn,
			BigInteger serno, Date revokedDate, int reason, String userDataDN)
			throws CertificateRevokeException, AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean setRevokeStatus(AuthenticationToken admin,
			Certificate certificate, Date revokedDate, int reason,
			String userDataDN) throws CertificateRevokeException,
			AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean setRevokeStatus(AuthenticationToken admin, String issuerdn,
			BigInteger serno, int reason, String userDataDN)
			throws CertificateRevokeException, AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean setRevokeStatus(AuthenticationToken admin,
			Certificate certificate, int reason, String userDataDN)
			throws CertificateRevokeException, AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}

	@Override
	public boolean setStatus(AuthenticationToken admin, String fingerprint,
			int status) throws AuthorizationDeniedException {
		throw new RuntimeException("Not implemented in stand alone version.");
	}
}
