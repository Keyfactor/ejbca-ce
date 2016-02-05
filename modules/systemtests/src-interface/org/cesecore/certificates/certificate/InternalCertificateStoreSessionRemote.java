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
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * This session bean should under no circumstances be included in the release version of CESeCore.
 * It allows removal of certificates, and may be used only for functional tests to clean up after
 * themselves.
 * 
 * @version $Id$
 */
@Remote
public interface InternalCertificateStoreSessionRemote {
    /**
     * This method removes the given certificate(s) by serial number.
     * 
     * @param serno Serial number of the certificate(s) to remove.
     */
    void removeCertificate(BigInteger serno);

    /**
     * This method removes the given certificate(s) by fingerprint (primary key).
     * @see org.cesecore.util.CertTools#getFingerprintAsString(java.lang.String)
     * 
     * @param fingerprint fingerprint of the certificate(s) to remove.
     * @return number of rows (certificates) removed from the Base64CertTable
     */
    int removeCertificate(String fingerprint);

    /**
     * Removes the given {@link Certificate} by its fingerprint.
     * 
     * @param certificate The Certificate whose corresponding CertificateData is to be removed.
     * @return number of rows (certificates) removed from the Base64CertTable.
     */
    int removeCertificate(Certificate certificate);
    
    /** Removes all certificates issued to the given subject DN
     * 
     * @param subjectDN the subject DN of the certificates that should be removed
     */
    public void removeCertificatesBySubject(final String subjectDN);

    /** To allow testing of Local-only method */
    List<Object[]> findExpirationInfo(Collection<String> cas, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin);
     
    Collection<Certificate> findCertificatesByIssuer(String issuerDN);

	/**
	 * Removes a CRL from the database, does not throw any errors if the CRL does not exist.
	 *
	 * @param admin Administrator performing the operation
	 * @param fingerprint the fingerprint of the CRL to remove
	 * 
     * @throws AuthorizationDeniedException (rollback) if admin was not authorized to remove CRL
	 */
	void removeCRL(final AuthenticationToken admin, final String fingerprint) throws AuthorizationDeniedException;
	
	 /**
     * Update the status of a cert in the database. Whatever status you want...
     * @param fingerprint
     * @param status one of CertificateConstants.CERT_...
     * @return true if the status was updated, false if not, for example if the certificate did not exist
     */
    boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws AuthorizationDeniedException;
    
    /** Setting unique serno check to OK, i.e. force EJBCA to believe we have a unique issuerDN/SerialNo index in the database
     */
    void setUniqueSernoIndexTrue();

    /** Setting unique serno check to false, i.e. force EJBCA to believe we don't have a unique issuerDN/SerialNo index in the database
     */
    void setUniqueSernoIndexFalse();

    /** Resets the current (static) check for unique index and re-checks. */
    boolean existsUniqueSernoIndex();

    /** Resetting unique serno check */
    void resetUniqueSernoCheck();

    /**
     * Reloads the cache containing CA certificates
     */
    void reloadCaCertificateCache();

    /**
     * Make updateLimitedCertificateDataStatus invokable from system tests.
     * @see org.cesecore.certificates.certificate.CertificateStoreSessionLocal#updateLimitedCertificateDataStatus(AuthenticationToken, int, String, BigInteger, Date, int, String)
     */
    void updateLimitedCertificateDataStatus(AuthenticationToken admin, int caId, String issuerDn, BigInteger serialNumber, Date revocationDate, int reasonCode, String caFingerprint) throws AuthorizationDeniedException;
    
    void updateLimitedCertificateDataStatus(AuthenticationToken admin, int caId, String issuerDn, String subjectDn, String username,
            BigInteger serialNumber, int status, Date revocationDate, int reasonCode, String caFingerprint)  throws AuthorizationDeniedException;

    /** @return a raw CertificateData row */
    CertificateData getCertificateData(String fingerprint);

    /** @return a raw Base64CertData row */
    Base64CertData getBase64CertData(String fingerprint);

    void removeCRLs(AuthenticationToken admin, String issuerDN) throws AuthorizationDeniedException;

    /** @see org.cesecore.certificates.certificate.CertificateStoreSessionLocal#storeCertificateNoAuth(AuthenticationToken, Certificate, String, String, int, int, int, String, long) */
    CertificateDataWrapper storeCertificateNoAuth(AuthenticationToken adminForLogging, Certificate incert, String username, String cafp, int status, int type, int certificateProfileId, String tag, long updateTime);
}
