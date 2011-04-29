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

import org.ejbca.core.model.authorization.AuthenticationFailedException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * Interface for certificate store operations
 *
 * @version $Id$
 */
public interface CertificateStoreSession {

    /**
     * Stores a certificate.
     *
     * @param incert   The certificate to be stored.
     * @param cafp     Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status   Status of the certificate (from CertificateData).
     * @param type     Type of certificate (CERTTYPE_ENDENTITY etc from CertificateDataBean).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * @return true if storage was successful.
     * @throws CreateException if the certificate can not be stored in the database
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp, int status, int type, int certificateProfileId, String tag, long updateTime) throws CreateException;

    /**
     * Lists fingerprint (primary key) of ALL certificates in the database.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millions of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param admin    Administrator performing the operation
     * @param issuerdn the dn of the certificates issuer.
     * @return Collection of fingerprints, i.e. Strings.
     */
    public Collection<String> listAllCertificates(Admin admin, String issuerdn);

    /**
     * Lists RevokedCertInfo of ALL revoked certificates (status =
     * CertificateDataBean.CERT_REVOKED) in the database from a certain issuer.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millions of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param admin Administrator performing the operation
     * @param issuerdn the dn of the certificates issuer.
     * @param lastbasecrldate a date (Date.getTime()) of last base CRL or -1
     *         for a complete CRL
     * @return Collection of RevokedCertInfo, reverse ordered by expireDate
     *         where last expireDate is first in array.
     */
    public Collection<RevokedCertInfo> listRevokedCertInfo(Admin admin, String issuerdn, long lastbasecrldate);

    /**
     * Lists certificates for a given subject signed by the given issuer.
     *
     * @param admin     Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @param issuerDN  the dn of the certificates issuer.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     */
    public Collection<Certificate> findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuerDN);

    /** @return set of users with certificates with specified subject DN issued by specified issuer. */
    public Set<String> findUsernamesByIssuerDNAndSubjectDN(Admin admin, String issuerDN, String subjectDN);

    /** @return set of users with certificates with specified key issued by specified issuer. */
    public Set<String> findUsernamesByIssuerDNAndSubjectKeyId(Admin admin, String issuerDN, byte[] subjectKeyId);

    /**
     * Lists certificates for a given subject.
     *
     * @param admin     Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     */
    public Collection<Certificate> findCertificatesBySubject(Admin admin, String subjectDN);

    /**
     * Finds certificates  expiring within a specified time and that has
     * status "active" or "notifiedaboutexpiration".
     * @see org.ejbca.core.model.SecConst#CERT_ACTIVE
     * @see org.ejbca.core.model.SecConst#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of Certificate, never null
     */
    public Collection<Certificate> findCertificatesByExpireTimeWithLimit(Admin admin, Date expireTime);

    /**
     * Finds usernames of users having certificate(s) expiring within a
     * specified time and that has status "active" or "notifiedaboutexpiration".
     * 
     * @see org.ejbca.core.model.SecConst#CERT_ACTIVE
     * @see org.ejbca.core.model.SecConst#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of String, never null
     */
    public Collection<String> findUsernamesByExpireTimeWithLimit(Admin admin, Date expiretime);

    /**
     * Finds a certificate specified by issuer DN and serial number.
     *
     * @param admin    Administrator performing the operation
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno    serial number of the desired certificate!
     * @return Certificate if found or null
     */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno);

    /**
     * The method retrieves all certificates from a specific issuer
     * which are identified by list of serial numbers. The collection
     * will be empty if the issuerDN is <tt>null</tt>/empty
     * or the collection of serial numbers is empty.
     *
     * @param issuerDN the subjectDN of a CA certificate
     * @param sernos a Collection<BigInteger> of certificate serialnumbers
     * @return Collection a list of certificates; never <tt>null</tt>
     */
    public Collection<Certificate> findCertificatesByIssuerAndSernos(Admin admin, String issuerDN, Collection<BigInteger> sernos);

    /**
     * Finds certificate(s) for a given serialnumber.
     *
     * @param admin Administrator performing the operation
     * @param serno the serialnumber of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     */
    public Collection<Certificate> findCertificatesBySerno(Admin admin, BigInteger serno);

    /**
     * Finds username for a given certificate serial number.
     *
     * @param admin Administrator performing the operation
     * @param serno the serialnumber of the certificate to find username for.
     * @return username or null if none found.
     */
    public String findUsernameByCertSerno(Admin admin, BigInteger serno, String issuerdn);

    /**
     * Finds certificate(s) for a given username.
     *
     * @param admin Administrator performing the operation
     * @param username the username of the certificate(s) that will be retrieved
     * @return Collection of Certificates ordered by expire date, with last expire date first, or null if none found.
     */
    public Collection<Certificate> findCertificatesByUsername(Admin admin, String username);

    /**
     * Finds certificate(s) for a given username and status.
     *
     * @param admin Administrator performing the operation
     * @param username the username of the certificate(s) that will be retrieved
     * @param status the status of the CertificateDataBean.CERT_ constants
     * @return Collection of Certificates ordered by expire date, with last expire date first, or empty list if user can not be found
     */
    public Collection<Certificate> findCertificatesByUsernameAndStatus(Admin admin, String username, int status);

    /**
     * Gets certificate info, which is basically all fields except the
     * certificate itself. Note: this method should not be used within a
     * transaction where the reading of this info might depend on something
     * stored earlier in the transaction. This is because this method uses
     * direct SQL.
     * 
     * @return CertificateInfo or null if certificate does not exist.
     */
    public CertificateInfo getCertificateInfo(Admin admin, String fingerprint);

    /**
     * Finds a certificate based on fingerprint. 
     * You can get fingerprint by for example "String fingerprint = CertTools.getFingerprintAsString(certificate);"
     * @return Certificate or null if it can not be found.
     */
    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint);

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     *
     * @param issuerDN get all certificates issued by a specific issuer.
     *                 If <tt>null</tt> or empty return certificates regardless of
     *                 the issuer.
     * @param type     CERTTYPE_* types from SecConst
     * @throws IllegalArgumentException when admin is null or type is not one or more of of SecConst.CERTTYPE_SUBCA, SecConst.CERTTYPE_ENDENTITY, SecConst.CERTTYPE_ROOTCA
     * @return Collection Collection of Certificate, never <tt>null</tt>
     */
    public Collection<Certificate> findCertificatesByType(Admin admin, int type, String issuerDN);

    /**
     * Method that sets status CertificateDataBean.CERT_ARCHIVED on the
     * certificate data, only used for testing. Can only be performed by an
     * Admin.TYPE_INTERNALUSER. Normally ARCHIVED is set by the CRL creation
     * job, after a certificate has expired and been added to a CRL (expired
     * certificates that are revoked must be present on at least one CRL).
     */
    public void setArchivedStatus(Admin admin, String fingerprint) throws AuthorizationDeniedException;

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     *
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     * 
     * @param admin      Administrator performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param serno      the serno of certificate to revoke.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     */
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Collection<Integer> publishers, int reason, String userDataDN);

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate
     *
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     *
     * @param admin      Administrator performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param serno      the serno of certificate to revoke.
     * @param revokedate when it was revoked
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @param reason     the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate, the object could be taken from user data instead.
     */
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Date revokedate, Collection<Integer> publishers, int reason, String userDataDN);

    /**
     * Revokes a certificate (already revoked by the CA), in the database. Also handles re-activation of suspended certificates.
     *
     * Re-activating (unrevoking) a certificate have two limitations.
     * 1. A password (for for example AD) will not be restored if deleted, only the certificate and certificate status and associated info will be restored
     * 2. ExtendedInformation, if used by a publisher will not be used when re-activating a certificate 
     * 
     * The method leaves up to the caller to find the correct publishers and userDataDN.
     *
     * @param admin      Administrator performing the operation
     * @param cert       The DER coded Certificate that has been revoked.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @param userDataDN if an DN object is not found in the certificate use object from user data instead.
     */
    public void revokeCertificate(Admin admin, Certificate cert, Collection<Integer> publishers, int reason, String userDataDN);

    /**
     * Method revoking all certificates generated by the specified issuerdn. Sets revocationDate to current time.
     * Should only be called by CAAdminSessionBean when a CA is about to be revoked.
     *
     * @param admin    the administrator performing the event.
     * @param issuerdn the dn of CA about to be revoked
     * @param reason   the reason of revocation.
     */
    public void revokeAllCertByCA(Admin admin, String issuerdn, int reason);

    /**
     * Method that checks if a users all certificates have been revoked.
     *
     * @param admin    Administrator performing the operation
     * @param username the username to check for.
     * @return returns true if all certificates are revoked.
     */
    public boolean checkIfAllRevoked(Admin admin, String username);

    /**
     * Checks if a certificate is revoked.
     *
     * @param issuerDN the DN of the issuer.
     * @param serno    the serialnumber of the certificate that will be checked
     * @return true if the certificate is revoked or can not be found in the
     *         database, false if it exists and is not revoked.
     */
    public boolean isRevoked(String issuerDN, BigInteger serno);

    /**
     * Get certificate status fast.
     * @return CertificateStatus status of the certificate, never null, CertificateStatus.NOT_AVAILABLE if the certificate is not found.
     */
    public CertificateStatus getStatus(String issuerDN, BigInteger serno);

    /**
     * Method that authenticates a certificate by checking validity and lookup if certificate is revoked.
     *
     * @param certificate the certificate to be authenticated.
     * @param requireAdminCertificateInDatabase if true the certificate has to exist in the database
     * @throws AuthenticationFailedException if authentication failed.
     */
    public void authenticate(X509Certificate certificate, boolean requireAdminCertificateInDatabase) throws AuthenticationFailedException;

    /**
     * Method used to add a CertReqHistory to database
     * 
     * @param admin calling the methods
     * @param cert the certificate to store (Only X509Certificate used for now)
     * @param useradmindata the user information used when issuing the certificate.
     */
    public void addCertReqHistoryData(Admin admin, Certificate cert, UserDataVO useradmindata);

    /**
     * Method to remove CertReqHistory data.
     * @param admin
     * @param certFingerprint the primary key.
     */
    public void removeCertReqHistoryData(Admin admin, String certFingerprint);

    /**
     * Retrieves the certificate request data belonging to given certificate serialnumber and issuerdn
     * 
	 * NOTE: This method will try to repair broken XML and will in that case
	 * update the database. This means that this method must always run in a
	 * transaction! 
	 * 
     * @param admin
     * @param certificateSN serial number of the certificate
     * @param issuerDN
     * @return the CertReqHistory or null if no data is stored with the certificate.
     */
    public CertReqHistory getCertReqHistory(Admin admin, BigInteger certificateSN, String issuerDN);

    /**
	 * NOTE: This method will try to repair broken XML and will in that case
	 * update the database. This means that this method must always run in a
	 * transaction! 
	 * 
     * @return all certificate request data belonging to a user.
     */
    public List<CertReqHistory> getCertReqHistory(Admin admin, String username);

    /**
     * Used by health-check. Validate database connection.
     * @return an error message or an empty String if all are ok.
     */
    // TODO: This should only be in the local interface.
    public java.lang.String getDatabaseStatus();
    
    /**
     * Fetch a List of all certificate fingerprints and corresponding username
     * @return [0] = (String) fingerprint, [1] = (String) username
     */
    public List<Object[]> findExpirationInfo(String cASelectString, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin);
    
    /**
     * Update the status of a cert in the database.
     * @param fingerprint
     * @param status one of SecConst.CERT_...
     */
    public boolean setStatus(String fingerprint, int status);
}
