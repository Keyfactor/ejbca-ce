/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificate;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Interface for certificate store operations
 * Stores certificate in the local database using Certificate JPA Beans. 
 * 
 * IMPORTANT: No publishing to publishersession from setRevokeStatus
 * 
 * @version $Id$
 */
public interface CertificateStoreSession {

    /**
     * Lists fingerprint (primary key) of ALL certificates in the database.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millions of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param issuerdn the dn of the certificates issuer.
     * @return Collection of fingerprints, i.e. Strings
     */
    Collection<String> listAllCertificates(String issuerdn);

    /**
     * Lists RevokedCertInfo of ALL revoked certificates (status =
     * CertificateConstants.CERT_REVOKED) in the database from a certain issuer.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what
     * happens if there are millions of certificates in the DB!). Should only be
     * used for testing purposes.
     * 
     * @param issuerdn the dn of the certificates issuer.
     * @param lastbasecrldate a date (Date.getTime()) of last base CRL or -1 for a complete CRL
     * @return Collection of RevokedCertInfo, reverse ordered by expireDate
     *         where last expireDate is first in array.
     */
    Collection<RevokedCertInfo> listRevokedCertInfo(String issuerdn, long lastbasecrldate);

    /**
     * Lists certificates for a given subject signed by the given issuer.
     * 
     * @param subjectDN the DN of the subject whose certificates will be retrieved.
     * @param issuerDN the DN of the certificates issuer.
     * @return Collection of Certificates (java.security.cert.Certificate) in no
     *         specified order or an empty Collection.
     */
    List<Certificate> findCertificatesBySubjectAndIssuer(String subjectDN, String issuerDN);
    
    /**
     * Lists certificates for a given subject signed by the given issuer.
     * 
     * @param subjectDN the DN of the subject whose certificates will be retrieved.
     * @param issuerDN the DN of the certificates issuer.
     * @param onlyActive set to true to limit the search to active (non revoked, unexpired) certificates.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     */
    List<Certificate> findCertificatesBySubjectAndIssuer(String subjectDN, String issuerDN, boolean onlyActive);

    /** @return set of users with certificates with specified subject DN issued by specified issuer. */
    Set<String> findUsernamesByIssuerDNAndSubjectDN(String issuerDN, String subjectDN);

    /** @return set of users with certificates with specified key issued by specified issuer. */
    Set<String> findUsernamesByIssuerDNAndSubjectKeyId(String issuerDN, byte[] subjectKeyId);

    /**
     * Return the username of a certificate data object matching the given issuer DN and serial 
     * number (there may be only one). 
     * 
     * @param issuerDn The DN of the issuing CA
     * @param serialNumber the serial number of the sought certificate. 
     * @return the matching username,
     */
    String findUsernameByIssuerDnAndSerialNumber(String issuerDn, BigInteger serialNumber);
    
    /**
     * Lists certificates for a given subject.
     * 
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @return Collection of Certificates (java.security.cert.Certificate) in no
     *         specified order or an empty Collection.
     */
    List<Certificate> findCertificatesBySubject(String subjectDN);

    /**
     * Finds certificates  expiring within a specified time and that have
     * status "active" or "notifiedaboutexpiration".
     * @param expireTime The time by which the certificates will be expired
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of maximum 500 certificates, never null
     */
    Collection<CertificateWrapper> findCertificatesByExpireTimeWithLimit(Date expireTime);
    
    /**
     * Finds certificates  expiring within a specified time and that have
     * status "active" or "notifiedaboutexpiration".
     * @param expireTime The time by which the certificates will be expired
     * @param maxNumberOfResults The maximum number of certificates to be returned
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @return List of certificates (java.security.cert.Certificate), never null
     */
    List<Certificate> findCertificatesByExpireTimeWithLimit(Date expireTime, int maxNumberOfResults);
    
    /**
     * Finds certificates  expiring within a specified time, issued by a specified issuer and have
     * status "active" or "notifiedaboutexpiration".
     * @param expireTime The time by which the certificates will be expired
     * @param issuerDN The SubjectDN of the CA that issued the certificates that will expire within the given time
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @return List of maximum 500 certificates (java.security.cert.Certificate), never null
     */
    List<Certificate> findCertificatesByExpireTimeAndIssuerWithLimit(Date expireTime, String issuerDN);
    
    /**
     * Finds certificates  expiring within a specified time, issued by a specified issuer and have
     * status "active" or "notifiedaboutexpiration".
     * @param expireTime The time by which the certificates will be expired
     * @param issuerDN The SubjectDN of the CA that issued the certificates that will expire within the given time
     * @param maxNumberOfResults The maximum number of certificates to be returned
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @return List of certificates (java.security.cert.Certificate), never null
     */
    List<Certificate> findCertificatesByExpireTimeAndIssuerWithLimit(Date expireTime, String issuerDN, int maxNumberOfResults);
        
    /**
     * Finds certificates  expiring within a specified time, of a specified type and have
     * status "active" or "notifiedaboutexpiration".
     * @param expireTime The time by which the certificates will be expired
     * @param certificateType The type of the certificates that will expire within the given time
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_UNKNOWN
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_ENDENTITY
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_SUBCA
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_ROOTCA
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_HARDTOKEN
     * @return List of maximum 500 certificates (java.security.cert.Certificate), never null
     */
    List<Certificate> findCertificatesByExpireTimeAndTypeWithLimit(Date expireTime, int certificateType);
    
   /** 
    * Finds certificates  expiring within a specified time, of a specified type and have
    * status "active" or "notifiedaboutexpiration".
    * @param expireTime The time by which the certificates will be expired
    * @param certificateType The type of the certificates that will expire within the given time
    * @param maxNumberOfResults The maximum number of certificates to be returned
    * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
    * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
    * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_UNKNOWN
    * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_ENDENTITY
    * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_SUBCA
    * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_ROOTCA
    * @see org.cesecore.certificates.certificate.CertificateConstants#CERTTYPE_HARDTOKEN
    * @return List of certificates (java.security.cert.Certificate), never null
    */
    List<Certificate> findCertificatesByExpireTimeAndTypeWithLimit(Date expireTime, int certificateType, int maxNumberOfResults);

    /**
     * Finds usernames of users having certificate(s) expiring within a
     * specified time and that has status "active" or "notifiedaboutexpiration".
     * 
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_ACTIVE
     * @see org.cesecore.certificates.certificate.CertificateConstants#CERT_NOTIFIEDABOUTEXPIRATION
     * @return Collection of String, never null
     */
    Collection<String> findUsernamesByExpireTimeWithLimit(Date expiretime);

    /**
     * Finds a certificate specified by issuer DN and serial number.
     * 
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno serial number of the desired certificate!
     * @return Certificate if found or null
     */
    Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno);

    /**
     * Gets full certificate meta data for the cert specified by issuer DN and serial number.
     * 
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno serial number of the desired certificate!
     * @return null when not found
     */
    CertificateDataWrapper getCertificateDataByIssuerAndSerno(String issuerDN, BigInteger serno);
    
    /**
     * Find a certificate by its subject key ID
     * 
     * @param subjectKeyId subject key ID of the sought certificate
     * @return Certificates if found, or null.
     */
    Collection<Certificate> findCertificatesBySubjectKeyId(byte[] subjectKeyId);
    
    /**
     * The method retrieves all certificates from a specific issuer which are
     * identified by list of serial numbers. The collection will be empty if the
     * issuerDN is <tt>null</tt>/empty or the collection of serial numbers is
     * empty.
     * 
     * @param issuerDN the subjectDN of a CA certificate
     * @param sernos a collection of certificate serialnumbers
     * @return Collection a list of certificates; never <tt>null</tt>
     */
    Collection<Certificate> findCertificatesByIssuerAndSernos(String issuerDN, Collection<BigInteger> sernos);

    /**
     * Finds certificate(s) for a given serialnumber.
     * 
     * @param serno the serialnumber of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     */
    List<CertificateDataWrapper> getCertificateDataBySerno(BigInteger serno);

    /**
     * Find the latest published X509Certificate matching the given subject DN.
     * Note that this method does not check if the returned certificate was issued by a rollover CA.
     * 
     * @param subjectDN The subject DN to match.
     * @return the sought result, or null if none exists.
     */
    X509Certificate findLatestX509CertificateBySubject(String subjectDN);
    
    /**
     * Find the latest published X509Certificate matching the given subject DN.
     * This method can search for normal or rollover certificates.
     * 
     * @param subjectDN The subject DN to match.
     * @param rolloverCA The rollover certificate of the issuing CA, or null to not check if issued by a rollover certificate.
     * @param findRollover Whether a rollover or normal certificate should be returned.
     * @return the sought result, or null if none exists.
     */
    X509Certificate findLatestX509CertificateBySubject(String subjectDN, X509Certificate rolloverCA, boolean findRollover);
    
    /**
     * Finds username for a given certificate serial number.
     * 
     * @param serno the serialnumber of the certificate to find username for.
     * @return username or null if none found.
     */
    String findUsernameByCertSerno(BigInteger serno, String issuerdn);

    /**
     * Finds certificate(s) for a given username.
     * 
     * @param username the username of the certificate(s) that will be retrieved
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or null if none found.
     */
    Collection<CertificateWrapper> findCertificatesByUsername(String username);

    /**
     * Finds certificate(s) with meta data for a given username.
     * 
     * @param username the username of the certificate(s) that will be retrieved
     * @return List of wrapped CertificateData and Base64CertData ordered by
     *         expire date, with last expire date first, or empty list if none found.
     */
    List<CertificateDataWrapper> getCertificateDataByUsername(String username);
    
    /**
     * Finds certificate(s) for a given username and status.
     * 
     * @param username the username of the certificate(s) that will be retrieved
     * @param status the status from the CertificateConstants.CERT_ constants
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or empty list if user can not be found
     */
    Collection<Certificate> findCertificatesByUsernameAndStatus(String username, int status);

    /**
     * Finds certificate(s) for a given username and status if the expireDate is after the provided one.
     * 
     * @param username the username of the certificate(s) that will be retrieved
     * @param status the status from the CertificateConstants.CERT_ constants
     * @param afterExpireDate only return entries that has an expireDate larger than or equal to this one
     * @return Collection of Certificates ordered by expire date, with last
     *         expire date first, or empty list if user can not be found
     */
    Collection<Certificate> findCertificatesByUsernameAndStatusAfterExpireDate(String username, int status, long afterExpireDate);

    /**
     * Gets certificate info, which is basically all fields except the
     * certificate itself. Note: this method should not be used within a
     * transaction where the reading of this info might depend on something
     * stored earlier in the transaction. This is because this method uses
     * direct SQL.
     * 
     * @return CertificateInfo or null if certificate does not exist.
     */
    CertificateInfo getCertificateInfo(String fingerprint);

    /**
     * Finds a certificate based on fingerprint. 
     * You can get fingerprint by for example "String fingerprint = CertTools.getFingerprintAsString(certificate);"
     * @return Certificate or null if it can not be found.
     */
    Certificate findCertificateByFingerprint(String fingerprint);

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     *
     * @param issuerDN get all certificates issued by a specific issuer.
     *                 If <tt>null</tt> or empty return certificates regardless of
     *                 the issuer.
     * @param type     CERTTYPE_* types from CertificateConstants
     * @throws IllegalArgumentException when admin is null or type is not one or more of of SecConst.CERTTYPE_SUBCA, SecConst.CERTTYPE_ENDENTITY, SecConst.CERTTYPE_ROOTCA
     * @return Collection of Certificate, never <tt>null</tt>
     */
    Collection<CertificateWrapper> findCertificatesByType(int type, String issuerDN);

    /**
     * Recursively finds the certificate chain for the given certificate.
     * 
     * @param certinfo Certificate to start from, usually a leaf certificate.
     * @return List containing certificate chain, starting with the given certificate.
     */
    List<Certificate> getCertificateChain(CertificateInfo certinfo);

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * @param admin      AuthenticationToken performing the operation
     * @param issuerdn   Issuer of certificate to be removed.
     * @param serno      the serno of certificate to revoke.
     * @param revokeDate when it was revoked
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked 
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     * @deprecated Only used by tests
     */
    boolean setRevokeStatus(AuthenticationToken admin, String issuerdn, BigInteger serno, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException;

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * @param admin      AuthenticationToken performing the operation
     * @param certificate the certificate to revoke or activate.
     * @param revokeDate when it was revoked
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked 
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     * @deprecated Only used by tests
     */
    boolean setRevokeStatus(AuthenticationToken admin, Certificate certificate, Date revokedDate, int reason)
        throws CertificateRevokeException, AuthorizationDeniedException;
    
    /**
     * Method revoking all certificates generated by the specified issuerdn. Sets revocationDate to current time. 
     * Should only be called by when a CA is about to be revoked.
     * 
     * @param admin    the administrator performing the event.
     * @param issuerdn the dn of CA about to be revoked
     * @param reason   the reason of revocation.
     */
    void revokeAllCertByCA(AuthenticationToken admin, String issuerdn, int reason) throws AuthorizationDeniedException;

    /**
     * Checks if a certificate is revoked.
     * 
     * @param issuerDN the DN of the issuer.
     * @param serno the serialnumber of the certificate that will be checked
     * @return true if the certificate is revoked or can not be found in the
     *         database, false if it exists and is not revoked.
     */
    boolean isRevoked(String issuerDN, BigInteger serno);

    /**
     * Get certificate status fast.
     * @return CertificateStatus status of the certificate, never null, CertificateStatus.NOT_AVAILABLE if the certificate is not found.
     */
    CertificateStatus getStatus(String issuerDN, BigInteger serno);

    /**
     * Performs the same operation as getStatus, but returns a richer object which also contains the certificate, in order to save on database 
     * lookups when both objects are required. Issuer + serial number are always unique. 
     * 
     * @param issuerDN the issuer of the sought certificate
     * @param serno the serial number of the sought certificate
     * @return a {@link CertificateStatusHolder} object containing the status and the sought certificate.
     */
    CertificateStatusHolder getCertificateAndStatus(String issuerDN, BigInteger serno);
    
    /**
     * Update the status of a cert in the database.
     * @param fingerprint
     * @param status one of CertificateConstants.CERT_...
     * @return true if the status was updated, false if not, for example if the certificate did not exist
     */
    boolean setStatus(AuthenticationToken admin, String fingerprint, int status) throws AuthorizationDeniedException;
    
}
