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

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.request.RequestMessage;

/**
 * Local interface for CertificateStoreSession.
 * 
 * @version $Id$
 */
@Local
public interface CertificateStoreSessionLocal extends CertificateStoreSession {

    /** return CertificateInfo for the certificate with issuerDN and serno. If there are multiple certificates
     * with the same issuerDN, serno (should only be possible for CVC certificates) the first one (returned from database) is returned.
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno serial number of the desired certificate!
     * @return CertificateInfo if found or null
     */
    CertificateInfo findFirstCertificateInfo(String issuerDN, BigInteger serno);

    /**
     * Stores a certificate.
     * 
     * @param admin An authentication token to authorize the action
     * @param incert The certificate to be stored.
     * @param cafp Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status the status from the CertificateConstants.CERT_ constants
     * @param type Type of certificate (CERTTYPE_ENDENTITY etc from CertificateConstants).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param endEntityProfileId the end entity profile id this cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * @param updateTime epoch millis to use as last update time of the stored object
     * @return CertificateDataWrapper with the certificate just stored that can be used for further publishing
     *
     * @throws AuthorizationDeniedException if admin was not authorized to store certificate in database
     */
    CertificateDataWrapper storeCertificate(AuthenticationToken admin, Certificate incert, String username,
            String cafp, int status, int type, int certificateProfileId, int endEntityProfileId, String tag, long updateTime) throws AuthorizationDeniedException;

    /**
     * Stores a certificate without checking authorization. This should be used from other methods where authorization to
     * the CA issuing the certificate has already been checked. For efficiency this method can then be used.
     * 
     * @param incert The certificate to be stored.
     * @param cafp Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status the status from the CertificateConstants.CERT_ constants
     * @param type Type of certificate (CERTTYPE_ENDENTITY etc from CertificateConstants).
     * @param certificateProfileId the certificate profile id this cert was issued under
     * @param endEntityProfileId the end entity profile id this cert was issued under
     * @param tag a custom string tagging this certificate for some purpose
     * 
     */
    CertificateDataWrapper storeCertificateNoAuth(AuthenticationToken admin, Certificate incert, String username,
            String cafp, int status, int type, int certificateProfileId, int endEntityProfileId, String tag, long updateTime);

    /** 
     * Retrieve the full wrapped CertificateData and Base64CertData objects.
     * @return null of no data for the specified fingerprint exists
     */
    CertificateDataWrapper getCertificateData(final String fingerprint);

    /**
     * Update the base64cert column if the database row exists, but the column is empty.
     * @return true if the column was empty and is now populated.
     */
    boolean updateCertificateOnly(AuthenticationToken authenticationToken, Certificate certificate);

    /**
     * Fetch a List of all certificate fingerprints and corresponding username
     * 
     * @param cas A list of CAs that the sought certificates should be issued from
     * @param certificateProfiles A list if certificateprofiles to sort from. Will be ignored if left empty. 
     * @param activeNotifiedExpireDateMin The minimal date for expiration notification
     * @param activeNotifiedExpireDateMax The maxmimal date for expiration notification
     * @param activeExpireDateMin the current rune timestamp + the threshold 
     * 
     * @return [0] = (String) fingerprint, [1] = (String) username
     */
    List<Object[]> findExpirationInfo(Collection<String> cas, Collection<Integer> certificateProfiles, long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin);
    
    /**
     * Query if we have a clear cut case where no username or the provided username is the only user of the subjectDN and subjectKeyId.
     * @param issuerDN The CA's subject
     * @param subjectDN The entity's subject
     * @param subjectKeyId The entity's subjectKeyId
     * @param username the entity's username
     * @return true if there is no other end entity under this issuer with the same subjectKeyId or subjectDN
     */
    boolean isOnlyUsernameForSubjectKeyIdOrDnAndIssuerDN(String issuerDN, byte[] subjectKeyId, String subjectDN, String username);

    /**
     * Find the most recently issued/updated certificate for a public key
     * 
     * @param subjectKeyId Is the ASN.1 SubjectKeyIdentifier of the public key as a byte array
     * @return null or the certificate which is active, matches the argument and has the latest updateTime
     * @see org.cesecore.keys.util.KeyTools#createSubjectKeyId(java.security.PublicKey)
     */
    Certificate findMostRecentlyUpdatedActiveCertificate(byte[] subjectKeyId);

    /** @return the username or null if no row was found for this certificate fingerprint */
    String findUsernameByFingerprint(String fingerprint);

    /** 
     * Tries to get an issuerDN/serialNumber pair from the request, and see if we have that CA certificate in the certificate store. If we have
     * the CA dn, in CESeCore normalized form, is returned. 
     * @param req the request message that might contain an issued DN
     * @return issuer DN or null if it does not exist in the 
     */
    String getCADnFromRequest(RequestMessage req);
    
    /**
     * Will test if there is a unique index/constraint for (certificate serial number,issuer DN) first time it is run.
     * @return returns true if there is a database index for unique certificate serial number / issuer DN.
     */
    boolean isUniqueCertificateSerialNumberIndex();

    /** ONLY use in Unit tests.
     * Required by multiple entry unit tests since isUniqueCertificateSerialNumberIndex is a static variable. */
    void resetUniqueCertificateSerialNumberIndex();

    /** ONLY use in Unit tests.
     * Sets the check for present certificate serial number unique index to specified value. Can be used to override safety check that the 
     * index exists. */
    void setUniqueCertificateSerialNumberIndex(final Boolean value);

    /** Checks for present certificate serial number unique index in a new transaction in order to avoid rollback, since we can expect SQL exceptions here. 
     * Should not be used externally.
     * NOTE: does not add an event to the security audit log, that test certificates were added to the database, and removed.
     * All normal operations that stores certificates in the database creates audit log events.
     */
    void checkForUniqueCertificateSerialNumberIndexInTransaction(AuthenticationToken admin, Certificate incert, String username, String cafp, int status, int type,
            int certificateProfileId, int endEntityProfileId, String tag, long updateTime) throws AuthorizationDeniedException;

    /** Removed certificates created during checks for present certificate serial number unique index. 
     * Should not be used externally. */
    void removeUniqueCertificateSerialNumberTestCertificates();
    
    /**
     * Creates a revoked certificate data, for use with OCSP or CRL generation.
     * @see CertificateStoreSessionLocal#updateLimitedCertificateDataStatus(AuthenticationToken, int, String, String, String, BigInteger, int, Date, int, String)
     */
    void updateLimitedCertificateDataStatus(AuthenticationToken admin, int caId, String issuerDn, BigInteger serialNumber, Date revocationDate, int reasonCode, String caFingerprint) throws AuthorizationDeniedException;
    
    /**
     * Method for populating the CertificateData table with limited information for example from a CRL, so the OCSP responder can answer if a certificate is revoked.
     * 
     * Existing entries may only be modified if they were created through this method.
     * Updating an entry by providing RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL as reasonCode will remove the row from the table.
     * 
     * @param admin an admin that is authorized to the CA that issued the certificate
     * @param caId the CA identifier
     * @param issuerDn the BC normalized version of the issuer DN
     * @param issuerDn the BC normalized version of the subject DN
     * @param username Username
     * @param serialNumber the certificate serial number
     * @param status Certificate status
     * @param revocationDate the date of revocation
     * @param reasonCode one of RevokedCertInfo.REVOCATION_REASON_...
     * @param caFingerprint the SHA-1 of the CA Certificate that issued this entry
     * @throws AuthorizationDeniedException
     */
    void updateLimitedCertificateDataStatus(final AuthenticationToken admin, final int caId, final String issuerDn, final String subjectDn, final String username, final BigInteger serialNumber,
            final int status, final Date revocationDate, final int reasonCode, final String caFingerprint) throws AuthorizationDeniedException;
    
    /** Reloads the cache containing CA certificates */
    void reloadCaCertificateCache();
    
    /** Invoked from timer. Reloads the cache containing CA certificates and additionally sets a new timeout. */
    void reloadCaCertificateCacheAndSetTimeout();

    /** Initialize all timers and related operations used by this bean. */
    void initTimers();

    /**
     * Set the status of certificate with given serno to revoked, or unrevoked (re-activation).
     *
     * @param admin      AuthenticationToken performing the operation
     * @param cdw the certificate data to revoke or activate.
     * @param revokeDate when it was revoked
     * @param reason     the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked 
     * @throws CertificaterevokeException (rollback) if certificate does not exist
     * @throws AuthorizationDeniedException (rollback)
     */
    boolean setRevokeStatus(AuthenticationToken admin, CertificateDataWrapper cdw, Date revokedDate, int reason) throws CertificateRevokeException, AuthorizationDeniedException;

    /**
     * Lists certificate datas for a given subject signed by the given issuer.
     * 
     * @param subjectDN the DN of the subject whose certificates will be retrieved.
     * @param issuerDN the DN of the certificates issuer.
     * @param onlyActive set to true to limit the search to active (non revoked, unexpired) certificates.
     * @return List of certificate datas in no specified order or an empty List.
     */
    List<CertificateDataWrapper> getCertificateDatasBySubjectAndIssuer(String subjectDN, String issuerDN, boolean onlyActive);

    /**
     * Lists certificate datas for a given subject.
     * 
     * @param subjectDN the DN of the subject whose certificates will be retrieved.
     * @return List of certificate datas in no specified order or an empty List.
     */
    List<CertificateDataWrapper> getCertificateDatasBySubject(String subjectDN);

    /**
     * Method to set the status of certificate to revoked or active, without checking for authorization. 
     * This is why it is important that this method is _local only_. 
     * 
     * @param admin Administrator performing the operation
     * @param fingerprint the fingerprint of the certificate to revoke or activate.
     * @param revokeDate when it was revoked
     * @param reason the reason of the revocation. (One of the RevokedCertInfo.REVOCATION_REASON constants.)
     * @return true if status was changed in the database, false if not, for example if the certificate was already revoked 
     * 
     * @throws CertificateRevokeException (rollback) if certificate does not exist
     */
    boolean setRevokeStatusNoAuth(AuthenticationToken admin, CertificateData certificateData, Date revokeDate, int reason) throws CertificateRevokeException;

    /**
     * Changes a certificate from CERT_ROLLOVERPENDING to CERT_ACTIVE. If the certificate status is already CERT_ACTIVE, then it does nothing.
     * @param admin Administrator performing the operation
     * @param fingerprint Fingerprint of the certificate
     * @throws AuthorizationDeniedException
     */
    void setRolloverDoneStatus(AuthenticationToken admin, String fingerprint) throws AuthorizationDeniedException;
}
