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
import java.util.List;
import java.util.Set;

import javax.ejb.Local;

import org.cesecore.certificates.crl.RevokedCertInfo;

/**
 * Local interface for CertificateDataSession.
 * 
 * @version $Id$
 */
@Local
public interface CertificateDataSessionLocal extends CertificateDataSession {

    /** @return the found entity instance or null if the entity does not exist */
    CertificateData findByFingerprint(String fingerprint);

    /** @return return the query results as a Set. */
    Set<String> findUsernamesBySubjectDNAndIssuerDN(String subjectDN, String issuerDN);
    
    /** @return return the query results as a List. */
    List<CertificateData> findBySubjectDN(String subjectDN);

    /** @return return the query results as a List. */
    List<CertificateData> findBySerialNumber(String serialNumber);

    /** @return return the query results as a List. */
    List<CertificateData> findByIssuerDNSerialNumber(String issuerDN, String serialNumber);

    /** @return return the query results as a List. */
    CertificateInfo findFirstCertificateInfo(String issuerDN, String serialNumber);
    
    /** @return the last found username or null if none was found */
    String findLastUsernameByIssuerDNSerialNumber(String issuerDN, String serialNumber);

    /** @return return the query results as a List. */
    List<CertificateData> findByUsernameOrdered(String username);
    
    /** @return return the query results as a List. */
    List<CertificateData> findByUsernameAndStatus(String username, int status);

    /** @return return the query results as a List. */
    List<CertificateData> findByUsernameAndStatusAfterExpireDate(String username, int status, long afterExpireDate);
    
    /** @return return the query results as a List. */
    Set<String> findUsernamesByIssuerDNAndSubjectKeyId(String issuerDN, String subjectKeyId);

    String findUsernameByIssuerDnAndSerialNumber(String issuerDn, String serialNumber);
    
    /** @return return the query results as a List. */
    Set<String> findUsernamesBySubjectKeyIdOrDnAndIssuer(String issuerDN, String subjectKeyId, String subjectDN);
    
    /** @return return the query results as a List<String>. */
    List<String> findFingerprintsByIssuerDN(String issuerDN);
    
    /** @return return the query results as a Collection<RevokedCertInfo>. */
    Collection<RevokedCertInfo> getRevokedCertInfos(String issuerDN, int crlPartitionIndex, long lastbasecrldate);
    
    /** @return return the query results as a List. */
    List<CertificateData> findByExpireDateWithLimit(long expireDate, int maxNumberOfResults);

    /** @return return the query results as a List. */
    List<CertificateData> findByExpireDateWithLimitAndOffset(long expireDate, int maxNumberOfResults, int offset);

    /** @return return count of query results. */
    int countByExpireDate(long expireDate);
    
    /** @return return the query results as a List. */
    List<CertificateData> findByExpireDateAndIssuerWithLimit(long expireDate, String issuerDN, int maxNumberOfResults);
    
    /** @return return the query results as a List. */
    List<CertificateData> findByExpireDateAndTypeWithLimit(long expireDate, int certificateType, int maxNumberOfResults);
    
    List<String> findUsernamesByExpireTimeWithLimit(long minExpireTime, long maxExpireTime, int maxResults);
    
    /**
     * Get a list of {@link Certificate} from a list of list of {@link CertificateData}.
     * @param cdl
     * @return The resulting list.
     */
    List<Certificate> getCertificateList(final List<CertificateData> cdl);
    
    List<Certificate> findCertificatesByIssuerDnAndSerialNumbers(final String issuerDN, final Collection<BigInteger> serialNumbers);
    
    /** @return the CertificateInfo representation (all fields except the actual cert) or null if no such fingerprint exists. */
    CertificateInfo getCertificateInfo(String fingerprint);
    
    /** @return a List<Certificate> of SecConst.CERT_ACTIVE and CERT_NOTIFIEDABOUTEXPIRATION certs that have one of the specified types. */
    List<Certificate> findActiveCertificatesByType(Collection<Integer> certificateTypes);
    
    
    /**
     * @return a List<Certificate> of SecConst.CERT_ACTIVE and CERT_NOTIFIEDABOUTEXPIRATION certs that have one of the specified types for the given
     *         issuer.
     */
    List<Certificate> findActiveCertificatesByTypeAndIssuer(Collection<Integer> certificateTypes, String issuerDN);
    

    /**
     * Fetch a List of all certificate fingerprints and corresponding username
     *
     * We want to accomplish two things:
     *
     * 1. Notify for expirations within the service window
     * 2. Notify _once_ for expirations that occurred before the service window like flagging certificates that have a shorter
     * life-span than the threshold (pathologic test-case...)
     *
     * The first is checked by:
     *
     * notify = currRunTimestamp + thresHold <= ExpireDate < nextRunTimestamp + thresHold
     *          AND (status = ACTIVE OR status = NOTIFIEDABOUTEXPIRATION)
     *
     * The second can be checked by:
     *
     * notify = currRunTimestamp + thresHold > ExpireDate AND status = ACTIVE
     *
     * @param cas A list of CAs that the sought certificates should be issued from
     * @param certificateProfiles A list if certificateprofiles to sort from. Will be ignored if left empty.
     * @param activeNotifiedExpireDateMin The minimal date for expiration notification
     * @param activeNotifiedExpireDateMax The maxmimal date for expiration notification
     * @param activeExpireDateMin the current rune timestamp + the threshold
     *
     * @return [0] = (String) fingerprint, [1] = (String) username
     */
    List<Object[]> findExpirationInfo(Collection<String> cas, Collection<Integer> certificateProfiles,
            long activeNotifiedExpireDateMin, long activeNotifiedExpireDateMax, long activeExpireDateMin);
    
}
