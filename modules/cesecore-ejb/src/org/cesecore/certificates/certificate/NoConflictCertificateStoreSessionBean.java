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
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.collections.CollectionUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;

/**
 * These methods call CertificateStoreSession for certificates that are plain CertificateData entities.
 * See {@link CertificateStoreSession} for method descriptions.
 * 
 * <p>For NoConflictCertificateData the methods perform additional logic to check that it gets the most recent
 * entry if there's more than one (taking permanent revocations into account), and for updates it
 * appends new entries instead of updating existing ones. 
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "NoConflictCertificateStoreSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class NoConflictCertificateStoreSessionBean implements NoConflictCertificateStoreSessionRemote, NoConflictCertificateStoreSessionLocal {

    private final static Logger log = Logger.getLogger(NoConflictCertificateStoreSessionBean.class);
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private SecurityEventsLoggerSessionLocal logSession;
    @EJB
    private NoConflictCertificateDataSessionLocal noConflictCertificateDataSession;
    
    private void authorizedToCA(final AuthenticationToken admin, final int caid) throws AuthorizationDeniedException {
        if (!authorizationSession.isAuthorized(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", admin.toString(), caid);
            throw new AuthorizationDeniedException(msg);
        }
    }
    
    /**
     * Returns true if the CA allows revocation of non-existing certificates.
     * @param issuerDN Subject DN of CA.
     */
    @Override
    public boolean canRevokeNonExisting(final String issuerDN) {
        final int caid = CertTools.stringToBCDNString(StringTools.strip(issuerDN)).hashCode();
        final CAInfo cainfo = caSession.getCAInfoInternal(caid);
        return canRevokeNonExisting(cainfo, issuerDN);
    }

    /**
     * Returns true if the CA allows revocation of non-existing certificates.
     * @param cainfo CA
     * @param issuerDN Subject DN of CA, for safety check against CAId collisions.
     */
    private boolean canRevokeNonExisting(final CAInfo cainfo, final String issuerDN) {
        String dn = CertTools.stringToBCDNString(StringTools.strip(issuerDN));
        if (cainfo == null || !cainfo.getSubjectDN().equals(dn) || !cainfo.isAcceptRevocationNonExistingEntry()) {
            return false;
        }
        // XXX this option can be set in the certificate profile as well! does it make sense to have mixed locations? it would make CRL generation more complex!
        if (cainfo.isUseCertificateStorage()) {
            if (log.isDebugEnabled()) {
                log.debug("CA '" + cainfo.getName() + "' is misconfigured. Revocation of non-existing certificates is currently only supported for 'throw away CAs'.");
            }
            return false;
        }
        return true;
    }

    @Override
    public CertificateDataWrapper getCertificateDataByIssuerAndSerno(final String issuerdn, final BigInteger certserno) {
        CertificateDataWrapper cdw = certificateStoreSession.getCertificateDataByIssuerAndSerno(issuerdn, certserno);
        if (cdw != null) {
            // Full certificate is available, return it
            return cdw;
        }

        // Throw away CA or missing certificate
        final int caid = CertTools.stringToBCDNString(StringTools.strip(issuerdn)).hashCode();
        final CAInfo cainfo = caSession.getCAInfoInternal(caid);
        if (!canRevokeNonExisting(cainfo, issuerdn)) {
            if (cainfo == null && log.isDebugEnabled()) {
                log.debug("Tried to look up certificate " + certserno.toString(16) +", but neither certificate nor CA was found. CA Id: " + caid + ". Issuer DN: '" + issuerdn + "'");
            }
            return null;
        }
        if (cainfo.isUseNoConflictCertificateData()) {
            final NoConflictCertificateData certificateData = getLimitedNoConflictCertDataRow(cainfo, certserno);
            return new CertificateDataWrapper(certificateData);
        } else {
            final CertificateData certificateData = new CertificateData();
            fillInLimitedCertificateData(certificateData, cainfo, certserno);
            certificateData.setUpdateTime(System.currentTimeMillis());
            return new CertificateDataWrapper(certificateData, null);
        }
    }
    
    @Override
    public CertificateStatus getStatus(final String issuerDN, final BigInteger serno) {
        if (log.isTraceEnabled()) {
            log.trace(">getStatus(), dn:" + issuerDN + ", serno=" + serno.toString(16));
        }
        // First, try to look up in CertificateData
        final String dn = CertTools.stringToBCDNString(issuerDN);
        CertificateStatus status = certificateStoreSession.getStatus(issuerDN, serno);
        if (!canRevokeNonExisting(issuerDN) || status != CertificateStatus.NOT_AVAILABLE) {
            log.trace("<getStatus()");
            return status;
        }
        // If not found, take most recent certificate from NoConflictCertificateData
        final NoConflictCertificateData noConflictCert = findMostRecentCertData(dn, serno); 
        if (noConflictCert == null) {
            if (log.isTraceEnabled()) {
                log.trace("<getStatus() did not find certificate with dn " + dn + " and serno " + serno.toString(16));
            }
            // For throw-away CAs that allow revocation of non-existing certificates, we pretend that non-existing is OK
            return CertificateStatus.OK;
        }
        status = CertificateStatusHelper.getCertificateStatus(noConflictCert);
        if (log.isTraceEnabled()) {
            log.trace("<getStatus() returned " + status + " for cert number " + serno.toString(16));
        }
        return status;
        
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public CertificateDataWrapper getCertificateData(final String fingerprint) {
        CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(fingerprint);
        if (cdw != null) {
            return cdw;
        }
        // If not found, take most recent certificate from NoConflictCertificateData
        final Collection<NoConflictCertificateData> certDatas = noConflictCertificateDataSession.findByFingerprint(fingerprint);
        return new CertificateDataWrapper(filterMostRecentCertData(certDatas));
    }
    
    @Override
    public Collection<RevokedCertInfo> listRevokedCertInfo(String issuerdn, long lastbasecrldate) {
        if (log.isTraceEnabled()) {
            log.trace(">listRevokedCertInfo('" + issuerdn + "', " + lastbasecrldate + ")");
        }
        final Collection<RevokedCertInfo> revokedInCertData = certificateStoreSession.listRevokedCertInfo(issuerdn, lastbasecrldate);
        final Collection<RevokedCertInfo> revokedInNoConflictData = noConflictCertificateDataSession.getRevokedCertInfosWithDuplicates(issuerdn, lastbasecrldate);
        if (log.isDebugEnabled()) {
            log.debug("listRevokedCertInfo: Got " + revokedInCertData.size() + " entries from CertificateData and " + revokedInNoConflictData.size() + " entries from NoConflictCertificateData");
        }
        return RevokedCertInfo.mergeByDateAndStatus(revokedInCertData, revokedInNoConflictData, lastbasecrldate);
    }
    
    /**
     * Locates the most recent entry in NoConflictCertificateData for a given issuerdn/serial number combination.
     * @param issuerdn Issuer DN
     * @param serno Certificate serial number
     * @return NoConflictCertificateData entry, or null if not found. Entity is append-only, so do not modify it.
     */
    private NoConflictCertificateData findMostRecentCertData(final String issuerdn, final BigInteger serno) {
        final Collection<NoConflictCertificateData> certDatas = noConflictCertificateDataSession.findByIssuerDNSerialNumber(issuerdn, serno.toString());
        return filterMostRecentCertData(certDatas);
    }
    
    /**
     * Filters out the most recent entry in NoConflictCertificateData for a given issuerDN/serial number combination.
     * Permanent revocations always take precedence over other updates, the first one wins.
     * Otherwise, the most recent update wins.
     * @param certDatas Collection of NoConflictCertificateData to filter.
     * @param serno Certificate serial number
     * @return NoConflictCertificateData entry, or null if not found. Entity is append-only, so do not modify it.
     */
    private NoConflictCertificateData filterMostRecentCertData(final Collection<NoConflictCertificateData> certDatas) {
        if (CollectionUtils.isEmpty(certDatas)) {
            log.trace("<findMostRecentCertData(): no certificates found");
            return null;
        }
        NoConflictCertificateData mostRecentData = null;
        for (final NoConflictCertificateData data : certDatas) {
            if (mostRecentData == null) {
                mostRecentData = data;
                continue;
            }
            long timestampThis = data.getUpdateTime() != null ? data.getUpdateTime() : 0;
            long timestampRecent = mostRecentData.getUpdateTime() != null ? mostRecentData.getUpdateTime() : 0;
            if (RevokedCertInfo.isPermanentlyRevoked(data.getRevocationReason())) {
                // Permanently revoked certificate always takes precedence over non-permanently revoked one.
                // Older permanent revocations take precedence over newer ones.
                if (!RevokedCertInfo.isPermanentlyRevoked(mostRecentData.getRevocationReason()) || timestampRecent > timestampThis) {
                    mostRecentData = data;
                    continue;
                }
            }
            // Permanent revocations take precedence over temporary ones
            if (RevokedCertInfo.isPermanentlyRevoked(mostRecentData.getRevocationReason())) {
                continue;
            }
            // Otherwise, most recent status takes precedence
            if (timestampThis > timestampRecent) {
                mostRecentData = data;
            }
        }
        return mostRecentData;
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean setRevokeStatus(final AuthenticationToken admin, final CertificateDataWrapper cdw, final Date revokedDate, final int reason)
            throws CertificateRevokeException, AuthorizationDeniedException {
        if (cdw.getBaseCertificateData() instanceof NoConflictCertificateData) {
            if (entityManager.contains(cdw.getBaseCertificateData())) {
                throw new IllegalStateException("Cannot update existing row in NoConflictCertificateData. It is append-only.");
            }
        }
        return certificateStoreSession.setRevokeStatus(admin, cdw, revokedDate, reason);
    }
    
    @Override
    public boolean setStatus(final AuthenticationToken admin, final String fingerprint, final int status) throws AuthorizationDeniedException {
        if (!certificateStoreSession.setStatus(admin, fingerprint, status)) {
            // Perhaps stored in NoConflictCertificateData
            final List<NoConflictCertificateData> certDatas = noConflictCertificateDataSession.findByFingerprint(fingerprint);
            NoConflictCertificateData certData = filterMostRecentCertData(certDatas);
            if (certData != null) {
                changeStatus(admin, certData, status);
            }
        }
        return false;
    }
    
    private void changeStatus(final AuthenticationToken admin, final NoConflictCertificateData certificateData, final int status) throws AuthorizationDeniedException {
        if (log.isDebugEnabled()) {
            log.debug("Set status " + status + " for certificate with serial: " + certificateData.getSerialNumberHex());
        }

        // Must be authorized to CA in order to change status is certificates issued by the CA
        String bcdn = CertTools.stringToBCDNString(certificateData.getIssuerDN());
        int caid = bcdn.hashCode();
        authorizedToCA(admin, caid);
        
        final NoConflictCertificateData newCertData = new NoConflictCertificateData(certificateData);
        newCertData.setStatus(status);
        setUniqueIdAndUpdateTime(newCertData);
        entityManager.persist(newCertData);
        
        final String serialNo = certificateData.getSerialNumberHex();
        final String msg = intres.getLocalizedMessage("store.setstatus", certificateData.getUsername(), certificateData.getFingerprint(), status, certificateData.getSubjectDnNeverNull(), certificateData.getIssuerDN(), serialNo);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("msg", msg);
        logSession.log(EventTypes.CERT_CHANGEDSTATUS, EventStatus.SUCCESS, ModuleTypes.CERTIFICATE, ServiceTypes.CORE, admin.toString(), String.valueOf(caid), serialNo, certificateData.getUsername(), details);
    }
    
    /**
     * Returns a row in the append-only NoConflictCertificateData table, or a new row that can be added.
     * The row is initialized with the data from the most recent entry in the table,
     * or as a new unrevoked entry if non-existent.
     * @param cainfo Issuer.
     * @param certserno Certificate serial number.
     * @return New row, or copy of an existing row. Always has a fresh UUID and timestamp, so it can be appended directly.
     */
    private NoConflictCertificateData getLimitedNoConflictCertDataRow(final CAInfo cainfo, final BigInteger certserno) {
        NoConflictCertificateData certificateData = findMostRecentCertData(cainfo.getSubjectDN(), certserno);
        if (certificateData != null) {
            // Make a copy, to prevent overwrites
            certificateData = new NoConflictCertificateData(certificateData);
        } else {
            certificateData = new NoConflictCertificateData();
            fillInLimitedCertificateData(certificateData, cainfo, certserno);
        }
        setUniqueIdAndUpdateTime(certificateData);
        return certificateData;
    }
    
    private void setUniqueIdAndUpdateTime(final NoConflictCertificateData certificateData) {
        // Always generate new UUID and timestamp, so updates are stored as a new row
        certificateData.setId(UUID.randomUUID().toString());
        certificateData.setUpdateTime(System.currentTimeMillis());
    }

    /** @see org.cesecore.certificates.certificate.CertificateStoreSessionBean#updateLimitedCertificateDataStatus(AuthenticationToken, int, String, String, String, BigInteger, int, Date, int, String) */
    private void fillInLimitedCertificateData(final BaseCertificateData certificateData, final CAInfo cainfo, final BigInteger certserno) {
        final int certProfId = cainfo.getDefaultCertificateProfileId();
        certificateData.setSerialNumber(certserno.toString());
        // A fingerprint is needed by the publisher session, so we put a dummy fingerprint here
        certificateData.setFingerprint(generateDummyFingerprint(cainfo.getSubjectDN(), certserno));
        certificateData.setIssuerDN(cainfo.getSubjectDN());
        certificateData.setSubject("CN=limited");
        certificateData.setUsername(null);
        certificateData.setCertificateProfileId(certProfId);
        certificateData.setStatus(CertificateConstants.CERT_ACTIVE);
        certificateData.setRevocationReason(RevocationReasons.NOT_REVOKED.getDatabaseValue());
        certificateData.setRevocationDate(-1L);
        certificateData.setCaFingerprint(CertTools.getFingerprintAsString(cainfo.getCertificateChain().get(0)));
        certificateData.setEndEntityProfileId(-1);
        // Set expire date to the maximum possible expire date this certificate could have (now + cert profile validity) 
        final CertificateProfile certProf = certificateProfileSession.getCertificateProfile(certProfId);
        if (certProf == null) {
            log.info("Missing certificate profile ID: " + certProfId);
        } else {
            final String encodedValidity = certProf.getEncodedValidity();
            final Date expireDate = ValidityDate.getDate(encodedValidity, new Date());
            certificateData.setExpireDate(expireDate);
        }
    }
    
    @Override
    public String generateDummyFingerprint(final String issuerdn, final BigInteger certserno) {
        final byte[] fingerprintBytes = CertTools.generateSHA1Fingerprint((certserno.toString()+';'+issuerdn).getBytes(StandardCharsets.UTF_8));
        return new String(Hex.encode(fingerprintBytes));
    }

}
