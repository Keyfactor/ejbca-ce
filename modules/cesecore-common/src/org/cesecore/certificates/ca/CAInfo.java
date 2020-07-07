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
package org.cesecore.certificates.ca;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.math.IntRange;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.ssh.SshCa;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;

/**
 * Holds non sensitive information about a CA.
 *
 * @version $Id$
 */
public abstract class CAInfo implements Serializable {

    private static final long serialVersionUID = 2L;
    public static final int CATYPE_X509 = 1;
    public static final int CATYPE_CVC = 2;
    public static final int CATYPE_SSH = 3;

    /**
     * Constants indicating that the CA is selfsigned.
     */
    public static final int SELFSIGNED = 1;
    /**
     * Constant indicating that the CA is signed by an external CA.
     */
    public static final int SIGNEDBYEXTERNALCA = 2;

    /**
     * Constant indicating where the special caid border is. All CAs with CA id not below this value
     * should be created
     */
    public static final int SPECIALCAIDBORDER = 10;

    protected String subjectdn;
    protected int caid;
    protected String name;
    /** CAConstants.CA_ACTIVE etc, 0 means not defined (i.e. not updated when editing CA) */
    protected int status = 0;
    protected String encodedValidity;
    protected Date expiretime;
    protected Date updatetime;
    /** CATYPE_X509 or CATYPE_CVC */
    protected int catype;
    /** A CAId or CAInfo.SELFSIGNED */
    protected int signedby;
    protected Collection<CertificateWrapper> certificatechain;
    protected Collection<CertificateWrapper> renewedcertificatechain;
    protected transient List<Certificate> certificatechainCached;
    protected transient Collection<Certificate> renewedcertificatechainCached;
    protected CAToken catoken;
    protected String description;
    protected int revocationReason;
    protected Date revocationDate;
    protected int certificateprofileid;
    protected int defaultCertificateProfileId;
    /** Default value 1 day */
    protected long crlperiod = 1 * SimpleTime.MILLISECONDS_PER_DAY;
    /** Default value 0 */
    protected long crlIssueInterval = 0;
    /** Default value 10 minutes */
    protected long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_MINUTE;
    /** Default value 0 = disabled */
    protected long deltacrlperiod = 0;
    protected Collection<Integer> crlpublishers;
    protected Collection<Integer> validators;
    protected boolean keepExpiredCertsOnCRL = false;
    protected boolean finishuser;
    protected Collection<ExtendedCAServiceInfo> extendedcaserviceinfos;
    protected boolean useNoConflictCertificateData = false; // By Default we use normal certificate data table.

    /**
     * @deprecated since 6.8.0, where approval settings and profiles became interlinked.
     */
    @Deprecated
    private Collection<Integer> approvalSettings;
    /**
     * @deprecated since 6.8.0, where approval settings and profiles became interlinked.
     */
    @Deprecated
    private int approvalProfile;

    /**
     * @deprecated since 6.6.0, use the appropriate approval profile instead
     * Needed for a while in order to be able to import old statedumps from 6.5 and earlier
     */
    @Deprecated
    protected int numOfReqApprovals;

    private LinkedHashMap<ApprovalRequestType, Integer> approvals;


    protected boolean includeInHealthCheck;
    protected boolean doEnforceUniquePublicKeys;
    protected boolean doEnforceKeyRenewal;
    protected boolean doEnforceUniqueDistinguishedName;
    protected boolean doEnforceUniqueSubjectDNSerialnumber;
    protected boolean useCertReqHistory;
    protected boolean useUserStorage;
    protected boolean useCertificateStorage;
    protected boolean acceptRevocationNonExistingEntry;

    /**
     * Returns the Subject DN of the CA, that will be used for issuing the CA certificate.
     * To get the Subject DN of the latest issued CA certificate, use {@link #getLatestSubjectDN}
     */
    public String getSubjectDN() {
        return subjectdn;
    }

    public void setSubjectDN(final String subjectDn) {
        this.subjectdn = CertTools.stringToBCDNString(StringTools.strip(subjectDn));
    }

    /**
     * Use issuer DN from the latest CA certificate. Might differ from the value from {@link #getSubjectDN}.
     */
    public String getLatestSubjectDN() {
        final Collection<Certificate> certs = getCertificateChain();
        final Certificate cacert = !certs.isEmpty() ? certs.iterator().next(): null;
        return cacert != null ? CertTools.getSubjectDN(cacert) : null;
    }

    public int getCAId() {
        return this.caid;
    }

    public void setCAId(final int caid) {
        this.caid = caid;
    }

    public String getName() {
        return this.name;
    }

    public void setName(final String name) {
        this.name = name;
    }

    /** CAConstants.CA_ACTIVE etc, 0 means not defined (i.e. not updated when editing CA) */
    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    /** CAInfo.CATYPE_X509 or CAInfo.CATYPE_CVC */
    public int getCAType() {
        return catype;
    }

    public void setCAType(int catype) {
        this.catype = catype;
    }

    public String getCaTypeAsString() {
        if (catype == CAInfo.CATYPE_CVC) {
            return "CVC";
        }
        if (catype == CAInfo.CATYPE_X509) {
            return "X.509";
        }
        if (catype == CAInfo.CATYPE_SSH) {
            return SshCa.CA_TYPE;
        }
        return String.valueOf(catype);
    }

    /**
     * @return A CAId or CAInfo.SELFSIGNED, CAInfo.SIGNEDBYEXTERNALCA etc
     */
    public int getSignedBy() {
        return signedby;
    }

    public void setSignedBy(int signedby) {
        this.signedby = signedby;
    }

    /** Returns true if the CA has a CA token. Used by Configdump */
    public boolean hasCaToken() {
        return status != CAConstants.CA_EXTERNAL;
    }

    public void setEncodedValidity(String encodedValidity) {
        this.encodedValidity = encodedValidity;
    }

    public String getEncodedValidity() {
        return encodedValidity;
    }

    public Date getExpireTime() {
        return this.expiretime;
    }

    public void setExpireTime(final Date expiretime) {
        this.expiretime = expiretime;
    }

    public Date getUpdateTime() {
        return this.updatetime;
    }

    public void setUpdateTime(final Date updatetime) {
        this.updatetime = updatetime;
    }

    /** Retrieves the certificate chain for the CA. The returned certificate chain MUST have the
     * RootCA certificate in the last position and the CAs certificate in the first.
     *
     * @return List of certificates, or null if no certificate chain exists for this CA
     */
    public List<Certificate> getCertificateChain() {
        if (certificatechain == null) {
            return null;
        }
        if (certificatechainCached == null) {
            certificatechainCached = EJBTools.unwrapCertCollection(certificatechain);
        }
        return certificatechainCached;
    }

    public void setCertificateChain(List<Certificate> certificatechain) {
        this.certificatechainCached = certificatechain;
        this.certificatechain = EJBTools.wrapCertCollection(certificatechain);
    }

    public Collection<Certificate> getRenewedCertificateChain() {
        if (renewedcertificatechain == null) {
            return null;
        }
        if (renewedcertificatechainCached == null) {
            renewedcertificatechainCached = EJBTools.unwrapCertCollection(renewedcertificatechain);
        }
        return renewedcertificatechainCached;
    }

    void setRenewedCertificateChain(Collection<Certificate> certificatechain) {
        this.renewedcertificatechainCached = certificatechain;
        this.renewedcertificatechain = EJBTools.wrapCertCollection(certificatechain);
    }

    public CAToken getCAToken() {
        return this.catoken;
    }

    public void setCAToken(CAToken catoken) {
        this.catoken = catoken;
    }

    public String getDescription() {
        return this.description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public int getRevocationReason() {
        return this.revocationReason;
    }

    public void setRevocationReason(final int revocationReason) {
        this.revocationReason = revocationReason;
    }

    public Date getRevocationDate() {
        return this.revocationDate;
    }

    public void setRevocationDate(final Date revocationDate) {
        this.revocationDate = revocationDate;
    }

    public void setCertificateProfileId(int certificateProfileId) {
        this.certificateprofileid = certificateProfileId;
    }

    /** @return  the ID of the certificate profile for this CA    */
    public int getCertificateProfileId() {
        return this.certificateprofileid;
    }

    /** @return  the id of default cetificate profile for certificates this CA issues    */
    public int getDefaultCertificateProfileId() {
        return defaultCertificateProfileId;
    }

    public void setDefaultCertificateProfileId(int defaultCertificateProfileId) {
        this.defaultCertificateProfileId = defaultCertificateProfileId;
    }

    public long getCRLPeriod() {
        return crlperiod;
    }

    public void setCRLPeriod(long crlperiod) {
        this.crlperiod = crlperiod;
    }

    public long getDeltaCRLPeriod() {
        return deltacrlperiod;
    }

    public void setDeltaCRLPeriod(long deltacrlperiod) {
        this.deltacrlperiod = deltacrlperiod;
    }

    public long getCRLIssueInterval() {
        return crlIssueInterval;
    }

    public void setCRLIssueInterval(long crlissueinterval) {
        this.crlIssueInterval = crlissueinterval;
    }

    public long getCRLOverlapTime() {
        return crlOverlapTime;
    }

    public void setCRLOverlapTime(long crlOverlapTime) {
        this.crlOverlapTime = crlOverlapTime;
    }

    public Collection<Integer> getCRLPublishers() {
        return crlpublishers;
    }

    public void setCRLPublishers(Collection<Integer> crlpublishers) {
        this.crlpublishers = crlpublishers;
    }

    public Collection<Integer> getValidators() {
        if (validators == null) {
        	// Make sure we never return null for upgraded CAs, avoiding possible NPE
            return new ArrayList<>();
        }
        return validators;
    }

    public void setValidators(Collection<Integer> validators) {
        this.validators = validators;
    }

    public boolean getKeepExpiredCertsOnCRL() {
        return this.keepExpiredCertsOnCRL;
    }
    public void setKeepExpiredCertsOnCRL(boolean keepExpiredCertsOnCRL) {
        this.keepExpiredCertsOnCRL = keepExpiredCertsOnCRL;
    }

    public boolean getFinishUser() {
        return finishuser;
    }

    public void setFinishUser(boolean finishuser) {
        this.finishuser = finishuser;
    }

    public boolean getIncludeInHealthCheck() {
        return this.includeInHealthCheck;
    }

    public void setIncludeInHealthCheck(boolean includeInHealthCheck) {
        this.includeInHealthCheck = includeInHealthCheck;
    }

    /** Lists the extended CA services.
     *
     * @return Collection of ExtendedCAServiceInfo
     */
    public Collection<ExtendedCAServiceInfo> getExtendedCAServiceInfos() {
        return this.extendedcaserviceinfos;
    }

    public void setExtendedCAServiceInfos(Collection<ExtendedCAServiceInfo> extendedcaserviceinfos) {
        this.extendedcaserviceinfos = extendedcaserviceinfos;
    }

    /**
     *
     * @return a map of approvals, mapped as approval setting (as defined in this class) : approval profile ID. Never returns null.
     */
    public Map<ApprovalRequestType, Integer> getApprovals() {
        return approvals;
    }

    public void setApprovals(Map<ApprovalRequestType, Integer> approvals) {
        if(approvals == null) {
            approvals = new LinkedHashMap<>();
        }
        this.approvals = new LinkedHashMap<>(approvals);
    }

    /**
     * Returns the ID of an approval profile
     *
     * @deprecated since 6.8.0. Use getApprovals() instead;
     */
    @Deprecated
    public int getApprovalProfile() {
        return approvalProfile;
    }

    /**
     * Sets the ID of an approval profile.
     *
     * @deprecated since 6.8.0. Use setApprovals() instead;
     */
    @Deprecated
    public void setApprovalProfile(final int approvalProfileID) {
        this.approvalProfile = approvalProfileID;
    }


    /**
     * Returns a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
     * action that requires approvals, default none
     *
     * Never null
     *
     * @deprecated since 6.8.0. Use getApprovals() instead;
     */
    @Deprecated
    public Collection<Integer> getApprovalSettings() {
        return approvalSettings;
    }

    /**
     * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
     * action that requires approvals
     *
     * @deprecated since 6.8.0. Use getApprovals() instead;
     */
    @Deprecated
    public void setApprovalSettings(Collection<Integer> approvalSettings) {
        this.approvalSettings = approvalSettings;
    }

    /**
     * @return true if the NoConflictCertificateData used.
     */
    public boolean isUseNoConflictCertificateData() {
        return this.useNoConflictCertificateData;
    }

    /**
     * @param useNoConflictCertificateData true means that the NoConflictCertificateData will be used instead of CertificateData.
     */
    public void setUseNoConflictCertificateData(final boolean useNoConflictCertificateData) {
        this.useNoConflictCertificateData = useNoConflictCertificateData;
    }

    /**
     * @return true if the UserData used to issue a certificate should be kept in the database.
     */
    public boolean isUseCertReqHistory() {
        return this.useCertReqHistory;
    }

    /**
     * @param useCertReqHistory true means that the UserData used at the time of certificate issuance should be kept in the database.
     */
    public void setUseCertReqHistory(boolean useCertReqHistory) {
        this.useCertReqHistory = useCertReqHistory;
    }

    /** @return true if the UserData used to issue a certificate should be kept in the database. */
    public boolean isUseUserStorage() {
        return this.useUserStorage;
    }

    /** @param useUserStorage true means that the latest UserData used to issue a certificate should be kept in the database. */
    public void setUseUserStorage(boolean useUserStorage) {
        this.useUserStorage = useUserStorage;
    }

    /** @return true if the issued certificate should be kept in the database. */
    public boolean isUseCertificateStorage() {
        return this.useCertificateStorage;
    }

    /** @param useCertificateStorage true means that the issued certificate should be kept in the database. */
    public void setUseCertificateStorage(boolean useCertificateStorage) {
        this.useCertificateStorage = useCertificateStorage;
    }

    /** @return true if revocation for non existing entries is accepted */
    public boolean isAcceptRevocationNonExistingEntry() {
        return acceptRevocationNonExistingEntry;
    }

    /** @param acceptRevocationNonExistingEntry true means that revocation for non existing entry is accepted. */
    public void setAcceptRevocationNonExistingEntry(boolean acceptRevocationNonExistingEntry) {
        this.acceptRevocationNonExistingEntry = acceptRevocationNonExistingEntry;
    }

    /**
     * @return answer this: should this CA issue certificates to only one user with certificates from one specific key.
     */
    public boolean isDoEnforceUniquePublicKeys() {
        return this.doEnforceUniquePublicKeys;
    }

    /**
     * @param doEnforceUniquePublicKeys enforce unique public keys flag.
     */
    public void setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
        this.doEnforceUniquePublicKeys = doEnforceUniquePublicKeys;
    }

    public boolean isDoEnforceKeyRenewal() {
        return doEnforceKeyRenewal;
    }

    public void setDoEnforceKeyRenewal(boolean doEnforceKeyRenewal) {
        this.doEnforceKeyRenewal = doEnforceKeyRenewal;
    }

    /**
     * @return answer this: should this CA issue certificates to only one user of a specific subjectDN serialnumber.
     */
    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return this.doEnforceUniqueSubjectDNSerialnumber;
    }

    /**
     * @param doEnforceUniqueSubjectDNSN enforce unique Subject DNSN flag.
     */
    public void setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSN) {
        this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSN;
    }

    /**
     * @param doEnforceUniqueDistinguishedName enforce unique DN flag.
     */
    public void setDoEnforceUniqueDistinguishedName(boolean doEnforceUniqueDistinguishedName) {
        this.doEnforceUniqueDistinguishedName = doEnforceUniqueDistinguishedName;
    }

    /**
     * @return answer this: should this CA issue certificates to only one user with certificates with a specific subject DN.
     */
    public boolean isDoEnforceUniqueDistinguishedName() {
        return this.doEnforceUniqueDistinguishedName;
    }

    /**
     * Determines which CRL Partition Index a given certificate belongs to. This check is based on the URI in the CRL Distribution Point extension.
     * @param cert Certificate
     * @return Partition number, or {@link CertificateConstants#NO_CRL_PARTITION} if partitioning is not enabled / not applicable.
     */
    public int determineCrlPartitionIndex(final Certificate cert) {
        // Overridden in X509CAInfo
        return CertificateConstants.NO_CRL_PARTITION;
    }

    /**
     * Determines which CRL Partition Index a given CRL belongs to. This check is based on the URI in the Issuing Distribution Point extension.
     * @param crl CRL
     * @return Partition number, or {@link CertificateConstants#NO_CRL_PARTITION} if partitioning is not enabled / not applicable.
     */
    public int determineCrlPartitionIndex(final X509CRL crl) {
        // Overridden in X509CAInfo
        return CertificateConstants.NO_CRL_PARTITION;
    }

    /**
     * Returns the CRL partitions' indexes for a given CA, or null if the CRL is not partitioned or the CA type does not support CRLs (e.g. CVC CA).
     * This includes suspended partitions, suspended partitions will just not have new certificates assigned to them.
     */
    public IntRange getAllCrlPartitionIndexes() {
        return null;
    }
}
