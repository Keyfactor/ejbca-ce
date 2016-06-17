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
import java.util.Collection;
import java.util.Date;

import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
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

    /**
     * Constants indicating approval settings for this CA
     */
    public static final int REQ_APPROVAL_ADDEDITENDENTITY = 1;

    /**
     * Constants indicating approval settings for key recover this CA
     */
    public static final int REQ_APPROVAL_KEYRECOVER = 2;

    /**
     * Constants indicating approval settings for revocations this CA
     */
    public static final int REQ_APPROVAL_REVOCATION = 3;

    /**
     * Constants indicating approval settings for activation of CA tokens
     */
    public static final int REQ_APPROVAL_ACTIVATECA = 4;

    public static final int[] AVAILABLE_APPROVALSETTINGS = { REQ_APPROVAL_ADDEDITENDENTITY, REQ_APPROVAL_KEYRECOVER, REQ_APPROVAL_REVOCATION,
            REQ_APPROVAL_ACTIVATECA };
    public static final String[] AVAILABLE_APPROVALSETTINGS_TEXTS = { "APPROVEADDEDITENDENTITY", "APPROVEKEYRECOVER", "APPROVEREVOCATION",
            "APPROVEACTIVATECA" };

    protected String subjectdn;
    protected int caid;
    protected String name;
    /** CAConstants.CA_ACTIVE etc, 0 means not defined (i.e. not updated when editing CA) */
    protected int status = 0;
    protected long validity;
    protected Date expiretime;
    protected Date updatetime;
    /** CATYPE_X509 or CATYPE_CVC */
    protected int catype;
    /** A CAId or CAInfo.SELFSIGNED */
    protected int signedby;
    protected Collection<CertificateWrapper> certificatechain;
    protected Collection<CertificateWrapper> renewedcertificatechain;
    protected transient Collection<Certificate> certificatechainCached;
    protected transient Collection<Certificate> renewedcertificatechainCached;
    protected CAToken catoken;
    protected String description;
    protected int revocationReason;
    protected Date revocationDate;
    protected int certificateprofileid;
    /** Default value 24 hours */
    protected long crlperiod = 1 * SimpleTime.MILLISECONDS_PER_DAY;
    /** Default value 0 */
    protected long crlIssueInterval = 0;
    /** Default value 10 minutes */
    protected long crlOverlapTime = 10 * SimpleTime.MILLISECONDS_PER_MINUTE;
    /** Default value 0 = disabled */
    protected long deltacrlperiod = 0;
    protected Collection<Integer> crlpublishers;
    protected boolean finishuser;
    protected Collection<ExtendedCAServiceInfo> extendedcaserviceinfos;
    protected Collection<Integer> approvalSettings;
    protected int approvalProfile;

    protected boolean includeInHealthCheck;
    protected boolean doEnforceUniquePublicKeys;
    protected boolean doEnforceUniqueDistinguishedName;
    protected boolean doEnforceUniqueSubjectDNSerialnumber;
    protected boolean useCertReqHistory;
    protected boolean useUserStorage;
    protected boolean useCertificateStorage;

    public String getSubjectDN() {
        return subjectdn;
    }

    public void setSubjectDN(final String subjectdn) {
        this.subjectdn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
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

    public int getSignedBy() {
        return signedby;
    }

    public void setSignedBy(int signedby) {
        this.signedby = signedby;
    }

    public long getValidity() {
        return validity;
    }

    public void setValidity(long validity) {
        this.validity = validity;
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
     */
    public Collection<Certificate> getCertificateChain() {
        if (certificatechain == null) {
            return null;
        }
        if (certificatechainCached == null) {
            certificatechainCached = EJBTools.unwrapCertCollection(certificatechain);
        }
        return certificatechainCached;
    }

    public void setCertificateChain(Collection<Certificate> certificatechain) {
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

    public void setRenewedCertificateChain(Collection<Certificate> certificatechain) {
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

    public void setCertificateProfileId(int _certificateprofileid) {
        this.certificateprofileid = _certificateprofileid;
    }

    public int getCertificateProfileId() {
        return this.certificateprofileid;
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

    public void setCRLOverlapTime(long crloverlaptime) {
        this.crlOverlapTime = crloverlaptime;
    }

    public Collection<Integer> getCRLPublishers() {
        return crlpublishers;
    }

    public void setCRLPublishers(Collection<Integer> crlpublishers) {
        this.crlpublishers = crlpublishers;
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
     * Returns the ID of an approval profile 
     */
    public int getApprovalProfile() {
        return approvalProfile;
    }

    /**
     * Sets the ID of an approval profile.
     */
    public void setApprovalProfile(final int approvalProfileID) {
        this.approvalProfile = approvalProfileID;
    }
    
    
    /**
     * Returns a collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
     * action that requires approvals, default none 
     * 
     * Never null
     */
    public Collection<Integer> getApprovalSettings() {
        return approvalSettings;
    }

    /**
     * Collection of Integers (CAInfo.REQ_APPROVAL_ constants) of which
     * action that requires approvals
     */
    public void setApprovalSettings(Collection<Integer> approvalSettings) {
        this.approvalSettings = approvalSettings;
    }

    /**
     * Returns true if the action requires approvals.
     * @param action, on of the CAInfo.REQ_APPROVAL_ constants
     */
    public boolean isApprovalRequired(int action) {
        return approvalSettings.contains(Integer.valueOf(action));
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

    /**
     * @return answer this: should this CA issue certificates to only one user with certificates from one specific key.
     */
    public boolean isDoEnforceUniquePublicKeys() {
        return this.doEnforceUniquePublicKeys;
    }

    /**
     * @param doEnforceUniquePublicKeys
     */
    public void setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
        this.doEnforceUniquePublicKeys = doEnforceUniquePublicKeys;
    }

    /**
     * @return answer this: should this CA issue certificates to only one user of a specific subjectDN serialnumber.
     */
    public boolean isDoEnforceUniqueSubjectDNSerialnumber() {
        return this.doEnforceUniqueSubjectDNSerialnumber;
    }

    /**
     * @param doEnforceUniqueSubjectDNSerialnumber
     */
    public void setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSN) {
        this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSN;
    }

    /**
     * @param doEnforceUniqueDistinguishedName
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
}