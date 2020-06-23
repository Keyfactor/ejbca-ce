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
package org.cesecore.certificates.ca.ssh;

import java.security.NoSuchProviderException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.X509CAInfo.X509CAInfoBuilder;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.util.CertTools;

/**
 * @version $Id$
 *
 */
public class SshCaInfo extends CAInfo {

    private static final long serialVersionUID = 1L;
       
    private int caSerialNumberOctetSize;
    private boolean useUTF8PolicyText;
    private boolean usePrintableStringSubjectDN;
    private boolean useLdapDNOrder;
    private String subjectaltname;


    private SshCaInfo(final String encodedValidity, final CAToken catoken, final String description, final int caSerialNumberOctetSize,
            final boolean finishuser,
            final Collection<ExtendedCAServiceInfo> extendedcaserviceinfos, final boolean useUTF8PolicyText, final Map<ApprovalRequestType, Integer> approvals,
            final boolean usePrintableStringSubjectDN, final boolean useLdapDnOrder, final boolean includeInHealthCheck,
            final boolean doEnforceUniquePublicKeys, final boolean doEnforceKeyRenewal, final boolean doEnforceUniqueDistinguishedName,
            final boolean doEnforceUniqueSubjectDNSerialnumber, final boolean useCertReqHistory, final boolean useUserStorage,
            final boolean useCertificateStorage, final boolean acceptRevocationNonExistingEntry, final int defaultCertprofileId,
            final boolean useNoConflictCertificateData) {
        
        this.encodedValidity = encodedValidity;
        this.catoken = catoken;
        this.description = description;
        this.caSerialNumberOctetSize = caSerialNumberOctetSize;
        this.finishuser = finishuser;
        this.extendedcaserviceinfos = extendedcaserviceinfos;
        this.useUTF8PolicyText = useUTF8PolicyText;
        this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
        this.useLdapDNOrder = useLdapDnOrder;
        this.includeInHealthCheck = includeInHealthCheck;
        this.doEnforceUniquePublicKeys = doEnforceUniquePublicKeys;
        this.doEnforceKeyRenewal = doEnforceKeyRenewal;
        this.doEnforceUniqueDistinguishedName = doEnforceUniqueDistinguishedName;
        this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSerialnumber;
        this.useCertReqHistory = useCertReqHistory;
        this.useUserStorage = useUserStorage;
        this.useCertificateStorage = useCertificateStorage;
        this.acceptRevocationNonExistingEntry = acceptRevocationNonExistingEntry;
        this.defaultCertificateProfileId = defaultCertprofileId;
        this.useNoConflictCertificateData = useNoConflictCertificateData;
        setApprovals(approvals);
    }
    
    public int getCaSerialNumberOctetSize() {
        return caSerialNumberOctetSize;
    }

    public void setCaSerialNumberOctetSize(int caSerialNumberOctetSize) {
        this.caSerialNumberOctetSize = caSerialNumberOctetSize;
    }
    

    public boolean getUseUTF8PolicyText() {
        return useUTF8PolicyText;
    }

    public void setUseUTF8PolicyText(final boolean useUTF8PolicyText) {
        this.useUTF8PolicyText = useUTF8PolicyText;
    }
    

    public boolean getUsePrintableStringSubjectDN() {
        return usePrintableStringSubjectDN;
    }


    public void setUsePrintableStringSubjectDN(final boolean usePrintableStringSubjectDN) {
        this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
    }
    
   
    public boolean getUseLdapDnOrder() {
        return useLdapDNOrder;
    }

 
    public void setUseLdapDnOrder(final boolean useLdapDNOrder) {
        this.useLdapDNOrder = useLdapDNOrder;
    }
    

    public String getSubjectAltName() {
        return subjectaltname;
    }


    public void setSubjectAltName(final String subjectaltname) {
        this.subjectaltname = subjectaltname;
    }


    public static class SshCAInfoBuilder {
        private int caId;
        private String subjectDn;
        private String name;
        private int status;
        private int certificateProfileId;
        private String encodedValidity;
        private int signedBy;
        private Collection<Certificate> certificateChain;
        private CAToken caToken;
        private Date updateTime = new Date();
        private int defaultCertProfileId = 0;
        private boolean useNoConflictCertificateData = false;
        private Date expireTime = null;
        private int caType = CAInfo.CATYPE_SSH;
        private String description = "";
        private int caSerialNumberOctetSize = -1;
        private int revocationReason = -1;
        private Date revocationDate = null;
        private boolean finishUser = true;
        private Collection<ExtendedCAServiceInfo> extendedCaServiceInfos = new ArrayList<>();
        private boolean useUtf8PolicyText = false;
        private boolean usePrintableStringSubjectDN = false;
        private boolean includeInHealthCheck = true;
        private boolean doEnforceUniquePublicKeys = true;
        private boolean doEnforceKeyRenewal = true;
        private boolean doEnforceUniqueDistinguishedName = true;
        private boolean doEnforceUniqueSubjectDNSerialnumber = false;
        private boolean useCertReqHistory = false;
        private boolean useUserStorage = true;
        private boolean useCertificateStorage = true;
        private boolean acceptRevocationNonExistingEntry = false;
        private boolean useLdapDnOrder = true;
        private String subjectAltName = "";
        private Map<ApprovalRequestType, Integer> approvals = new HashMap<>();

        
        public SshCAInfoBuilder setCaId(int caId) {
            this.caId = caId;
            return this;
        }
        
        /**
         * @param subjectDn the Subject DN of the CA as found in the certificate
         */
        public SshCAInfoBuilder setSubjectDn(String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }

        /**
         * @param name the name of the CA shown in EJBCA, can be changed by the user
         */
        public SshCAInfoBuilder setName(String name) {
            this.name = name;
            return this;
        }

        /**
         * @param status the operational status of the CA, one of the constants in {@link CAConstants}
         */
        public SshCAInfoBuilder setStatus(int status) {
            this.status = status;
            return this;
        }

        /**
         * @param certificateProfileId the ID of the certificate profile for this CA
         */
        public SshCAInfoBuilder setCertificateProfileId(int certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
            return this;
        }

        /**
         * @param encodedValidity the validity of this CA as a human-readable string, e.g. 25y
         */
        public SshCAInfoBuilder setEncodedValidity(String encodedValidity) {
            this.encodedValidity = encodedValidity;
            return this;
        }

        /**
         * @param signedBy the id of the CA which signed this CA
         */
        public SshCAInfoBuilder setSignedBy(int signedBy) {
            this.signedBy = signedBy;
            return this;
        }

        /**
         * @param certificateChain the certificate chain containing the CA certificate of this CA
         */
        public SshCAInfoBuilder setCertificateChain(Collection<Certificate> certificateChain) {
            this.certificateChain = certificateChain;
            return this;
        }

        /**
         * @param caToken the CA token for this CA, containing e.g. a reference to the crypto token
         */
        public SshCAInfoBuilder setCaToken(CAToken caToken) {
            this.caToken = caToken;
            return this;
        }

        /**
         * @param updateTime the last time this CA was updated, normally the current date and time
         */
        public SshCAInfoBuilder setUpdateTime(Date updateTime) {
            this.updateTime = updateTime;
            return this;
        }

        /**
         * @param defaultCertProfileId the id of default cetificate profile for certificates this CA issues
         */
        public SshCAInfoBuilder setDefaultCertProfileId(int defaultCertProfileId) {
            this.defaultCertProfileId = defaultCertProfileId;
            return this;
        }

        /**
         * @param useNoConflictCertificateData should use NoConflictCertificate data table to write to
         */
        public SshCAInfoBuilder setUseNoConflictCertificateData(boolean useNoConflictCertificateData) {
            this.useNoConflictCertificateData = useNoConflictCertificateData;
            return this;
        }

        /**
         * @param expireTime the date when this CA expires
         */
        public SshCAInfoBuilder setExpireTime(Date expireTime) {
            this.expireTime = expireTime;
            return this;
        }

        /**
         * @param caType the type of CA, in this case CAInfo.CATYPE_X509
         */
        public SshCAInfoBuilder setCaType(int caType) {
            this.caType = caType;
            return this;
        }

        /**
         * @param description a text describing this CA
         */
        public SshCAInfoBuilder setDescription(String description) {
            this.description = description;
            return this;
        }

        /**
         * @param revocationReason the reason why this CA was revoked, or -1 if not revoked
         */
        public SshCAInfoBuilder setRevocationReason(int revocationReason) {
            this.revocationReason = revocationReason;
            return this;
        }

        /**
         * @param revocationDate the date of revocation, or null if not revoked
         */
        public SshCAInfoBuilder setRevocationDate(Date revocationDate) {
            this.revocationDate = revocationDate;
            return this;
        }

        public SshCAInfoBuilder setFinishUser(boolean finishUser) {
            this.finishUser = finishUser;
            return this;
        }

        public SshCAInfoBuilder setExtendedCaServiceInfos(Collection<ExtendedCAServiceInfo> extendedCaServiceInfos) {
            this.extendedCaServiceInfos = extendedCaServiceInfos;
            return this;
        }

        public SshCAInfoBuilder setUseUtf8PolicyText(boolean useUtf8PolicyText) {
            this.useUtf8PolicyText = useUtf8PolicyText;
            return this;
        }

        public SshCAInfoBuilder setUsePrintableStringSubjectDN(boolean usePrintableStringSubjectDN) {
            this.usePrintableStringSubjectDN = usePrintableStringSubjectDN;
            return this;
        }

        public SshCAInfoBuilder setUseLdapDnOrder(boolean useLdapDnOrder) {
            this.useLdapDnOrder = useLdapDnOrder;
            return this;
        }

        /**
         * @param includeInHealthCheck enable healthcheck for this CA
         */
        public SshCAInfoBuilder setIncludeInHealthCheck(boolean includeInHealthCheck) {
            this.includeInHealthCheck = includeInHealthCheck;
            return this;
        }

        public SshCAInfoBuilder setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
            this.doEnforceUniquePublicKeys = doEnforceUniquePublicKeys;
            return this;
        }

        public SshCAInfoBuilder setDoEnforceKeyRenewal(boolean doEnforceKeyRenewal) {
            this.doEnforceKeyRenewal = doEnforceKeyRenewal;
            return this;
        }

        public SshCAInfoBuilder setDoEnforceUniqueDistinguishedName(boolean doEnforceUniqueDistinguishedName) {
            this.doEnforceUniqueDistinguishedName = doEnforceUniqueDistinguishedName;
            return this;
        }

        public SshCAInfoBuilder setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSerialnumber) {
            this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSerialnumber;
            return this;
        }

        public SshCAInfoBuilder setUseCertReqHistory(boolean useCertReqHistory) {
            this.useCertReqHistory = useCertReqHistory;
            return this;
        }

        public SshCAInfoBuilder setUseUserStorage(boolean useUserStorage) {
            this.useUserStorage = useUserStorage;
            return this;
        }

        public SshCAInfoBuilder setUseCertificateStorage(boolean useCertificateStorage) {
            this.useCertificateStorage = useCertificateStorage;
            return this;
        }
        
        public SshCAInfoBuilder setSubjectAltName(final String subjectAltName) {
            this.subjectAltName = subjectAltName;
            return this;
        }

        public SshCAInfoBuilder setAcceptRevocationNonExistingEntry(boolean acceptRevocationNonExistingEntry) {
            this.acceptRevocationNonExistingEntry = acceptRevocationNonExistingEntry;
            return this;
        }
        
        /**
         * @param approvals a map of approval profiles which should be used for different operations
         */
        public SshCAInfoBuilder setApprovals(Map<ApprovalRequestType, Integer> approvals) {
            this.approvals = approvals;
            return this;
        }

        /**
         * @param caSerialNumberOctetSize serial number octet size for this CA
         */
        public SshCAInfoBuilder setCaSerialNumberOctetSize(int caSerialNumberOctetSize) {
            this.caSerialNumberOctetSize = caSerialNumberOctetSize;
            return this;
        }
        
        public SshCaInfo buildForUpdate() {
            SshCaInfo caInfo = new SshCaInfo(encodedValidity, caToken, description, caSerialNumberOctetSize, finishUser, extendedCaServiceInfos, useUtf8PolicyText, approvals, usePrintableStringSubjectDN, useLdapDnOrder,
                    includeInHealthCheck, doEnforceUniquePublicKeys, doEnforceKeyRenewal, doEnforceUniqueDistinguishedName,
                    doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage, acceptRevocationNonExistingEntry,
                    defaultCertProfileId, useNoConflictCertificateData);
            caInfo.setCAId(caId);
            return caInfo;
        }

        public SshCaInfo build() {
            SshCaInfo caInfo = new SshCaInfo(encodedValidity, caToken, description, caSerialNumberOctetSize, finishUser, extendedCaServiceInfos, useUtf8PolicyText, approvals, usePrintableStringSubjectDN, useLdapDnOrder,
                    includeInHealthCheck, doEnforceUniquePublicKeys, doEnforceKeyRenewal, doEnforceUniqueDistinguishedName,
                    doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage, acceptRevocationNonExistingEntry,
                    defaultCertProfileId, useNoConflictCertificateData);
            caInfo.setSubjectDN(subjectDn);
            caInfo.setCAId(CertTools.stringToBCDNString(caInfo.getSubjectDN()).hashCode());
            caInfo.setName(name);
            caInfo.setStatus(status);
            caInfo.setUpdateTime(updateTime);
            caInfo.setExpireTime(expireTime);
            caInfo.setCAType(caType);
            caInfo.setSignedBy(signedBy);
            caInfo.setSubjectAltName(subjectAltName);
            // Due to a bug in Glassfish v1 (fixed in v2), we used to have to make sure all certificates in this
            // Array were of Oracle's own provider, using CertTools.SYSTEM_SECURITY_PROVIDER.
            // As of EJBCA 3.9.3 we decided that we don't have to support Glassfish v1 anymore.
            try {
                if (certificateChain != null) {
                    X509Certificate[] certs = certificateChain.toArray(new X509Certificate[certificateChain.size()]);
                    List<Certificate> list = CertTools.getCertCollectionFromArray(certs, null);
                    caInfo.setCertificateChain(list);
                } else {
                    caInfo.setCertificateChain(null);
                }
            } catch (CertificateException | NoSuchProviderException e) {
                throw new IllegalArgumentException(e);
            }
            caInfo.setRevocationReason(revocationReason);
            caInfo.setRevocationDate(revocationDate);

            caInfo.setCertificateProfileId(certificateProfileId);
            return caInfo;
        }
    }

}
