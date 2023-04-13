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
package org.cesecore.certificates.ca;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.certificate.ca.its.region.ItsGeographicRegion;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;

public class CitsCaInfo extends CAInfo {
    
    private static final long serialVersionUID = -2024462945820076720L;
    
    private String certificateId;
    private ItsGeographicRegion region;
    
    private String hexEncodedCert;
    private String hexEncodedCertHash;
        
    public static final String CERTIFICATE_ID = "certificateid";
    public static final String GEOGRAPHIC_REGION = "geographicregion";
    public static final String ITS_CA_CERTIFICATE = "itscacert";
    public static final String ECA_CERT_HASH = "ecacerthash";

    /**
     * To be used when creating a CA. This constructor creates a CITS CA with defaults values for the parameters
     * not specified.
     */
    public static CitsCaInfo getDefaultCitsCaInfo(final String name, final String description, final String encodedValidity, final String certificateId, final int certificateProfileId, final int defaultCertProfileId, final CAToken caToken) {
        CitsCaInfoBuilder builder = new CitsCaInfoBuilder().setName(name)
                                                           .setDescription(description)
                                                           .setEncodedValidity(encodedValidity)
                                                           .setCertificateId(certificateId)
                                                           .setCertificateProfileId(certificateProfileId)
                                                           .setDefaultCertProfileId(defaultCertProfileId)
                                                           .setStatus(CAConstants.CA_WAITING_CERTIFICATE_RESPONSE)
                                                           .setAcceptRevocationNonExistingEntry(true)
                                                           .setUpdateTime(new Date())
                                                           .setExpireTime(null)
                                                           .setCertificateChain(null) // TODO: To be added after clarification
                                                           .setCaToken(caToken)
                                                           .setExtendedCAServiceInfos(new ArrayList<>())
                                                           .setValidators(new ArrayList<>())
                                                           .setFinishUser(true)
                                                           .setUseNoConflictCertificateData(false)
                                                           .setIncludeInHealthCheck(true)
                                                           .setDoEnforceUniquePublicKeys(true)
                                                           .setDoEnforceKeyRenewal(false)
                                                           .setDoEnforceUniqueDistinguishedName(true)
                                                           .setDoEnforceUniqueSubjectDNSerialnumber(false)
                                                           .setUseCertReqHistory(false)
                                                           .setUseUserStorage(true)
                                                           .setUseCertificateStorage(true)
                                                           .setCaType(CAInfo.CATYPE_CITS)
                                                           .setSignedBy(CAInfo.SIGNEDBYEXTERNALCA)
                                                           .setApprovals(new HashMap<>())
                                                           .setRegion(null);// To allow absent region field

        return builder.build();
    }

    private CitsCaInfo(final String name, final String description, final String encodedValidity, final String certificateId, final int status, final boolean acceptRevocationNonExistingEntry,
                       final List<Certificate> certificateChain, final CAToken caToken, final List<ExtendedCAServiceInfo> extendedCAServiceInfos, List<Integer> validators, final boolean finishUser,
                       final boolean useNoConflictCertificateData, final boolean includeInHealthCheck, final boolean doEnforceUniquePublicKeys, final boolean doEnforceKeyRenewal, final boolean doEnforceUniqueDistinguishedName,
                       final boolean doEnforceUniqueSubjectDNSerialnumber, final boolean useCertReqHistory, final boolean useUserStorage, final boolean useCertificateStorage) {

        setName(name);
        setDescription(description);
        setEncodedValidity(encodedValidity);
        setCertificateId(certificateId);
        setStatus(status);
        setAcceptRevocationNonExistingEntry(acceptRevocationNonExistingEntry);
        setCertificateChain(certificateChain);
        setCAToken(caToken);
        setExtendedCAServiceInfos(extendedCAServiceInfos);
        setValidators(validators);
        setFinishUser(finishUser);
        setUseNoConflictCertificateData(useNoConflictCertificateData);
        setIncludeInHealthCheck(includeInHealthCheck);
        setDoEnforceUniquePublicKeys(doEnforceUniquePublicKeys);
        setDoEnforceKeyRenewal(doEnforceKeyRenewal);
        setDoEnforceUniqueDistinguishedName(doEnforceUniqueDistinguishedName);
        setDoEnforceUniqueSubjectDNSerialnumber(doEnforceUniqueSubjectDNSerialnumber);
        setUseCertReqHistory(useCertReqHistory);
        setUseUserStorage(useUserStorage);
        setUseCertificateStorage(useCertificateStorage);

        /**
         * TODO: Remove after confirmation/clarification
         * Following fields from CaInfo were not included:
         *  revocationReason;
         *  revocationDate;
         *  acceptRevocationNonExistingEntry;
         *
         *  crlperiod;
         *  crlIssueInterval;
         *  crlOverlapTime;
         *  deltacrlperiod;
         *  generateCrlUponRevocation;
         *  crlpublishers;
         *  keepExpiredCertsOnCRL;
         *
         */


        // Some default or to be implemented values.
        setCAType(CATYPE_CITS);
        setSignedBy(CAInfo.SIGNEDBYEXTERNALCA);
        setApprovals(new HashMap<>()); // TODO: To be implemented later.
    }

    public CitsCaInfo() {
    }

    @Override
    public boolean isExpirationInclusive() {
        return false;
    }

    public String getCertificateId() {
        return certificateId;
    }

    public void setCertificateId(String certificateId) {
        this.subjectdn = CITS_SUBJECTDN_PREFIX + certificateId;
        this.caid = this.subjectdn.hashCode();
        this.certificateId = certificateId;
    }

    public ItsGeographicRegion getRegion() {
        return region;
    }

    public void setRegion(ItsGeographicRegion region) {
        this.region = region;
    }

    public String getHexEncodedCertHash() {
        return hexEncodedCertHash;
    }

    public void setHexEncodedCertHash(String hexEncodedCertHash) {
        this.hexEncodedCertHash = hexEncodedCertHash;
    }
    
    public String getHexEncodedCert() {
        return hexEncodedCert;
    }

    public void setHexEncodedCert(String hexEncodedCert) {
        this.hexEncodedCert = hexEncodedCert;
    }

    public static class CitsCaInfoBuilder {
        // Common Field from CAINFO.
        private int caId;
        private String name;
        private String description = "";
        private int status;
        private int certificateProfileId;
        private int defaultCertProfileId;
        private String encodedValidity;
        private int caType;
        private int signedBy;
        private boolean acceptRevocationNonExistingEntry;
        private Date updateTime;
        private Date expireTime;
        private List<Certificate> certificateChain;
        private CAToken caToken;
        private Map<ApprovalRequestType, Integer> approvals = new HashMap<>();
        private List<ExtendedCAServiceInfo> extendedCAServiceInfos = new ArrayList<>();
        private List<Integer> validators = new ArrayList<>();
        private boolean finishUser;
        private boolean useNoConflictCertificateData;
        private boolean includeInHealthCheck;
        private boolean doEnforceUniquePublicKeys;
        private boolean doEnforceKeyRenewal;
        private boolean doEnforceUniqueDistinguishedName;
        private boolean doEnforceUniqueSubjectDNSerialnumber;
        private boolean useCertReqHistory;
        private boolean useUserStorage;
        private boolean useCertificateStorage;
        
        // CITS Specific Fields
        private String certificateId;
        private ItsGeographicRegion region;
        private String subjectDN; // Built based on certificateID (prefix + certificateId)
        private String hexEncodedCert;
        private String hexEncodedCertHash;

        public CitsCaInfoBuilder setCaId(int caId) {
            this.caId = caId;
            return this;
        }

        /**
         * @param name the name of the CA shown in EJBCA, can be changed by the user
         */
        public CitsCaInfoBuilder setName(String name) {
            this.name = name;
            return this;
        }

        public CitsCaInfoBuilder setDescription(String description) {
            this.description = description;
            return this;
        }

        /**
         * @param status the operational status of the CA, one of the constants in {@link CAConstants}
         */
        public CitsCaInfoBuilder setStatus(int status) {
            this.status = status;
            return this;
        }

        public CitsCaInfoBuilder setCertificateProfileId(int certificateProfileId) {
            this.certificateProfileId = certificateProfileId;
            return this;
        }

        public CitsCaInfoBuilder setDefaultCertProfileId(int defaultCertProfileId) {
            this.defaultCertProfileId = defaultCertProfileId;
            return this;
        }

        /**
         * @param encodedValidity the validity of this CA as a human-readable string, e.g. 25y
         */
        public CitsCaInfoBuilder setEncodedValidity(String encodedValidity) {
            this.encodedValidity = encodedValidity;
            return this;
        }
        /**
         * @param caType the type of CA, in this case CAInfo.CATYPE_CITS
         */
        public CitsCaInfoBuilder setCaType(int caType) {
            this.caType = caType;
            return this;
        }

        /**
         * @param signedBy the id of the CA which signed this CA. Can be CAInfo.SIGNEDBYEXTERNALCA
         */
        public CitsCaInfoBuilder setSignedBy(int signedBy) {
            this.signedBy = signedBy;
            return this;
        }

        public CitsCaInfoBuilder setAcceptRevocationNonExistingEntry(boolean acceptRevocationNonExistingEntry) {
            this.acceptRevocationNonExistingEntry = acceptRevocationNonExistingEntry;
            return this;
        }


        public CitsCaInfoBuilder setUpdateTime(Date updateTime) {
            this.updateTime = updateTime;
            return this;
        }

        public CitsCaInfoBuilder setExpireTime(Date expireTime) {
            this.expireTime = expireTime;
            return this;
        }

        public CitsCaInfoBuilder setCertificateChain(List<Certificate> certificateChain) {
            this.certificateChain = certificateChain;
            return this;
        }

        public CitsCaInfoBuilder setCaToken(CAToken caToken) {
            this.caToken = caToken;
            return this;
        }

        public CitsCaInfoBuilder setApprovals(Map<ApprovalRequestType, Integer> approvals) {
            this.approvals = approvals;
            return this;
        }

        public CitsCaInfoBuilder setExtendedCAServiceInfos(List<ExtendedCAServiceInfo> extendedCAServiceInfos) {
            this.extendedCAServiceInfos = extendedCAServiceInfos;
            return this;
        }

        public CitsCaInfoBuilder setValidators(List<Integer> validators) {
            this.validators = validators;
            return this;
        }

        public CitsCaInfoBuilder setFinishUser(boolean finishUser) {
            this.finishUser = finishUser;
            return this;
        }

        public CitsCaInfoBuilder setUseNoConflictCertificateData(boolean useNoConflictCertificateData) {
            this.useNoConflictCertificateData = useNoConflictCertificateData;
            return this;
        }

        public CitsCaInfoBuilder setIncludeInHealthCheck(boolean includeInHealthCheck) {
            this.includeInHealthCheck = includeInHealthCheck;
            return this;
        }

        public CitsCaInfoBuilder setDoEnforceUniquePublicKeys(boolean doEnforceUniquePublicKeys) {
            this.doEnforceUniquePublicKeys = doEnforceUniquePublicKeys;
            return this;
        }

        public CitsCaInfoBuilder setDoEnforceKeyRenewal(boolean doEnforceKeyRenewal) {
            this.doEnforceKeyRenewal = doEnforceKeyRenewal;
            return this;
        }

        public CitsCaInfoBuilder setDoEnforceUniqueDistinguishedName(boolean doEnforceUniqueDistinguishedName) {
            this.doEnforceUniqueDistinguishedName = doEnforceUniqueDistinguishedName;
            return this;
        }

        public CitsCaInfoBuilder setDoEnforceUniqueSubjectDNSerialnumber(boolean doEnforceUniqueSubjectDNSerialnumber) {
            this.doEnforceUniqueSubjectDNSerialnumber = doEnforceUniqueSubjectDNSerialnumber;
            return this;
        }

        public CitsCaInfoBuilder setUseCertReqHistory(boolean useCertReqHistory) {
            this.useCertReqHistory = useCertReqHistory;
            return this;
        }

        public CitsCaInfoBuilder setUseUserStorage(boolean useUserStorage) {
            this.useUserStorage = useUserStorage;
            return this;
        }

        public CitsCaInfoBuilder setUseCertificateStorage(boolean useCertificateStorage) {
            this.useCertificateStorage = useCertificateStorage;
            return this;
        }
        
        /**
         * @param certificateId CITS specific field. Unique identifier for the CA.
         */
        public CitsCaInfoBuilder setCertificateId(String certificateId) {
            this.certificateId = certificateId;
            this.subjectDN = CITS_SUBJECTDN_PREFIX + certificateId;
            return this;
        }

        /**
         * @param region ITS define GeographicRegion. If null, it's considered global.
         */
        public CitsCaInfoBuilder setRegion(String region) {
            this.region = ItsGeographicRegion.fromString(region);
            return this;
        }

        public CitsCaInfo build() {
            CitsCaInfo caInfo = new CitsCaInfo(name, description, encodedValidity, certificateId, status, acceptRevocationNonExistingEntry,
                                               certificateChain, caToken, extendedCAServiceInfos, validators, finishUser,
                                               useNoConflictCertificateData, includeInHealthCheck, doEnforceUniquePublicKeys, doEnforceKeyRenewal, doEnforceUniqueDistinguishedName,
                                               doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage);

            // May be done differently
            caInfo.setCAId(subjectDN.hashCode());
            caInfo.setUpdateTime(updateTime);

            // This fields are usually not updated in UI, only needed when creating
            // a new CA. They are not included in buildForUpdate() method below.
            caInfo.setStatus(status);
            caInfo.setCAType(caType);
            caInfo.setSignedBy(signedBy);
            caInfo.setExpireTime(expireTime);

            try {
                if (certificateChain != null) {
                    // TODO: Certificate chain
                }
            } catch (Exception e) {
                throw new IllegalArgumentException(e);
            }

            caInfo.setCertificateProfileId(certificateProfileId);
            caInfo.setDefaultCertificateProfileId(defaultCertProfileId);
            caInfo.setRegion(region);
            return caInfo;
        }

        public CitsCaInfo buildForUpdate() {
            CitsCaInfo caInfo = new CitsCaInfo(name, description, encodedValidity, certificateId, status, acceptRevocationNonExistingEntry,
                                               certificateChain, caToken, extendedCAServiceInfos, validators, finishUser,
                                               useNoConflictCertificateData, includeInHealthCheck, doEnforceUniquePublicKeys, doEnforceKeyRenewal, doEnforceUniqueDistinguishedName,
                                               doEnforceUniqueSubjectDNSerialnumber, useCertReqHistory, useUserStorage, useCertificateStorage);

            // May be done differently
            caInfo.setCAId(caId);
            caInfo.setUpdateTime(new Date());
            caInfo.setRegion(region);            
            return caInfo;
        }

    }
    
}
