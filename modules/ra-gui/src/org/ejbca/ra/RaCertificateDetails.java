/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ra;

import java.io.IOException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificatetransparency.CertificateTransparency;
import org.cesecore.certificates.certificatetransparency.CertificateTransparencyFactory;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.cert.QCStatementExtension;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.cvc.AuthorizationField;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CardVerifiableCertificate;

/** 
 * UI representation of a certificate from the back end.
 * 
 * @version $Id$
 */
public class RaCertificateDetails {
    
    public interface Callbacks {
        RaLocaleBean getRaLocaleBean();
        boolean changeStatus(RaCertificateDetails raCertificateDetails, int newStatus, int newRevocationReason) throws ApprovalException, WaitingForApprovalException;
    }
    
    private static final Logger log = Logger.getLogger(RaCertificateDetails.class);

    private final Callbacks callbacks;

    private CertificateDataWrapper cdw;
    private String fingerprint;
    private String fingerprintSha256 = "";
    private String username;
    private String type = "";
    private String typeVersion = "";
    private String serialnumber;
    private String serialnumberRaw;
    private String subjectDn;
    private String subjectAn = "";
    private String subjectDa = "";
    private Integer eepId;
    private String eepName;
    private Integer cpId;
    private String cpName;
    private String issuerDn;
    private String caName;
    private String created = "-";
    private long expireDate;
    private String expires;
    private int status;
    private int revocationReason;
    private String updated;
    private String revocationDate = "";
    private String publicKeyAlgorithm = "";
    private String publicKeySpecification = "";
    private String publicKeyParameter = "";
    private String subjectKeyId = "";
    private String basicConstraints = "";
    private String cvcAuthorizationRole = "";
    private String cvcAuthorizationAccessRights = "";
    private final List<String> keyUsages = new ArrayList<>();
    private final List<String> extendedKeyUsages = new ArrayList<>();
    private boolean hasNameConstraints = false;
    private boolean hasQcStatements = false;
    private boolean hasCertificateTransparencyScts = false;
    private String signatureAlgorithm;

    private boolean more = false;
    private int styleRowCallCounter = 0;
    
    private RaCertificateDetails next = null;
    private RaCertificateDetails previous = null;

    private int newRevocationReason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED;

    public RaCertificateDetails(final CertificateDataWrapper cdw, final Callbacks callbacks,
            final Map<Integer, String> cpIdToNameMap, final Map<Integer, String> eepIdToNameMap, final Map<String,String> caSubjectToNameMap) {
        this.callbacks = callbacks;
        reInitialize(cdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap);
    }

    public void reInitialize(final CertificateDataWrapper cdw,
            final Map<Integer, String> cpIdToNameMap, final Map<Integer, String> eepIdToNameMap, final Map<String,String> caSubjectToNameMap) {
        this.cdw = cdw;
        final CertificateData certificateData = cdw.getCertificateData();
        this.cpId = certificateData.getCertificateProfileId();
        this.cpName = cpId==null ? null : cpIdToNameMap.get(cpId);
        this.eepId = certificateData.getEndEntityProfileIdOrZero();
        this.eepName = eepIdToNameMap.get(Integer.valueOf(eepId));
        this.issuerDn = certificateData.getIssuerDN();
        this.caName = getCaNameFromIssuerDn(caSubjectToNameMap, issuerDn);
        this.status = certificateData.getStatus();
        this.revocationReason = certificateData.getRevocationReason();
        this.fingerprint = certificateData.getFingerprint();
        this.serialnumberRaw = certificateData.getSerialNumber();
        try {
            this.serialnumber = new BigInteger(this.serialnumberRaw).toString(16);
        } catch (NumberFormatException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to format serial number as hex. Probably a CVC certificate. Message: " + e.getMessage());
            }
        }
        this.username = certificateData.getUsername()==null ? "" : certificateData.getUsername();
        this.subjectDn = certificateData.getSubjectDnNeverNull();
        final Certificate certificate = cdw.getCertificate();
        byte[] certificateEncoded = null;
        if (certificate!=null) {
            try {
                certificateEncoded = certificate.getEncoded();
            } catch (CertificateEncodingException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to encode the certificate as a byte array: " + e.getMessage());
                }
            }
        }
        if (certificate!=null || certificateEncoded!=null) {
            this.type = certificate.getType();
            this.fingerprintSha256 = new String(Hex.encode(CertTools.generateSHA256Fingerprint(certificateEncoded)));
            final PublicKey publicKey = certificate.getPublicKey();
            this.publicKeyAlgorithm = AlgorithmTools.getKeyAlgorithm(publicKey);
            this.publicKeySpecification = AlgorithmTools.getKeySpecification(publicKey);
            if (publicKey instanceof RSAPublicKey) {
                this.publicKeyParameter = ((RSAPublicKey)publicKey).getModulus().toString(16);
            } else if(certificate.getPublicKey() instanceof DSAPublicKey) {
                this.publicKeyParameter = ((DSAPublicKey)publicKey).getY().toString(16);
            } else if(certificate.getPublicKey() instanceof ECPublicKey) {
                this.publicKeyParameter = ((ECPublicKey)publicKey).getW().getAffineX().toString(16) + " " + ((ECPublicKey)publicKey).getW().getAffineY().toString(16);
            }
            this.created = ValidityDate.formatAsISO8601ServerTZ(CertTools.getNotBefore(certificate).getTime(), TimeZone.getDefault());
            this.signatureAlgorithm = AlgorithmTools.getCertSignatureAlgorithmNameAsString(certificate);
            if (certificate instanceof X509Certificate) {
                final X509Certificate x509Certificate = (X509Certificate)certificate;
                this.typeVersion = Integer.toString(x509Certificate.getVersion());
                this.subjectAn = CertTools.getSubjectAlternativeName(certificate);
                try {
                    this.subjectDa = SubjectDirAttrExtension.getSubjectDirectoryAttributes(certificate);
                } catch (ParseException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to parse Subject Directory Attributes extension: " + e.getMessage());
                    }
                }
                final int basicConstraints = x509Certificate.getBasicConstraints();
                if (basicConstraints==Integer.MAX_VALUE) {
                    this.basicConstraints = "";
                } else if (basicConstraints == -1) {
                    this.basicConstraints = callbacks.getRaLocaleBean().getMessage("component_certdetails_info_basicconstraints_ee");
                } else {
                    this.basicConstraints = callbacks.getRaLocaleBean().getMessage("component_certdetails_info_basicconstraints_ca", basicConstraints);
                }
                keyUsages.clear();
                final boolean[] keyUsageArray = x509Certificate.getKeyUsage();
                for (int i=0; i<keyUsageArray.length; i++) {
                    if (keyUsageArray[i]) {
                        keyUsages.add(String.valueOf(i));
                    }
                }
                extendedKeyUsages.clear();
                try {
                    final List<String> extendedKeyUsages = x509Certificate.getExtendedKeyUsage();
                    if (extendedKeyUsages != null) {
                        this.extendedKeyUsages.addAll(extendedKeyUsages);
                    }
                } catch (CertificateParsingException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to parse Extended Key Usage extension: " + e.getMessage());
                    }
                }
                this.hasNameConstraints = x509Certificate.getExtensionValue(Extension.nameConstraints.getId())!=null;
                final CertificateTransparency ct = CertificateTransparencyFactory.getInstance();
                this.hasCertificateTransparencyScts = ct != null ? ct.hasSCTs(certificate) : false;
                this.hasQcStatements = QCStatementExtension.hasQcStatement(certificate);
            } else if (certificate instanceof CardVerifiableCertificate) {
                final CardVerifiableCertificate cardVerifiableCertificate = (CardVerifiableCertificate)certificate;
                this.typeVersion = String.valueOf(CVCertificateBody.CVC_VERSION);
                // Role and access rights
                try {
                    final AuthorizationField authorizationField = cardVerifiableCertificate.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField();
                    if (authorizationField!=null) {
                        this.cvcAuthorizationRole = String.valueOf(authorizationField.getAuthRole());
                        this.cvcAuthorizationAccessRights = String.valueOf(authorizationField.getAccessRights());
                    }
                } catch (NoSuchFieldException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to parse CVC AuthorizationTemplate's AuthorizationField: " + e.getMessage());
                    }
                }
            }
        }
        this.expireDate = certificateData.getExpireDate();
        this.expires = ValidityDate.formatAsISO8601ServerTZ(expireDate, TimeZone.getDefault());
        if (status==CertificateConstants.CERT_ARCHIVED || status==CertificateConstants.CERT_REVOKED) {
            this.updated = ValidityDate.formatAsISO8601ServerTZ(certificateData.getRevocationDate(), TimeZone.getDefault());
            this.revocationDate = ValidityDate.formatAsISO8601ServerTZ(certificateData.getRevocationDate(), TimeZone.getDefault());
        } else {
            this.updated = ValidityDate.formatAsISO8601ServerTZ(certificateData.getUpdateTime(), TimeZone.getDefault());
        }
        final String subjectKeyIdB64 = certificateData.getSubjectKeyId();
        if (subjectKeyIdB64!=null) {
            this.subjectKeyId = new String(Hex.encode(Base64.decode(subjectKeyIdB64.getBytes())));
        }
        styleRowCallCounter = 0;    // Reset
    }

    public String getFingerprint() { return fingerprint; }
    public String getFingerprintSha256() { return fingerprintSha256; }
    public String getUsername() { return username; }
    public String getType() { return type; }
    public boolean isTypeX509() { return "X.509".equals(type); }
    public boolean isTypeCvc() { return "CVC".equals(type); }
    public String getTypeVersion() { return typeVersion; }
    public String getSerialnumber() { return serialnumber; }
    public String getSerialnumberRaw() { return serialnumberRaw; }
    public String getIssuerDn() { return issuerDn; }
    public String getSubjectDn() { return subjectDn; }
    public String getSubjectAn() { return subjectAn; }
    public String getSubjectDa() { return subjectDa; }
    public String getCaName() { return caName; }
    /** @return Certificate Profile Name from the provided CP ID or a localized error String */
    public String getCpName() {
        if (cpId != null && cpId.intValue()==EndEntityInformation.NO_CERTIFICATEPROFILE) {
            return callbacks.getRaLocaleBean().getMessage("component_certdetails_info_unknowncp");
        } else if (cpName!=null) {
            return cpName;
        }
        return callbacks.getRaLocaleBean().getMessage("component_certdetails_info_missingcp", cpId);
    }
    public boolean isCpNameSameAsEepName() { return getEepName().equals(getCpName()); }
    /** @return End Entity Profile Name from the provided EEP ID or a localized error String */
    public String getEepName() {
        if (eepId==EndEntityInformation.NO_ENDENTITYPROFILE) {
            return callbacks.getRaLocaleBean().getMessage("component_certdetails_info_unknowneep");
        }
        if (eepName!=null) {
            return eepName;
        }
        return callbacks.getRaLocaleBean().getMessage("component_certdetails_info_missingeep", eepId);
    }
    public String getCreated() { return created; }
    public String getExpires() { return expires; }

    public boolean isExpired() { return expireDate<System.currentTimeMillis(); }
    public boolean isActive() {
        return status==CertificateConstants.CERT_ACTIVE || status==CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION;
    }
    public boolean isSuspended() {
        return status == CertificateConstants.CERT_REVOKED && revocationReason == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD;
    }
    
    /** @return a localized certificate (revocation) status string */
    public String getStatus() {
        switch (status) {
        case CertificateConstants.CERT_ACTIVE:
        case CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION:
            return callbacks.getRaLocaleBean().getMessage("component_certdetails_status_active");
        case CertificateConstants.CERT_ARCHIVED:
        case CertificateConstants.CERT_REVOKED:
            return callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_"+revocationReason);
        default:
            return callbacks.getRaLocaleBean().getMessage("component_certdetails_status_other");
        }
    }
    public String getUpdated() { return updated; }
    public String getRevocationDate() { return revocationDate; }
    public String getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
    public String getPublicKeySpecification() { return publicKeySpecification; }
    public String getPublicKeyParameter() { return publicKeyParameter; }
    public String getSubjectKeyId() { return subjectKeyId; }
    public String getBasicConstraints() { return basicConstraints; }
    public String getCvcAuthorizationRole() { return cvcAuthorizationRole; }
    public String getCvcAuthorizationAccessRights() { return cvcAuthorizationAccessRights; }
    public List<String> getKeyUsages() { return keyUsages; }
    public List<String> getExtendedKeyUsages() { return extendedKeyUsages; }
    public String getNameConstraints() { return hasNameConstraints ? callbacks.getRaLocaleBean().getMessage("component_certdetails_info_present") : ""; }
    public String getQcStatements() { return hasQcStatements ? callbacks.getRaLocaleBean().getMessage("component_certdetails_info_present") : ""; }
    public String getCertificateTransparencyScts() { return hasCertificateTransparencyScts ? callbacks.getRaLocaleBean().getMessage("component_certdetails_info_present") : ""; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }

    public String getDump() {
        final Certificate certificate = cdw.getCertificate();
        if (certificate!=null) {
            try {
                return CertTools.dumpCertificateAsString(certificate);
            } catch (RuntimeException e) {
                try {
                    return ASN1Dump.dumpAsString(ASN1Primitive.fromByteArray(certificate.getEncoded()));
                } catch (CertificateEncodingException | IOException e2) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to parse certificate ASN.1: " + e2.getMessage());
                    }
                }
            }
        }
        return "";
    }

    /** @return true if more details should be shown */
    public boolean isMore() { return more; }
    public void actionToggleMore() {
        more = !more;
        styleRowCallCounter = 0;    // Reset
    }

    /** @return true every twice starting with every forth call */
    public boolean isEven() {
        styleRowCallCounter++;
        return (styleRowCallCounter+1) / 2 % 2 == 0;
    }

    /** @return CA Name from the provided issuer DN or the IssuerDN itself if no name is known */
    private String getCaNameFromIssuerDn(final Map<String, String> caSubjectToNameMap, final String issuerDn) {
        if (issuerDn != null && caSubjectToNameMap.containsKey(issuerDn)) {
            return String.valueOf(caSubjectToNameMap.get(issuerDn));
        }
        return String.valueOf(issuerDn);
    }

    public RaCertificateDetails getNext() { return next; }
    public void setNext(RaCertificateDetails next) { this.next = next; }

    public RaCertificateDetails getPrevious() { return previous; }
    public void setPrevious(RaCertificateDetails previous) { this.previous = previous; }

    public List<SelectItem> getNewRevocationReasons() {
        return getNewRevocationReasons(!isSuspended());
    }

    private List<SelectItem> getNewRevocationReasons(final boolean includeOnHold) {
        final List<SelectItem> ret = new ArrayList<>();
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_0")));
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_1")));
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_CACOMPROMISE), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_2")));
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_AFFILIATIONCHANGED), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_3")));
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_SUPERSEDED), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_4")));
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_CESSATIONOFOPERATION), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_5")));
        if (includeOnHold) {
            ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_6")));
        }
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_REMOVEFROMCRL), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_8")));
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_PRIVILEGESWITHDRAWN), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_9")));
        ret.add(new SelectItem(Integer.valueOf(RevokedCertInfo.REVOCATION_REASON_AACOMPROMISE), callbacks.getRaLocaleBean().getMessage("component_certdetails_status_revoked_reason_10")));
        return ret;
    }

    public Integer getNewRevocationReason() { return Integer.valueOf(newRevocationReason); }
    public void setNewRevocationReason(final Integer newRevocationReason) { this.newRevocationReason = newRevocationReason.intValue(); }

    public void actionRevoke() {
        try {
            if (callbacks.changeStatus(this, CertificateConstants.CERT_REVOKED, newRevocationReason)) {
                callbacks.getRaLocaleBean().addMessageInfo("component_certdetails_info_revocation_successful");
            } else {
                callbacks.getRaLocaleBean().addMessageError("component_certdetails_error_revocation_failed");
            }
        } catch (ApprovalException e) {
            callbacks.getRaLocaleBean().addMessageError("component_certdetails_error_revocation_approvalrequest");
        } catch (WaitingForApprovalException e) {
            callbacks.getRaLocaleBean().addMessageInfo("component_certdetails_info_revocation_approvalrequest", e.getRequestId());
        }
        styleRowCallCounter = 0;    // Reset
    }
    public void actionReactivate() {
        try {
            if (callbacks.changeStatus(this, CertificateConstants.CERT_ACTIVE, RevokedCertInfo.NOT_REVOKED)) {
                callbacks.getRaLocaleBean().addMessageInfo("component_certdetails_info_reactivation_successful");
            } else {
                callbacks.getRaLocaleBean().addMessageError("component_certdetails_error_reactivation_failed");
            }
        } catch (ApprovalException e) {
            callbacks.getRaLocaleBean().addMessageError("component_certdetails_error_reactivation_approvalrequest");
        } catch (WaitingForApprovalException e) {
            callbacks.getRaLocaleBean().addMessageInfo("component_certdetails_info_reactivation_approvalrequest", e.getRequestId());
        }
        styleRowCallCounter = 0;    // Reset
    }
}
