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

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.cvc.AuthorizationField;
import org.ejbca.cvc.CVCertificateBody;
import org.ejbca.cvc.CardVerifiableCertificate;

/** 
 * UI representation of a certificate from the back end.
 */
public class RaCertificateDetails {
    
    private static final Logger log = Logger.getLogger(RaCertificateDetails.class);

    private final CertificateDataWrapper cdw;
    private final String fingerprint;
    private final String fingerprintSha256;
    private final String username;
    private final String type;
    private final String typeVersion;
    private final String serialnumber;
    private final String serialnumberRaw;
    private final String subjectDn;
    private final String subjectAn;
    private final String subjectDa;
    private final Integer eepId;
    private final String eepName;
    private final Integer cpId;
    private final String cpName;
    private final String issuerDn;
    private final String caName;
    private final String created;
    private final String expires;
    private final int status;
    private final String statusString;
    private final int revocationReason;
    private String updated;
    private final String publicKeyAlgorithm;
    private final String publicKeySpecification;
    private final String publicKeyModulus;
    private final String subjectKeyId;
    private final String basicConstraints;
    private final String cvcAuthorizationRole;
    private final String cvcAuthorizationAccessRights;
    private final String keyUsage;
    private final String extendedKeyUsage;
    private final String nameConstraints;
    private final String qcStatements;
    private final String certificateTransparencyScts;
    private final String signatureAlgorithm;

    public static RaCertificateDetails create(final CertificateDataWrapper cdw, final RaLocaleBean raLocaleBean, final Map<Integer, String> cpIdToNameMap,
            final Map<Integer, String> eepIdToNameMap, final Map<String,String> caSubjectToNameMap) {
        final Integer cpId = cdw.getCertificateData().getCertificateProfileId();
        final String cpName;
        if (cpId != null && cpId.intValue()==EndEntityInformation.NO_CERTIFICATEPROFILE) {
            cpName = raLocaleBean.getMessage("search_certs_page_info_unknowncp");
        } else if (cpId != null && cpIdToNameMap!=null && cpIdToNameMap.containsKey(cpId)) {
            cpName = String.valueOf(cpIdToNameMap.get(cpId));
        } else {
            cpName = raLocaleBean.getMessage("search_certs_page_info_missingcp", cpId);
        }
        final int eepId = cdw.getCertificateData().getEndEntityProfileIdOrZero();
        final String eepName;
        if (eepId==EndEntityInformation.NO_ENDENTITYPROFILE) {
            eepName = raLocaleBean.getMessage("search_certs_page_info_unknowneep", eepId);
        } else if (eepIdToNameMap!=null && eepIdToNameMap.containsKey(Integer.valueOf(eepId))) {
            eepName = String.valueOf(eepIdToNameMap.get(Integer.valueOf(eepId)));
        } else {
            eepName = raLocaleBean.getMessage("search_certs_page_info_missingeep", eepId);
        }
        final String issuerDn = cdw.getCertificateData().getIssuerDN();
        final String caName;
        if (issuerDn != null && caSubjectToNameMap.containsKey(issuerDn)) {
            caName = String.valueOf(caSubjectToNameMap.get(issuerDn));
        } else {
            caName = String.valueOf(issuerDn);
        }
        final int status = cdw.getCertificateData().getStatus();
        final String statusString;
        switch (status) {
        case CertificateConstants.CERT_ACTIVE:
        case CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION:
            statusString = raLocaleBean.getMessage("search_certs_page_status_active");
            break;
        case CertificateConstants.CERT_ARCHIVED:
        case CertificateConstants.CERT_REVOKED:
            statusString = raLocaleBean.getMessage("search_certs_page_status_revoked_"+cdw.getCertificateData().getRevocationReason());
            break;
        default:
            statusString = raLocaleBean.getMessage("search_certs_page_status_other");
        }
        
        return new RaCertificateDetails(cdw, cpName, eepName, caName, statusString);
    }
    
    public RaCertificateDetails(final CertificateDataWrapper cdw, final String cpName, final String eepName, final String caName, final String statusString) {
        this.cdw = cdw;
        final CertificateData certificateData = cdw.getCertificateData();
        this.fingerprint = certificateData.getFingerprint();
        this.serialnumberRaw = certificateData.getSerialNumber();
        String serialnumber = "";
        try {
            serialnumber = new BigInteger(this.serialnumberRaw).toString(16);
        } catch (NumberFormatException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to format serial number as hex. Probably a CVC certificate. Message: " + e.getMessage());
            }
        }
        this.serialnumber = serialnumber;
        final String username = certificateData.getUsername();
        this.username = username==null ? "" : username;
        this.subjectDn = certificateData.getSubjectDN();
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
        if (certificate==null || certificateEncoded==null) {
            this.type = "";
            this.subjectAn = "";
            this.subjectDa = "";
            this.fingerprintSha256 = "";
            this.publicKeyAlgorithm = "";
            this.publicKeySpecification = "";
            this.publicKeyModulus = "";
            this.keyUsage = "";
            this.extendedKeyUsage = "";
            this.typeVersion = "";
            this.basicConstraints = "";
            this.cvcAuthorizationRole = "";
            this.cvcAuthorizationAccessRights = "";
        } else {
            if (certificate instanceof X509Certificate) {
                final X509Certificate x509Certificate = (X509Certificate)certificate;
                this.typeVersion = Integer.toString(x509Certificate.getVersion());
                final int basicConstraints = x509Certificate.getBasicConstraints();
                if (basicConstraints==Integer.MAX_VALUE) {
                    this.basicConstraints = "";
                } else if (basicConstraints == -1) {
                    // TODO: Localize
                    this.basicConstraints = "End Entity";
                } else {
                    // TODO: Localize
                    this.basicConstraints = "CA, Path length constraint " + basicConstraints;
                }
                final boolean[] keyUsageArray = x509Certificate.getKeyUsage();
                final StringBuilder keyUsageSb = new StringBuilder();
                if (keyUsageArray[CertificateConstants.DIGITALSIGNATURE]) { keyUsageSb.append("digitalSignature"); }
                if (keyUsageArray[CertificateConstants.NONREPUDIATION]) { keyUsageSb.append("  nonRepudiation (contentCommitment)"); }
                if (keyUsageArray[CertificateConstants.KEYENCIPHERMENT]) { keyUsageSb.append("  keyEncipherment"); }
                if (keyUsageArray[CertificateConstants.DATAENCIPHERMENT]) { keyUsageSb.append("  dataEncipherment"); }
                if (keyUsageArray[CertificateConstants.KEYAGREEMENT]) { keyUsageSb.append("  keyAgreement"); }
                if (keyUsageArray[CertificateConstants.KEYCERTSIGN]) { keyUsageSb.append("  keyCertSign"); }
                if (keyUsageArray[CertificateConstants.CRLSIGN]) { keyUsageSb.append("  cRLSign"); }
                if (keyUsageArray[CertificateConstants.ENCIPHERONLY]) { keyUsageSb.append("  encipherOnly"); }
                if (keyUsageArray[CertificateConstants.DECIPHERONLY]) { keyUsageSb.append("  decipherOnly"); }
                this.keyUsage = keyUsageSb.toString().replaceAll("  ", ", ");
                List<String> extendedKeyUsages = null;
                try {
                    extendedKeyUsages = x509Certificate.getExtendedKeyUsage();
                } catch (CertificateParsingException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to parse Extended Key Usage extension: " + e.getMessage());
                    }
                }
                if (extendedKeyUsages == null) {
                    this.extendedKeyUsage = "";
                } else {
                    final StringBuilder sb = new StringBuilder();
                    for (final String eku : extendedKeyUsages) {
                        if (sb.length()>0) {
                            sb.append(", ");
                        }
                        // TODO: Localize? (Configured name resides on the CA..)
                        sb.append(eku);
                    }
                    this.extendedKeyUsage = sb.toString();
                }
                this.cvcAuthorizationRole = "";
                this.cvcAuthorizationAccessRights = "";
            } else if ("CVC".equals(this.type)) {
                final CardVerifiableCertificate cardVerifiableCertificate = (CardVerifiableCertificate)certificate;
                this.keyUsage = "";
                this.extendedKeyUsage = "";
                this.typeVersion = String.valueOf(CVCertificateBody.CVC_VERSION);
                this.basicConstraints = "";
                // Role and access rights
                AuthorizationField authorizationField = null;
                try {
                    authorizationField = cardVerifiableCertificate.getCVCertificate().getCertificateBody().getAuthorizationTemplate().getAuthorizationField();
                } catch (NoSuchFieldException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to parse CVC AuthorizationTemplate's AuthorizationField: " + e.getMessage());
                    }
                }
                if (authorizationField==null) {
                    this.cvcAuthorizationRole = "";
                    this.cvcAuthorizationAccessRights = "";
                } else {
                    this.cvcAuthorizationRole = authorizationField.getAuthRole().toString();
                    this.cvcAuthorizationAccessRights = authorizationField.getAccessRights().toString();
                }
            } else {
                this.keyUsage = "";
                this.extendedKeyUsage = "";
                this.typeVersion = "";
                this.basicConstraints = "";
                this.cvcAuthorizationRole = "";
                this.cvcAuthorizationAccessRights = "";
            }
            this.type = certificate.getType();
            this.subjectAn = CertTools.getSubjectAlternativeName(certificate);
            String subjectDa = "";
            try {
                subjectDa = SubjectDirAttrExtension.getSubjectDirectoryAttributes(certificate);
            } catch (ParseException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to parse Subject Directory Attributes extension: " + e.getMessage());
                }
            }
            this.subjectDa = subjectDa;
            this.fingerprintSha256 = new String(Hex.encode(CertTools.generateSHA256Fingerprint(certificateEncoded)));
            this.publicKeyAlgorithm = AlgorithmTools.getKeyAlgorithm(certificate.getPublicKey());
            this.publicKeySpecification = AlgorithmTools.getKeySpecification(certificate.getPublicKey());
            if( certificate.getPublicKey() instanceof RSAPublicKey){
                this.publicKeyModulus = ((RSAPublicKey)certificate.getPublicKey()).getModulus().toString(16);
            } else if( certificate.getPublicKey() instanceof DSAPublicKey){
                this.publicKeyModulus = ((DSAPublicKey)certificate.getPublicKey()).getY().toString(16);
            } else if( certificate.getPublicKey() instanceof ECPublicKey){
                this.publicKeyModulus = ((ECPublicKey)certificate.getPublicKey()).getW().getAffineX().toString(16)
                        + " " + ((ECPublicKey)certificate.getPublicKey()).getW().getAffineY().toString(16);
            } else {
                this.publicKeyModulus = "";
            }
        }
        this.cpId = certificateData.getCertificateProfileId();
        this.cpName = cpName;
        this.eepId = certificateData.getEndEntityProfileIdOrZero();
        this.eepName = eepName;
        this.issuerDn = certificateData.getIssuerDN();
        this.caName = caName;
        this.created = certificate==null ? "-" : ValidityDate.formatAsISO8601ServerTZ(CertTools.getNotBefore(certificate).getTime(), TimeZone.getDefault());
        this.expires = ValidityDate.formatAsISO8601ServerTZ(certificateData.getExpireDate(), TimeZone.getDefault());
        this.status = certificateData.getStatus();
        this.statusString = statusString;
        this.revocationReason = certificateData.getRevocationReason();
        if (status==CertificateConstants.CERT_ARCHIVED || status==CertificateConstants.CERT_REVOKED) {
            this.updated = ValidityDate.formatAsISO8601ServerTZ(certificateData.getRevocationDate(), TimeZone.getDefault());
        } else {
            this.updated = ValidityDate.formatAsISO8601ServerTZ(certificateData.getUpdateTime(), TimeZone.getDefault());
        }
        final String subjectKeyIdB64 = certificateData.getSubjectKeyId();
        if (subjectKeyIdB64==null) {
            this.subjectKeyId = "";
        } else {
            this.subjectKeyId = new String(Hex.encode(certificateData.getSubjectKeyId().getBytes()));
        }
        this.nameConstraints = "todo";
        this.qcStatements = "todo";
        this.certificateTransparencyScts = "todo";
        this.signatureAlgorithm = AlgorithmTools.getCertSignatureAlgorithmNameAsString(certificate);
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
    public String getCpName() { return cpName; }
    public boolean isCpNameSameAsEepName() { return eepName.equals(cpName); }
    public String getEepName() { return eepName; }
    public String getCreated() { return created; }
    public String getExpires() { return expires; }
    public boolean isActive() { return status==CertificateConstants.CERT_ACTIVE || status==CertificateConstants.CERT_NOTIFIEDABOUTEXPIRATION; }
    public String getStatus() { return statusString; }
    public String getUpdated() { return updated; }
    public String getPublicKeyAlgorithm() { return publicKeyAlgorithm; }
    public String getPublicKeySpecification() { return publicKeySpecification; }
    public String getPublicKeyModulus() { return publicKeyModulus; }
    public String getSubjectKeyId() { return subjectKeyId; }
    public String getBasicConstraints() { return basicConstraints; }
    public String getCvcAuthorizationRole() { return cvcAuthorizationRole; }
    public String getCvcAuthorizationAccessRights() { return cvcAuthorizationAccessRights; }
    public String getKeyUsage() { return keyUsage; }
    public String getExtendedKeyUsage() { return extendedKeyUsage; }
    public String getNameConstraints() { return nameConstraints; }
    public String getQcStatements() { return qcStatements; }
    public String getCertificateTransparencyScts() { return certificateTransparencyScts; }
    public String getSignatureAlgorithm() { return signatureAlgorithm; }
}
