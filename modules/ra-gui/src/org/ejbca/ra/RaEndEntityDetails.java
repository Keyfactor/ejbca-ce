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
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.TimeZone;
import java.util.stream.Collectors;

import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;
import javax.faces.model.SelectItem;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificate.ssh.SshEndEntityProfileFields;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.SshCertificateUtils;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;

/**
 * UI representation of a result set item from the back end.
 *
 * For printing user data fields.
 */
public class RaEndEntityDetails {

    public interface Callbacks {
        RaLocaleBean getRaLocaleBean();
        EndEntityProfile getEndEntityProfile(final int eepId);
    }

    private static final Logger log = Logger.getLogger(RaEndEntityDetails.class);
    private final Callbacks callbacks;

    private final String username;
    private final EndEntityInformation endEntityInformation;
    private final ExtendedInformation extendedInformation;
    private final String extensionData;
    private final String subjectDn;
    private final String subjectAn;
    private final String subjectDa;
    private final int eepId;
    private final String eepName;
    private final int cpId;
    private final String cpName;
    private final String caName;
    private final String created;
    private final String modified;
    private final int status;

    // SSH End entity fields
    private final boolean sshTypeEndEntity;
    private final String sshKeyId;
    private final String sshPrincipals;
    private final String sshComment;
    private final String sshForceCommand;
    private final String sshSourceAddress;
    private final boolean sshVerifyRequired;

    private EndEntityProfile endEntityProfile = null;
    private SubjectDn subjectDistinguishedName = null;
    private SubjectAlternativeName subjectAlternativeName = null;
    private SubjectDirectoryAttributes subjectDirectoryAttributes = null;

    private int styleRowCallCounter = 0;

    private RaEndEntityDetails next = null;
    private RaEndEntityDetails previous = null;
    
    public RaEndEntityDetails(final EndEntityInformation endEntity, final Callbacks callbacks,
            final Map<Integer, String> cpIdToNameMap, final Map<Integer, String> eepIdToNameMap, final Map<Integer,String> caIdToNameMap) {
        this(endEntity, callbacks, cpIdToNameMap.get(Integer.valueOf(endEntity.getCertificateProfileId())),
                String.valueOf(eepIdToNameMap.get(Integer.valueOf(endEntity.getEndEntityProfileId()))),
                String.valueOf(caIdToNameMap.get(Integer.valueOf(endEntity.getCAId()))));
    }

    public RaEndEntityDetails(final EndEntityInformation endEntity, final Callbacks callbacks,
            final String certProfName, final String eeProfName, final String caName) {
        this.endEntityInformation = endEntity;
        final ExtendedInformation extendedInformation = endEntity.getExtendedInformation();
        this.extendedInformation = extendedInformation==null ? new ExtendedInformation() : extendedInformation;
        this.extensionData = getExtensionData(endEntityInformation.getExtendedInformation());
        this.callbacks = callbacks;
        this.username = endEntity.getUsername();
        this.subjectDn = endEntity.getDN();
        this.subjectAn = endEntity.getSubjectAltName();
        this.subjectDa = this.extendedInformation.getSubjectDirectoryAttributes();
        this.cpId = endEntity.getCertificateProfileId();
        this.cpName = certProfName;
        this.eepId = endEntity.getEndEntityProfileId();
        this.eepName = eeProfName;
        this.caName = caName;
        final Date timeCreated = endEntity.getTimeCreated();
        if (endEntity.isSshEndEntity()) {
            this.sshTypeEndEntity = true;
            this.sshKeyId = SshCertificateUtils.getKeyId(this.subjectDn);
            this.sshPrincipals = SshCertificateUtils.getPrincipalsAsString(this.subjectAn);
            this.sshComment = SshCertificateUtils.getComment(this.subjectAn);
            Map<String, String> sshCriticalOptions = this.extendedInformation.getSshCriticalOptions();
            this.sshForceCommand = sshCriticalOptions.containsKey(
                    SshEndEntityProfileFields.SSH_CRITICAL_OPTION_FORCE_COMMAND_CERT_PROP) ?
                    sshCriticalOptions.get(SshEndEntityProfileFields.SSH_CRITICAL_OPTION_FORCE_COMMAND_CERT_PROP) : null;
            this.sshSourceAddress = sshCriticalOptions.containsKey(
                    SshEndEntityProfileFields.SSH_CRITICAL_OPTION_SOURCE_ADDRESS_CERT_PROP) ?
                    sshCriticalOptions.get(SshEndEntityProfileFields.SSH_CRITICAL_OPTION_SOURCE_ADDRESS_CERT_PROP) : null;
            this.sshVerifyRequired = sshCriticalOptions.containsKey(
                SshEndEntityProfileFields.SSH_CRITICAL_OPTION_VERIFY_REQUIRED_CERT_PROP);
        } else {
            this.sshTypeEndEntity = false;
            this.sshKeyId = null;
            this.sshPrincipals = null;
            this.sshComment = null;
            this.sshForceCommand = null;
            this.sshSourceAddress = null;
            this.sshVerifyRequired = false;
        }
        if(timeCreated != null) {
            this.created = ValidityDate.formatAsISO8601ServerTZ(timeCreated.getTime(), TimeZone.getDefault());
        } else {
            this.created = "";
        }
        final Date timeModified = endEntity.getTimeModified();
        if(timeModified != null) {
            this.modified = ValidityDate.formatAsISO8601ServerTZ(timeModified.getTime(), TimeZone.getDefault());
        } else {
            this.modified = "";
        }
        this.status = endEntity.getStatus();
    }
    public EndEntityInformation getEndEntityInformation() { return endEntityInformation; }
    public String getUsername() { return username; }
    public String getSubjectDn() { return subjectDn; }

    /**
     *
     * @return the Subject DN string of the current certificate in unescaped RDN format
     */
    public final String getSubjectDnUnescapedValue() {
        if (StringUtils.isNotEmpty(subjectDn)) {
            return org.ietf.ldap.LDAPDN.unescapeRDN(subjectDn);
        } else {
            return subjectDn;
        }
    }
    public String getSubjectAn() { return subjectAn; }
    public String getSubjectDa() { return subjectDa; }
    public String getCaName() { return caName; }
    public String getCpName() {
        if (cpId==CertificateProfileConstants.NO_CERTIFICATE_PROFILE) {
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_info_unknowncp");
        } else if (cpName!=null) {
            return cpName;
        }
        return callbacks.getRaLocaleBean().getMessage("component_eedetails_info_missingcp", cpId);
    }
    public boolean isCpNameSameAsEepName() { return getEepName().equals(getCpName()); }
    public String getEepName() {
        if (eepId==EndEntityConstants.NO_END_ENTITY_PROFILE) {
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_info_unknowneep", eepId);
        } else if (eepName!=null) {
            return eepName;
        }
        return callbacks.getRaLocaleBean().getMessage("component_eedetails_info_missingeep", eepId);
    }
    public int getCaId() {
        return endEntityInformation.getCAId();
    }
    public boolean isSshTypeEndEntity() { return sshTypeEndEntity; }
    public String getSshKeyId() { return sshKeyId; }
    public String getSshPrincipals() { return sshPrincipals; }

    /**
     * Converts colon separated list of principals to colon separated.
     * @return String with principals separated by ,
     */
    public String getSshPrincipalsPretty() {
        String principals = getSshPrincipals().replace(":", ", ");
        if (StringUtils.endsWith(principals, ", ")) {
            principals = principals.substring(0, principals.length() -2);
        }
        return principals;
    }

    public String getSshComment() { return sshComment; }
    public String getSshForceCommand() { return sshForceCommand; }
    public String getSshSourceAddress() { return sshSourceAddress; }
    public boolean getSshVerifyRequired() { return sshVerifyRequired; }
    public String getSshVerifyRequiredString() {
        return getSshVerifyRequired() ? callbacks.getRaLocaleBean().getMessage("enroll_ssh_critical_verify_required_enabled") :
                callbacks.getRaLocaleBean().getMessage("enroll_ssh_critical_verify_required_disabled");
    }

    public boolean isSshForceCommandRequired() {
        return this.endEntityProfile.isSshForceCommandRequired();
    }

    public boolean isSshForceCommandModifiable() {
        return this.endEntityProfile.isSshForceCommandModifiable();
    }

    public boolean isSshSourceAddressRequired() {
        return this.endEntityProfile.isSshSourceAddressRequired();
    }

    public boolean isSshSourceAddressModifiable() {
        return this.endEntityProfile.isSshSourceAddressModifiable();
    }

    public boolean isSshVerifyRequiredModifiable() {
        return this.endEntityProfile.isSshVerifyRequiredModifiable();
    }

    public boolean isSshVerifyRequiredRequired() {
        return this.endEntityProfile.isSshVerifyRequiredRequired();
    }

    public String getCreated() { return created; }
    public String getModified() { return modified; }
    public String getStatus() {
        switch (status) {
        case EndEntityConstants.STATUS_FAILED:
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_status_failed");
        case EndEntityConstants.STATUS_GENERATED:
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_status_generated");
        case EndEntityConstants.STATUS_KEYRECOVERY:
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_status_keyrecovery");
        case EndEntityConstants.STATUS_NEW:
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_status_new");
        case EndEntityConstants.STATUS_REVOKED:
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_status_revoked");
        }
        return callbacks.getRaLocaleBean().getMessage("component_eedetails_status_other");
    }

    public String getTokenType() {
        switch (endEntityInformation.getTokenType()) {
            case EndEntityConstants.TOKEN_USERGEN:
                return callbacks.getRaLocaleBean().getMessage("component_eedetails_tokentype_usergen");
            case EndEntityConstants.TOKEN_SOFT_JKS:
                return callbacks.getRaLocaleBean().getMessage("component_eedetails_tokentype_jks");
            case EndEntityConstants.TOKEN_SOFT_P12:
                return callbacks.getRaLocaleBean().getMessage("component_eedetails_tokentype_pkcs12");
            case EndEntityConstants.TOKEN_SOFT_BCFKS:
                return callbacks.getRaLocaleBean().getMessage("component_eedetails_tokentype_bcfks");
            case EndEntityConstants.TOKEN_SOFT_PEM:
                return callbacks.getRaLocaleBean().getMessage("component_eedetails_tokentype_pem");
        }
        return "?";
    }

    /**
     * Extracts subject DN from certificate request and converts the string to cesecore namestyle
     * @return subject DN from CSR or null if CSR is missing / corrupted
     */
    public String getDnFromCsr() {
        if (endEntityInformation.getExtendedInformation().getCertificateRequest() != null) {
            try {
                PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(endEntityInformation.getExtendedInformation().getCertificateRequest());
                // Convert to "correct" display format
                X500Name subjectDn = CertTools.stringToBcX500Name(pkcs10CertificationRequest.getSubject().toString());
                return org.ietf.ldap.LDAPDN.unescapeRDN(subjectDn.toString());
            } catch (IOException e) {
                log.info("Failed to retrieve CSR attached to end entity " + username + ". Incorrect or corrupted structure", e);
                return null;
            }
        }
        log.info("No CSR found for end entity with username " + username);
        return null;
    }

    /** Returns the specified key type for this end entity (e.g. "RSA 2048"), or null if none is specified (e.g. if created from the Admin GUI) */
    public String getKeyType() {
        if (extendedInformation != null && extendedInformation.getKeyStoreAlgorithmType() != null) {
            String keyTypeString = extendedInformation.getKeyStoreAlgorithmType();
            if (extendedInformation.getKeyStoreAlgorithmSubType() != null) {
                keyTypeString += " " + extendedInformation.getKeyStoreAlgorithmSubType();
            }
            return keyTypeString;
        } else if (extendedInformation.getCertificateRequest() != null && extendedInformation.getKeyStoreAlgorithmType() == null) {
            return getKeysFromCsr();

        }
        return null; // null = hidden in UI
    }

    private String getKeysFromCsr() {
        if (endEntityInformation.getExtendedInformation().getCertificateRequest() != null) {
            try {
                PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(endEntityInformation.getExtendedInformation().getCertificateRequest());
                final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(pkcs10CertificationRequest);
                final String keySpecification = AlgorithmTools.getKeySpecification(jcaPKCS10CertificationRequest.getPublicKey());
                final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(jcaPKCS10CertificationRequest.getPublicKey());
                return keyAlgorithm + " " + keySpecification;
            } catch (InvalidKeyException e) {
                log.info("Failed to retrieve public key from CSR attached to end entity " + username + ". Key is either uninitialized or corrupted", e);
            } catch (IOException e) {
                log.info("Failed retrieve CSR attached to end entity " + username + ". Incorrect or corrupted structure", e);
            } catch (NoSuchAlgorithmException e) {
                log.info("Unsupported key algorithm attached to CSR for end entity with username " + username, e);
            }
        }
        log.info("No CSR found for end entity with username " + username);
        return null;
    }

    /** Download CSR attached to end entity in .pem format */
    public void downloadCsr() {
        if (extendedInformation.getCertificateRequest() != null) {
            byte[] certificateSignRequest = extendedInformation.getCertificateRequest();
            downloadToken(certificateSignRequest, "application/octet-stream", ".pkcs10.pem");
        } else {
            throw new IllegalStateException("Could not find CSR attached to end entity with username " + username + ". CSR is expected to be set at this point");
        }
    }

    private final void downloadToken(byte[] token, String responseContentType, String fileExtension) {
        if (token == null) {
            return;
        }
        //Download the CSR
        FacesContext fc = FacesContext.getCurrentInstance();
        ExternalContext ec = fc.getExternalContext();
        ec.responseReset(); // Some JSF component library or some Filter might have set some headers in the buffer beforehand. We want to get rid of them, else it may collide.
        ec.setResponseContentType(responseContentType);
        ec.setResponseContentLength(token.length);
        String fileName = CertTools.getPartFromDN(endEntityInformation.getDN(), "CN");
        if(fileName == null){
            fileName = "request_csr";
        }

        final String filename = StringTools.stripFilename(fileName + fileExtension);
        ec.setResponseHeader("Content-Disposition", "attachment; filename=\"" + filename + "\""); // The Save As popup magic is done here. You can give it any file name you want, this only won't work in MSIE, it will use current request URL as file name instead.
        OutputStream output = null;
        try {
            output = ec.getResponseOutputStream();
            output.write(token);
            output.flush();
            fc.responseComplete(); // Important! Otherwise JSF will attempt to render the response which obviously will fail since it's already written with a file and closed.
        } catch (IOException e) {
            log.info("Token " + filename + " could not be downloaded", e);
            callbacks.getRaLocaleBean().getMessage("enroll_token_could_not_be_downloaded", filename);
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                    throw new IllegalStateException("Failed to close outputstream", e);
                }
            }
        }
    }

    public boolean isTokenTypeUserGenerated() {
        return endEntityInformation.getTokenType() == EndEntityConstants.TOKEN_USERGEN;
    }

    public boolean isKeyRecoverable() {
        return endEntityInformation.getKeyRecoverable();
    }

    public boolean isEmailEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isEmailUsed() : false;
    }
    public String getEmail() {
        return endEntityInformation.getEmail();
    }

    public boolean isLoginsMaxEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isMaxFailedLoginsUsed() : false;
    }
    public String getLoginsMax() {
        return Integer.toString(extendedInformation.getMaxLoginAttempts());
    }
    public String getLoginsRemaining() {
        return Integer.toString(extendedInformation.getRemainingLoginAttempts());
    }

    public boolean isSendNotificationEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isSendNotificationUsed() : false;
    }
    public boolean isSendNotificationDisabled(){
        return getEndEntityProfile().isSendNotificationRequired();
    }
    public boolean isSendNotification() {
        return endEntityInformation.getSendNotification();
    }

    public boolean isCertificateSerialNumberOverrideEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isCustomSerialNumberUsed() : false;
    }
    public String getCertificateSerialNumberOverride() {
        final BigInteger certificateSerialNumber = extendedInformation.certificateSerialNumber();
        if (certificateSerialNumber!=null) {
            return certificateSerialNumber.toString(16);
        }
        return "";
    }

    public boolean isOverrideNotBeforeEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isValidityStartTimeUsed() : false;
    }
    public String getOverrideNotBefore() {
        return extendedInformation.getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
    }
    public boolean isOverrideNotAfterEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isValidityEndTimeUsed() : false;
    }
    public String getOverrideNotAfter() {
        return extendedInformation.getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
    }

    public boolean isCardNumberEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isCardNumberUsed() : false;
    }
    public String getCardNumber() {
        return endEntityInformation.getCardNumber();
    }

    public boolean isNameConstraintsPermittedEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isNameConstraintsPermittedUsed() : false;
    }
    public boolean isNameConstraintsPermittedRequired() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isNameConstraintsPermittedRequired() : false;
    }
    /**
     * Format permitted name constraints as user has entered earlier to create end 
     * entity. This is shown in edit end entity page.
     * 
     * @return string
     */
    public String getNameConstraintsPermitted() {
        final List<String> value = extendedInformation.getNameConstraintsPermitted();
        if (value!=null) {
            return NameConstraint.formatNameConstraintsList(value);
        }
        return "";
    }
    /**
     * Format permitted name constraints as a user friendly semicolon separated list for
     * view end entity page accessible in RA web from search results.
     *  
     * @return semicolon separated string
     */
    public String getNameConstraintsPermittedViewOnly() {
        return getNameConstraintsPermitted().replace("\n", "; ");
    }
    
    public boolean isNameConstraintsExcludedEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isNameConstraintsExcludedUsed() : false;
    }
    public boolean isNameConstraintsExcludedRequired() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isNameConstraintsExcludedRequired() : false;
    }
    public String getNameConstraintsExcluded() {
        final List<String> value = extendedInformation.getNameConstraintsExcluded();
        if (value!=null) {
            return NameConstraint.formatNameConstraintsList(value);
        }
        return "";
    }
    /**
     * Format excluded name constraints as a semicolon separated list for
     * view end entity page accessible in RA web from search results.
     *  
     * @return semicolon separated string
     */
    public String getNameConstraintsExcludedViewOnly() {
        return getNameConstraintsExcluded().replace("\n", "; ");
    }
    
    /** @return true if CSR exists in EEI*/
    public boolean isCsrSet() {
        return extendedInformation.getCertificateRequest() != null;
    }
    

    public boolean isAllowedRequestsEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isAllowedRequestsUsed() : false;
    }
    public String getAllowedRequests() {
        return getEndEntityProfile() != null ? String.valueOf(getEndEntityProfile().getAllowedRequests()) : "";
    }
    public String getAllowedRequestsUsed() {
        final String value = extendedInformation.getCustomData(ExtendedInformationFields.CUSTOM_REQUESTCOUNTER);
        return value==null ? "0" : value;
    }

    public boolean isIssuanceRevocationReasonEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isIssuanceRevocationReasonUsed() : false;
    }
    public String getIssuanceRevocationReason() {
      final String reasonCode = String.valueOf(extendedInformation.getIssuanceRevocationReason());
        if (reasonCode!=null) {
            return callbacks.getRaLocaleBean().getMessage("component_eedetails_field_issuancerevocation_reason_"+reasonCode);
        }
        return callbacks.getRaLocaleBean().getMessage("component_eedetails_field_issuancerevocation_reason_" + RevokedCertInfo.NOT_REVOKED);
    }

    public SubjectDn getSubjectDistinguishedName() {
        if (subjectDistinguishedName==null) {
            this.subjectDistinguishedName = new SubjectDn(getEndEntityProfile(), subjectDn);
        }
        return subjectDistinguishedName;
    }

    public SubjectAlternativeName getSubjectAlternativeName() {
        if (subjectAlternativeName==null) {
            this.subjectAlternativeName = new SubjectAlternativeName(getEndEntityProfile(), subjectAn);
        }
        return subjectAlternativeName;

    }

    public SubjectDirectoryAttributes getSubjectDirectoryAttributes() {
        if (subjectDirectoryAttributes==null) {
            this.subjectDirectoryAttributes = new SubjectDirectoryAttributes(getEndEntityProfile(), subjectDa);
        }
        return subjectDirectoryAttributes;
    }

    private EndEntityProfile getEndEntityProfile() {
        if (endEntityProfile==null) {
            endEntityProfile = callbacks.getEndEntityProfile(eepId);
        }
        return endEntityProfile;
    }

    /**
     * Returns the add approval request ID stored in the extended information
     * @return the ID of the approval request that was submitted to create the end entity
     */
    public String getAddEndEntityApprovalRequestId() {
        String ret = "";
        final ExtendedInformation ext = endEntityInformation.getExtendedInformation();
        if(ext != null) {
            final Integer reqid = ext.getAddEndEntityApprovalRequestId();
            if(reqid != null) {
                ret = reqid.toString();
            }
        }
        return ret;
    }

    /**
     * Returns the edit approval request IDs stored in the extended information as one String separated by ';'
     * @return the IDs of the approval request that were submitted to edit the end entity
     */
    public String getEditEndEntityApprovalRequestIds() {
        StringBuilder ret = new StringBuilder("");
        final ExtendedInformation ext = endEntityInformation.getExtendedInformation();
        if(ext != null) {
            final List<Integer> ids = ext.getEditEndEntityApprovalRequestIds();
            if(!ids.isEmpty()) {
                for(Integer id : ids) {
                    ret = ret.append("; ").append(id);
                }
                ret.delete(0, 2);
            }
        }
        return ret.toString();
    }

    /**
     * Returns the revocation approval request IDs stored in the extended information as one String separated by ';'
     * @return the IDs of the approval request that were submitted to revoke the end entity
     */
    public String getRevokeEndEntityApprovalRequestIds() {
        StringBuilder ret = new StringBuilder("");
        final ExtendedInformation ext = endEntityInformation.getExtendedInformation();
        if(ext != null) {
            final List<Integer> ids = ext.getRevokeEndEntityApprovalRequestIds();
            if(!ids.isEmpty()) {
                for(Integer id : ids) {
                    ret = ret.append("; ").append(id);
                }
                ret.delete(0, 2);
            }
        }
        return ret.toString();
    }
    
    
    /**
     * @return Certificate extension data after it has already been read from extended information
     */
    public String getExtensionData() {
        return extensionData;
    }
    
    public boolean isExtensionDataConfigured() {
        if (endEntityProfile != null) {
            return endEntityProfile.getUseExtensiondata();
        }
        return false;
    }
    
    /**
     * @return Certificate extension data read from extended information
     */
    public String getExtensionData(ExtendedInformation extendedInformation) {
        final String result;
        if (extendedInformation == null) {
            return null;
        } else {
            @SuppressWarnings("rawtypes")
            Map data = (Map) extendedInformation.getData();
            Properties properties = new Properties();

            for (Object o : data.keySet()) {
                if (o instanceof String) {
                    String key = (String) o;
                    if (key.startsWith(ExtendedInformation.EXTENSIONDATA)) {
                        String subKey = key.substring(ExtendedInformation.EXTENSIONDATA.length());
                        properties.put(subKey, data.get(key));
                    }
                }

            }

            // Render the properties and remove the first line created by the Properties class.
            StringWriter out = new StringWriter();
            try {
                properties.store(out, null);
            } catch (IOException ex) {
                // Should not happen as we are using a StringWriter
                throw new RuntimeException(ex);
            }

            StringBuffer buff = out.getBuffer();
            String lineSeparator = System.getProperty("line.separator");
            int firstLineSeparator = buff.indexOf(lineSeparator);

            result = firstLineSeparator >= 0 ? buff.substring(firstLineSeparator + lineSeparator.length()) : buff.toString();
        }
        return result;
    }

    /**
     * @return true if the Revised Payment Service Directive (PSD2) Qualified Certificate statement field usage is enabled in End Entity profile.
     */
    public boolean isPsd2QcStatementEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isPsd2QcStatementUsed() : false;
    }

    /**
     * @return the PSD2 National Competent Authority (NCA) Name stored in the extended information
     */
    public String getPsd2NcaName() {
        return extendedInformation.getQCEtsiPSD2NCAName();
    }

    /**
     * @return the PSD2 National Competent Authority (NCA) Identifier stored in the extended information
     */
    public String getPsd2NcaId() {
        return extendedInformation.getQCEtsiPSD2NCAId();
    }

    /**
     * @return selected roles of PSD2 third party Payment Service Providers (PSPs)
     */
    public List<String> getSelectedPsd2PspRoles() {
        return Optional.ofNullable(extendedInformation.getQCEtsiPSD2RolesOfPSP())
                .orElseGet(Collections::emptyList)
                .stream()
                .map(role -> role.getName())
                .collect(Collectors.toList());
    }

    /**
     * @return all available roles of PSD2 third party Payment Service Providers (PSPs)
     */
    public List<SelectItem> getAvailablePsd2PspRoles() {
        final List<SelectItem> pspRoles = new ArrayList<>();
        pspRoles.add(new SelectItem("PSP_AS", callbacks.getRaLocaleBean().getMessage("enroll_psd2_psp_as")));
        pspRoles.add(new SelectItem("PSP_PI", callbacks.getRaLocaleBean().getMessage("enroll_psd2_psp_pi")));
        pspRoles.add(new SelectItem("PSP_AI", callbacks.getRaLocaleBean().getMessage("enroll_psd2_psp_ai")));
        pspRoles.add(new SelectItem("PSP_IC", callbacks.getRaLocaleBean().getMessage("enroll_psd2_psp_ic")));
        return pspRoles;
    }

    /**
     * @return true if CA/B Forum Organization Identifier field usage is enabled in End Entity profile.
     */
    public boolean isCabfOrganizationIdentifierEnabled() {
        return getEndEntityProfile() != null ? getEndEntityProfile().isCabfOrganizationIdentifierUsed() : false;
    }

    /**
     * @return the CA/B Forum Organization Identifier stored in the extended information
     */
    public String getCabfOrganizationIdentifier() {
        return extendedInformation.getCabfOrganizationIdentifier();
    }

    /** @return true every twice starting with every forth call */
    public boolean isEven() {
        styleRowCallCounter++;
        return (styleRowCallCounter+1) / 2 % 2 == 0;
    }
    /** @return true every twice starting with every other call */
    public boolean isEvenTwice() {
        isEven();
        return isEven();
    }

    public RaEndEntityDetails getNext() { return next; }
    public void setNext(RaEndEntityDetails next) { this.next = next; }

    public RaEndEntityDetails getPrevious() { return previous; }
    public void setPrevious(RaEndEntityDetails previous) { this.previous = previous; }
}
