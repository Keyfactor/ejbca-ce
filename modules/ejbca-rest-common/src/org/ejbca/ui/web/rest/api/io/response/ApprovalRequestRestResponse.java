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

package org.ejbca.ui.web.rest.api.io.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import java.io.IOException;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import org.apache.commons.lang3.StringUtils;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalPartition;
import org.ejbca.core.model.era.RaApprovalRequestInfo;

/**
 * Response object for approval request data.
 */
@Schema(name = "ApprovalRequestRestResponse", description = "Response containing approval request information")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApprovalRequestRestResponse extends ProcessApprovalRestResponse {

    @Schema(description = "Certificate profile name", example = "ENDUSER")
    private String certificateProfileName;

    @Schema(description = "End Entity profile name", example = "ExampleEEP")
    private String endEntityProfileName;
    
    @Schema(description = "Issuer Distinguished Name", example = "CN=ExampleCA,O=Sample,C=SE")
    private String issuerDn;

    @Schema(description = "Subject Distinguished Name", example = "CN=ExampleCA,O=Sample,C=SE")
    private String subjectDn;

    @Schema(description = "Key algorithm", example = "RSA 2048")
    private String keyAlgorithm;

    @Schema(description = "Keystore type property", example = "P12")
    private String token;

    @Schema(description = "Revocation reason", example = "Unspecified")
    private String reason;

    @Schema(description = "Ca Name", example = "ManagementCA")
    private String caName;

    @Schema(description = "Serial Number", example = "12345")
    private String serialNumber;

    @Schema(description = "E-mail", example = "a@domain.com")
    private String email;

    @Schema(description = "Invalidity Date", example = "yyyy-MM-dd HH:mm:ssXXX")
    private String invalidityDate;

    @Schema(description = "Key Recoverable", example = "Yes")
    private String keyRecoverable;

    @Schema(description = "Subject Name Log Redaction (key recovery)", example = "false")
    private String subjectNameLogRedaction;

    @Schema(description = "Revocation Date", example = "yyyy-MM-dd HH:mm:ssXXX")
    private String revocationDate;

    @Schema(description = "End Entity Status ", example = "NEW")
    private String endEntityStatus;

    @Schema(description = "Send Notification ", example = "Yes")
    private String sendNotification;

    @Schema(description = "Subject Directory Attributes", example = "NOVALUE")
    private String subjectDirectoryAttributes;

    @Schema(description = "Subject Alternative Name", example = "NOVALUE")
    private String subjectAlternativeName;

    @Schema(description = "ACME Account Id", example = "1")
    private String acmeAccountId;

    @Schema(description = "ACME CA ID", example = "1")
    private String caId;

    @Schema(description = "ACME End Entity Profile ID", example = "1")
    private String endEntityProfileId;

    @Schema(description = "Name Constraints Excluded", example = "ABC")
    private String nameConstraintsExcluded;

    @Schema(description = "Name Constraints Permitted", example = "ABC")
    private String nameConstraintsPermitted;

    @Schema(description = "Certificate Extension Data", example = "1.5.6.value=Value")
    private String certificateExtensionData;


    public ApprovalRequestRestResponse(final ApprovalRequestRestResponseBuilder builder) {
        super(builder);
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public String getIssuerDn() {
        return issuerDn;
    }

    public String getSubjectDn() {
        return subjectDn;
    }

    public String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public String getToken() {
        return token;
    }

    public String getReason() {
        return reason;
    }
    public String getCaName() {
        return caName;
    }
    public String getSerialNumber() {
        return serialNumber;
    }
    public String getEmail() {
        return email;
    }
    public String getInvalidityDate() {
        return invalidityDate;
    }
    public String getKeyRecoverable() {
        return keyRecoverable;
    }
    public String getSubjectNameLogRedaction() {
        return subjectNameLogRedaction;
    }
    public String getRevocationDate() {
        return revocationDate;
    }
    public String getEndEntityStatus() {
        return endEntityStatus;
    }
    public String getSendNotification() {
        return sendNotification;
    }
    public String getSubjectDirectoryAttributes() {
        return subjectDirectoryAttributes;
    }
    public String getSubjectAlternativeName() {
        return subjectAlternativeName;
    }
    public String getAcmeAccountId() {
        return acmeAccountId;
    }
    public String getCaId() {
        return caId;
    }
    public String getEndEntityProfileId() {
        return endEntityProfileId;
    }
    public String getNameConstraintsExcluded() {
        return nameConstraintsExcluded;
    }
    public String getNameConstraintsPermitted() {
        return nameConstraintsPermitted;
    }
    public String getCertificateExtensionData() {
        return certificateExtensionData;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static ApprovalRequestRestResponseBuilder builder() {
        return new ApprovalRequestRestResponseBuilder();
    }

    public static class ApprovalRequestRestResponseBuilder extends Builder {
        private String certificateProfileName;
        private String endEntityProfileName;
        private String issuerDn;
        private String subjectDn;
        private String keyAlgorithm;
        private String token;
        private String reason;
        private String caName;
        private String serialNumber;
        private String email;
        private String invalidityDate;
        private String keyRecoverable;
        private String subjectNameLogRedaction;
        private String revocationDate;
        private String endEntityStatus;
        private String sendNotification;
        private String subjectDirectoryAttributes;
        private String subjectAlternativeName;
        private String acmeAccountId;
        private String caId;
        private String endEntityProfileId;
        private String nameConstraintsExcluded;
        private String nameConstraintsPermitted;
        private String certificateExtensionData;

        
        public ApprovalRequestRestResponseBuilder certificateProfileName(String certificateProfileName) {
            this.certificateProfileName = certificateProfileName;
            return this;
        }
        
        public ApprovalRequestRestResponseBuilder endEntityProfileName(String endEntityProfileName) {
            this.endEntityProfileName = endEntityProfileName;
            return this;
        }
        
        public ApprovalRequestRestResponseBuilder issuerDn(String issuerDn) {
            this.issuerDn = issuerDn;
            return this;
        }

        public ApprovalRequestRestResponseBuilder subjectDn(String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }
        
        public ApprovalRequestRestResponseBuilder keyAlgorithm(String keyAlgorithm) {
            this.keyAlgorithm = keyAlgorithm;
            return this;
        }
        
        public ApprovalRequestRestResponseBuilder token(String token) {
            this.token = token;
            return this;
        }

        public ApprovalRequestRestResponseBuilder reason(String reason) {
            this.reason = reason;
            return this;
        }

        public ApprovalRequestRestResponseBuilder caName(String caName) {
            this.caName = caName;
            return this;
        }

        public ApprovalRequestRestResponseBuilder serialNumber(String serialNumber) {
            this.serialNumber = serialNumber;
            return this;
        }

        public ApprovalRequestRestResponseBuilder email(String email) {
            this.email = email;
            return this;
        }
        public ApprovalRequestRestResponseBuilder invalidityDate(String invalidityDate) {
            this.invalidityDate = invalidityDate;
            return this;
        }
        public ApprovalRequestRestResponseBuilder keyRecoverable(String keyRecoverable) {
            this.keyRecoverable = keyRecoverable;
            return this;
        }
        public ApprovalRequestRestResponseBuilder subjectNameLogRedaction(String subjectNameLogRedaction) {
            this.subjectNameLogRedaction = subjectNameLogRedaction;
            return this;
        }
        public ApprovalRequestRestResponseBuilder revocationDate(String revocationDate) {
            this.revocationDate = revocationDate;
            return this;
        }
        public ApprovalRequestRestResponseBuilder endEntityStatus(String approvalStatus) {
            this.endEntityStatus = approvalStatus;
            return this;
        }
        public ApprovalRequestRestResponseBuilder sendNotification(String sendNotification) {
            this.sendNotification = sendNotification;
            return this;
        }
        public ApprovalRequestRestResponseBuilder subjectDirectoryAttributes(String subjectDirectoryAttributes) {
            this.subjectDirectoryAttributes = subjectDirectoryAttributes;
            return this;
        }
        public ApprovalRequestRestResponseBuilder subjectAlternativeName(String subjectAlternativeName) {
            this.subjectAlternativeName = subjectAlternativeName;
            return this;
        }
        public ApprovalRequestRestResponseBuilder acmeAccountId(String acmeAccountId) {
            this.acmeAccountId = acmeAccountId;
            return this;
        }
        public ApprovalRequestRestResponseBuilder caId(String caId) {
            this.caId = caId;
            return this;
        }
        public ApprovalRequestRestResponseBuilder endEntityProfileId(String endEntityProfileId) {
            this.endEntityProfileId = endEntityProfileId;
            return this;
        }
        public ApprovalRequestRestResponseBuilder nameConstraintsExcluded(String nameConstraintsExcluded) {
            this.nameConstraintsExcluded = nameConstraintsExcluded;
            return this;
        }
        public ApprovalRequestRestResponseBuilder nameConstraintsPermitted(String nameConstraintsPermitted) {
            this.nameConstraintsPermitted = nameConstraintsPermitted;
            return this;
        }
        public ApprovalRequestRestResponseBuilder certificateExtensionData(String certificateExtensionData) {
            this.certificateExtensionData = certificateExtensionData;
            return this;
        }

        @Override
        public ApprovalRequestRestResponse build() {
            ApprovalRequestRestResponse approvalRequestRestResponse = new ApprovalRequestRestResponse(this);
            approvalRequestRestResponse.certificateProfileName = this.certificateProfileName;
            approvalRequestRestResponse.endEntityProfileName = this.endEntityProfileName;
            approvalRequestRestResponse.issuerDn = this.issuerDn;
            approvalRequestRestResponse.subjectDn = this.subjectDn;
            approvalRequestRestResponse.keyAlgorithm = this.keyAlgorithm;
            approvalRequestRestResponse.token = this.token;
            approvalRequestRestResponse.reason = this.reason;
            approvalRequestRestResponse.caName = this.caName;
            approvalRequestRestResponse.serialNumber = this.serialNumber;
            approvalRequestRestResponse.email = this.email;
            approvalRequestRestResponse.invalidityDate = this.invalidityDate;
            approvalRequestRestResponse.keyRecoverable = this.keyRecoverable;
            approvalRequestRestResponse.subjectNameLogRedaction = this.subjectNameLogRedaction;
            approvalRequestRestResponse.revocationDate = this.revocationDate;
            approvalRequestRestResponse.endEntityStatus = this.endEntityStatus;
            approvalRequestRestResponse.sendNotification = this.sendNotification;
            approvalRequestRestResponse.subjectDirectoryAttributes = this.subjectDirectoryAttributes;
            approvalRequestRestResponse.subjectAlternativeName = this.subjectAlternativeName;
            approvalRequestRestResponse.acmeAccountId = this.acmeAccountId;
            approvalRequestRestResponse.caId = this.caId;
            approvalRequestRestResponse.endEntityProfileId = this.endEntityProfileId;
            approvalRequestRestResponse.nameConstraintsExcluded = this.nameConstraintsExcluded;
            approvalRequestRestResponse.nameConstraintsPermitted = this.nameConstraintsPermitted;
            approvalRequestRestResponse.certificateExtensionData = this.certificateExtensionData;
            return approvalRequestRestResponse;
        }
    }

    public static ApprovalRequestRestResponse buildApprovalResponse(final RaApprovalRequestInfo requestInfo) {
        final SimpleDateFormat dateFormat = new SimpleDateFormat(DATE_FORMAT);
        final ApprovalDataVO approvalData = requestInfo.getApprovalData();
        ApprovalRequest approvalRequest = requestInfo.getApprovalRequest();
        final String endEntityName = getUsername(approvalRequest);


        // Build approval steps
        final List<ApprovalStepRestResponse> steps = buildApprovalSteps(requestInfo);


        final Date requestDate = new Date(approvalData.getRequestDate().getTime());
        final long expirationPeriod = approvalRequest.getRequestValidity();
        final Date expirationDate = new Date(requestDate.getTime() + expirationPeriod);
        ApprovalRequestRestResponseBuilder builder = ApprovalRequestRestResponse.builder();
        ApprovalRequestStatus status = ApprovalRequestStatus.fromIntWithCombinedStates(requestInfo.getStatus());
        builder
                .requestId(String.valueOf(requestInfo.getId()))
                .requestType(ApprovalType.getNameByCode(approvalData.getApprovalType()))
                .requestDate(dateFormat.format(requestDate))
                .expirationDate(dateFormat.format(expirationDate))
                .endEntityName(endEntityName)
                .status(status)
                .steps(steps);
        if (requestInfo.getNextApprovalStep() != null) {
            final List<ApprovalPartitionRestResponse.ApprovalPartitionStep> partitions = new ArrayList<>();
            for (ApprovalPartition partition : requestInfo.getNextApprovalStep().getPartitionList()) {
                ApprovalPartitionRestResponse.ApprovalPartitionStep partitionStep = buildStepPartitionNextStep(requestInfo.getNextApprovalStep().getStepIdentifier(), partition,
                        requestInfo.getApprovalData().getApprovals(), requestInfo.getApprovalProfile(), status.getValue());
                partitions.add(partitionStep);
            }
            final ApprovalStepRestResponse.Builder stepBuilder = ApprovalStepRestResponse.builder()
                    .stepNumber(steps.size() + 1)
                    .partitionList(partitions);
            builder.nextStep(stepBuilder.build());
        }
        builder.certificateProfileName(requestInfo.getCertificateProfileName())
                .endEntityProfileName(requestInfo.getEndEntityProfileName());
        for (ApprovalDataText approvalDataText: requestInfo.getRequestData()){
            if (!approvalDataText.getData().isEmpty() && !approvalDataText.getData().equals("NOVALUE")) {
                switch (ApprovalDataText.ApprovalDataHeader.valueOf(approvalDataText.getHeader())) {
                    case CA, CANAME:
                        builder.caName(approvalDataText.getData());
                        break;
                    case ACMEACCOUNTID:
                        builder.acmeAccountId(approvalDataText.getData());
                        break;
                    case CAID:
                        builder.caId(approvalDataText.getData());
                        break;
                    case EEPID:
                        builder.endEntityProfileId(approvalDataText.getData());
                        break;
                    case CERTIFICATEPROFILE:
                        builder.certificateProfileName(approvalDataText.getData());
                        break;
                    case CERTSERIALNUMBER:
                        builder.serialNumber(approvalDataText.getData());
                        break;
                    case EMAIL:
                        builder.email(approvalDataText.getData());
                        break;
                    case ENDENTITYPROFILE:
                        builder.endEntityProfileName(approvalDataText.getData());
                        break;
                    case INVALIDITYDATE:
                        builder.invalidityDate(approvalDataText.getData());
                        break;
                    case ISSUERDN:
                        builder.issuerDn(approvalDataText.getData());
                        break;
                    case KEYALGORITHM:
                        builder.keyAlgorithm(approvalDataText.getData());
                        break;
                    case KEYRECOVERABLE:
                        builder.keyRecoverable(approvalDataText.getData());
                        break;
                    case REASON:
                        builder.reason(RevocationReason.getTextByCode(approvalDataText.getData()));
                        break;
                    case REDACTPII:
                        builder.subjectNameLogRedaction(approvalDataText.getData());
                        break;
                    case REVOCATIONDATE:
                        builder.revocationDate(approvalDataText.getData());
                        break;
                    case SENDNOTIFICATION:
                        builder.sendNotification(approvalDataText.getData());
                        break;
                    case STATUS:
                        builder.endEntityStatus(approvalDataText.getData());
                        break;
                    case SUBJECTDIRATTRIBUTES:
                        builder.subjectDirectoryAttributes(approvalDataText.getData());
                        break;
                    case SUBJECTALTNAME:
                        builder.subjectAlternativeName(approvalDataText.getData());
                        break;
                    case SUBJECTDN:
                        builder.subjectDn(approvalDataText.getData());
                        break;
                    case USERNAME:
                        builder.endEntityName(approvalDataText.getData());
                        break;
                    case PASSWORD, REQUESTEXPIRATIONDATE, REQUESTDATE:
                        break;
                }
            }
        }
        EndEntityInformation endEntityInformation = null;
        if (approvalRequest instanceof AddEndEntityApprovalRequest request) {
            endEntityInformation = request.getEndEntityInformation();

        } else if (approvalRequest instanceof EditEndEntityApprovalRequest request) {
            endEntityInformation = request.getNewEndEntityInformation();
        }
        if (endEntityInformation != null && endEntityInformation.getExtendedInformation() != null) {
            List<String> nameConstraintsExcluded = endEntityInformation.getExtendedInformation().getNameConstraintsExcluded();
            List<String> nameConstraintsPermitted = endEntityInformation.getExtendedInformation().getNameConstraintsPermitted();
            if(nameConstraintsPermitted !=null && !nameConstraintsPermitted.isEmpty()) {
                builder.nameConstraintsPermitted(NameConstraint.formatNameConstraintsList(nameConstraintsPermitted));
            }
            if (nameConstraintsExcluded != null && !nameConstraintsExcluded.isEmpty()) {
                builder.nameConstraintsExcluded(NameConstraint.formatNameConstraintsList(nameConstraintsExcluded));
            }
            String extensionData = getExtensionData(endEntityInformation.getExtendedInformation());
            if (!StringUtils.isEmpty(extensionData)) {
                builder.certificateExtensionData(extensionData);
            }

        }
        return builder.build();
    }


    /**
     * @return Certificate extension data read from extended information
     */
    private static String getExtensionData(ExtendedInformation extendedInformation) {
        final String result;
        if (extendedInformation == null) {
            return null;
        }
        @SuppressWarnings("rawtypes")
        Map data = (Map) extendedInformation.getData();
        Properties properties = new Properties();

        for (Object o : data.keySet()) {
            if (o instanceof String key && key.startsWith(ExtendedInformation.EXTENSIONDATA)) {
                String subKey = key.substring(ExtendedInformation.EXTENSIONDATA.length());
                properties.put(subKey, data.get(key));
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
        String lineSeparator = System.lineSeparator();
        int firstLineSeparator = buff.indexOf(lineSeparator);

        result = firstLineSeparator >= 0
                ? buff.substring(firstLineSeparator + lineSeparator.length())
                : buff.toString();

        return result;
    }

}
