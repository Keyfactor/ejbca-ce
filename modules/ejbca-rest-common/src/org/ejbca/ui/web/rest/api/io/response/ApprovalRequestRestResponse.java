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
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import io.swagger.v3.oas.annotations.media.Schema;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import org.apache.log4j.Logger;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestStatus;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.ui.web.rest.api.io.request.TokenType;

/**
 * Response object for approval request data.
 */
@Schema(name = "ApprovalRequestRestResponse", description = "Response containing approval request information")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApprovalRequestRestResponse extends ProcessApprovalRestResponse {
    private static final Logger log = Logger.getLogger(ApprovalRequestRestResponse.class);

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
        
        public ApprovalRequestRestResponse build() {
            ApprovalRequestRestResponse approvalRequestRestResponse = new ApprovalRequestRestResponse(this);
            approvalRequestRestResponse.certificateProfileName = this.certificateProfileName;
            approvalRequestRestResponse.endEntityProfileName = this.endEntityProfileName;
            approvalRequestRestResponse.issuerDn = this.issuerDn;
            approvalRequestRestResponse.subjectDn = this.subjectDn;
            approvalRequestRestResponse.keyAlgorithm = this.keyAlgorithm;
            approvalRequestRestResponse.token = this.token;
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
        builder
                .requestId(String.valueOf(requestInfo.getId()))
                .requestType(ApprovalType.getNameByCode(approvalData.getApprovalType()))
                .requestDate(dateFormat.format(requestDate))
                .expirationDate(dateFormat.format(expirationDate))
                .endEntityName(endEntityName)
                .status(ApprovalRequestStatus.fromIntWithCombinedStates(requestInfo.getStatus()))
                .steps(steps);
        builder.certificateProfileName(requestInfo.getCertificateProfileName())
                .endEntityProfileName(requestInfo.getEndEntityProfileName())
                .issuerDn(approvalData.getReqadmincertissuerdn());

        if (approvalRequest instanceof AddEndEntityApprovalRequest request) {
            EndEntityInformation endEntityInformation = request.getEndEntityInformation();
            int tokenTypeInt = endEntityInformation.getTokenType();
            TokenType tokenType = TokenType.resolveTokenTypeByValue( tokenTypeInt);
            if (tokenType != null) {
                builder.token(tokenType.name());
            }
            String keyType = getKeyType(endEntityInformation.getExtendedInformation());
            builder.keyAlgorithm(keyType);
            builder.subjectDn(requestInfo.getRequesterSubjectDN());
        } else if (approvalRequest instanceof EditEndEntityApprovalRequest request) {
            EndEntityInformation endEntityInformation = request.getNewEndEntityInformation();
            int tokenTypeInt = endEntityInformation.getTokenType();
            TokenType tokenType = TokenType.resolveTokenTypeByValue( tokenTypeInt);
            if (tokenType != null) {
                builder.token(tokenType.name());
            }
            String keyType = getKeyType(endEntityInformation.getExtendedInformation());
            builder.keyAlgorithm(keyType);
            builder.subjectDn(requestInfo.getRequesterSubjectDN());
        } else if (approvalRequest instanceof RevocationApprovalRequest) {
//             ((RevocationApprovalRequest) approvalRequest);
            //reason
        }

        return builder.build();
    }

    private static String getKeyType(ExtendedInformation extendedInformation) {
        if (extendedInformation != null && extendedInformation.getKeyStoreAlgorithmType() != null) {
            String keyTypeString = extendedInformation.getKeyStoreAlgorithmType();
            if (extendedInformation.getKeyStoreAlgorithmSubType() != null) {
                keyTypeString = getAlgorithmUiRepresentationString(keyTypeString, extendedInformation.getKeyStoreAlgorithmSubType());
            }
            return keyTypeString;
        } else if (extendedInformation != null && extendedInformation.getCertificateRequest() != null && extendedInformation.getKeyStoreAlgorithmType() == null) {
            return getKeysFromCsr(extendedInformation.getCertificateRequest());
        }
        return null; // null = hidden in UI
    }

    private static String getAlgorithmUiRepresentationString(String alg, String spec) {
        return alg.equals(spec) ? alg : alg + " " + spec;
    }

    private static String getKeysFromCsr(byte[] certificateRequest) {
        if (certificateRequest != null) {
            try {
                PKCS10CertificationRequest pkcs10CertificationRequest = new PKCS10CertificationRequest(certificateRequest);
                final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(pkcs10CertificationRequest);
                final String keySpecification = AlgorithmTools.getKeySpecification(jcaPKCS10CertificationRequest.getPublicKey());
                final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(jcaPKCS10CertificationRequest.getPublicKey());
                return getAlgorithmUiRepresentationString(keyAlgorithm, keySpecification);
            } catch (InvalidKeyException e) {
                log.info("Failed to retrieve public key from CSR for approval request ", e);
            } catch (IOException e) {
                log.info("Failed retrieve CSR attached to end entity for approval request ", e);
            } catch (NoSuchAlgorithmException e) {
                log.info("Unsupported key algorithm attached to CSR for end entity for approval request ", e);
            }
        }
        log.info("No CSR found for end entity with username for approval request");
        return null;
    }
}
