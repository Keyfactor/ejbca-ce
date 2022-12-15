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
package org.ejbca.ui.web.rest.api.io.request;

import java.util.Date;
import java.util.List;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidAddEndEntityRestRequest;

import io.swagger.annotations.ApiModelProperty;

/**
 * JSON input for registration of end entity.
 */
@ValidAddEndEntityRestRequest
public class AddEndEntityRestRequest {

    @ApiModelProperty(value = "Username", example = "JohnDoe")
	private String username;
    @ApiModelProperty(value = "Password", example = "foo123")
    private String password;
    @ApiModelProperty(value = "Subject Distinguished Name", example = "CN=John Doe,SURNAME=Doe,GIVENNAME=John,C=SE")
    private String subjectDn;
    @ApiModelProperty(value = "Subject Alternative Name (SAN)", example = "rfc822Name=john.doe@example.com")
    private String subjectAltName;
    @ApiModelProperty(value = "Email", example = "john.doe@example.com")
    private String email;
    private List<ExtendedInformationRestRequestComponent> extensionData;
    @ApiModelProperty(value = "Certificate Authority (CA) name", example = "CN=ExampleCA")
    private String caName;
    @ApiModelProperty(value = "Certificate profile name", example = "ENDUSER")
    private String certificateProfileName;
    @ApiModelProperty(value = "End Entity profile name", example = "ExampleEEP")
    private String endEntityProfileName;
    @ApiModelProperty(value = "Token type property", allowableValues = "USERGENERATED, P12, JKS, PEM", example = "P12")
    private String token;
    @ApiModelProperty(value = "Account Binding ID", example = "1234567890")
    private String accountBindingId;
    
    /** default constructor needed for serialization */
    public AddEndEntityRestRequest() {}

    public static class Builder {
        private String username;
        private String password;
        private String subjectDn;
        private String subjectAltName;
        private String email;
        private List<ExtendedInformationRestRequestComponent> extensionData;
        private String caName;
        private String certificateProfileName;
        private String endEntityProfileName;
        private String token;
        private String accountBindingId;

        
        public Builder certificateProfileName(final String certificateProfileName) {
            this.certificateProfileName = certificateProfileName;
            return this;
        }

        public Builder endEntityProfileName(final String endEntityProfileName) {
            this.endEntityProfileName = endEntityProfileName;
            return this;
        }

        public Builder caName(final String caName) {
            this.caName = caName;
            return this;
        }

        public Builder username(final String username) {
            this.username = username;
            return this;
        }

        public Builder password(final String password) {
            this.password = password;
            return this;
        }

        
        public Builder subjectDn(String subjectDn) {
            this.subjectDn = subjectDn;
            return this;
        }

        public Builder subjectAltName(String subjectAltName) {
            this.subjectAltName = subjectAltName;
            return this;
        }

        public Builder email(String email) {
            this.email = email;
            return this;
        }

        public Builder extensionData(List<ExtendedInformationRestRequestComponent> extensionData) {
            this.extensionData = extensionData;
            return this;
        }

        public Builder token(String token) {
            this.token = token;
            return this;
        }
        
        public Builder accountBindingId(String accountBindingId) {
            this.accountBindingId = accountBindingId;
            return this;
        }

        public AddEndEntityRestRequest build() {
            return new AddEndEntityRestRequest(this);
        }
    }
    
    private AddEndEntityRestRequest(final Builder builder) {
        this.certificateProfileName = builder.certificateProfileName;
        this.endEntityProfileName = builder.endEntityProfileName;
        this.caName = builder.caName;
        this.username = builder.username;
        this.password = builder.password;
        this.subjectDn = builder.subjectDn;
        this.subjectAltName = builder.subjectAltName;
        this.email = builder.email;
        this.extensionData = builder.extensionData;
        this.token = builder.token;
        this.accountBindingId = builder.accountBindingId;
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static AddEndEntityRestRequestConverter converter() {
        return new AddEndEntityRestRequestConverter();
    }

    public static class AddEndEntityRestRequestConverter {

        public EndEntityInformation toEntity(final AddEndEntityRestRequest addEndEntityRestRequest) throws RestException {
            final ExtendedInformation extendedInfo = new ExtendedInformation();
            if (addEndEntityRestRequest.getAccountBindingId() != null || addEndEntityRestRequest.getExtensionData() != null && !addEndEntityRestRequest.getExtensionData().isEmpty()) {
                if (addEndEntityRestRequest.getAccountBindingId() != null) {
                    extendedInfo.setAccountBindingId(addEndEntityRestRequest.getAccountBindingId());
                }
                if (addEndEntityRestRequest.getExtensionData() != null && !addEndEntityRestRequest.getExtensionData().isEmpty()) {
                    addEndEntityRestRequest.getExtensionData().forEach((extendedInformation) -> {
                        // There are two different types of ExtendedInformation, Extension Data (custom extensions) and 
                        // Custom Data (other fields like validity, certificate serial number and other things)
                        // See ExtendedInformation
                        if (extendedInformation.getName().startsWith("customdata_")) {
                            extendedInfo.setCustomData(extendedInformation.getName().substring(11), extendedInformation.getValue());
                        } else {
                            extendedInfo.setExtensionData(extendedInformation.getName(), extendedInformation.getValue());
                        }
                    });
                }
            }
            extendedInfo.setCustomData(ExtendedInformation.MARKER_FROM_REST_RESOURCE, "dummy");
            extendedInfo.setCustomData(ExtendedInformation.CA_NAME, addEndEntityRestRequest.getCaName());
            extendedInfo.setCustomData(ExtendedInformation.CERTIFICATE_PROFILE_NAME, addEndEntityRestRequest.getCertificateProfileName());
            extendedInfo.setCustomData(ExtendedInformation.END_ENTITY_PROFILE_NAME, addEndEntityRestRequest.getEndEntityProfileName());
            
            final Date now = new Date();
            final int tokenType = TokenType.resolveEndEntityTokenByName(addEndEntityRestRequest.getToken()).getTokenValue();
            final EndEntityInformation eeInformation = new EndEntityInformation(
                    addEndEntityRestRequest.getUsername(), 
                    addEndEntityRestRequest.getSubjectDn(), 
                    Integer.MIN_VALUE,  
                    addEndEntityRestRequest.getSubjectAltName(), 
                    addEndEntityRestRequest.getEmail(),
                    EndEntityConstants.STATUS_NEW, 
                    EndEntityTypes.ENDUSER.toEndEntityType(), 
                    Integer.MIN_VALUE, 
                    Integer.MIN_VALUE, 
                    now,
                    now,
                    tokenType,
                    extendedInfo);
            eeInformation.setPassword(addEndEntityRestRequest.getPassword());
            return eeInformation;
        }
    }

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getSubjectDn() {
		return subjectDn;
	}

	public void setSubjectDn(String subjectDn) {
		this.subjectDn = subjectDn;
	}

	public String getSubjectAltName() {
		return subjectAltName;
	}

	public void setSubjectAltName(String subjectAltName) {
		this.subjectAltName = subjectAltName;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public List<ExtendedInformationRestRequestComponent> getExtensionData() {
		return extensionData;
	}

	public void setExtensionData(List<ExtendedInformationRestRequestComponent> extensionData) {
		this.extensionData = extensionData;
	}

	public String getCaName() {
		return caName;
	}

	public void setCaName(String caName) {
		this.caName = caName;
	}

	public String getCertificateProfileName() {
		return certificateProfileName;
	}

	public void setCertificateProfileName(String certificateProfileName) {
		this.certificateProfileName = certificateProfileName;
	}

	public String getEndEntityProfileName() {
		return endEntityProfileName;
	}

	public void setEndEntityProfileName(String endEntityProfileName) {
		this.endEntityProfileName = endEntityProfileName;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}
	
    public String getAccountBindingId() {
        return accountBindingId;
    }

    public void setAccountBindingId(String accountBindingId) {
        this.accountBindingId = accountBindingId;
    }	
	
	public enum EndEntityStatus {
    	NEW(EndEntityConstants.STATUS_NEW),
    	FAILED(EndEntityConstants.STATUS_FAILED),
    	INITIALIZED(EndEntityConstants.STATUS_INITIALIZED),
    	INPROCESS(EndEntityConstants.STATUS_INPROCESS),
    	GENERATED(EndEntityConstants.STATUS_GENERATED),
    	REVOKED(EndEntityConstants.STATUS_REVOKED),
    	HISTORICAL(EndEntityConstants.STATUS_HISTORICAL),
    	KEYRECOVERY(EndEntityConstants.STATUS_KEYRECOVERY),
    	WAITINGFORADDAPPROVAL(EndEntityConstants.STATUS_WAITINGFORADDAPPROVAL);

        private final int statusValue;

        EndEntityStatus(final int statusValue) {
            this.statusValue = statusValue;
        }

        public int getStatusValue() {
            return statusValue;
        }

        /**
         * Resolves the EndEntityStatus using its name or returns null.
         *
         * @param name status name.
         *
         * @return EndEntityStatus using its name or null.
         */
        public static EndEntityStatus resolveEndEntityStatusByName(final String name) {
            for (EndEntityStatus endEntityStatus : values()) {
                if (endEntityStatus.name().equalsIgnoreCase(name)) {
                    return endEntityStatus;
                }
            }
            return null;
        }

    }
	
	public enum TokenType {
    	USERGENERATED(EndEntityConstants.TOKEN_USERGEN),
    	P12(EndEntityConstants.TOKEN_SOFT_P12),
    	JKS(EndEntityConstants.TOKEN_SOFT_JKS),
    	PEM(EndEntityConstants.TOKEN_SOFT_PEM);

        private final int tokenValue;

        TokenType(final int tokenValue) {
            this.tokenValue = tokenValue;
        }

        public int getTokenValue() {
            return tokenValue;
        }

        /**
         * Resolves the TokenType using its name or returns null.
         *
         * @param name status name.
         *
         * @return TokenType using its name or null.
         */
        public static TokenType resolveEndEntityTokenByName(final String name) {
            for (TokenType tokenType : values()) {
                if (tokenType.name().equalsIgnoreCase(name)) {
                    return tokenType;
                }
            }
            return null;
        }

    }

}
