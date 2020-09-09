package org.ejbca.ui.web.rest.api.io.request;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidAddEndEntityRestRequest;

import io.swagger.annotations.ApiModelProperty;

import java.util.List;

/**
 * JSON input for registration of end entity.
 */
@ValidAddEndEntityRestRequest
public class AddEndEntityRestRequest {

	private String username;
    private String password;
    private String subjectDn;
    private String subjectAltName;
    private String email;
    private List<ExtendedInformationRestRequestComponent> extensionData;
    private String caName;
    private String certificateProfileName;
    private String endEntityProfileName;
    @ApiModelProperty(value = "Token type property",
            allowableValues = "USERGENERATED, P12, JKS, PEM"
    )
    private String token;
    
    public AddEndEntityRestRequest() {}
    
    public AddEndEntityRestRequest(String username, String password, String subjectDn, String subjectAltName,
			String email, List<ExtendedInformationRestRequestComponent> extensionData, String caName,
			String certificateProfileName, String endEntityProfileName, String token) {
		super();
		this.username = username;
		this.password = password;
		this.subjectDn = subjectDn;
		this.subjectAltName = subjectAltName;
		this.email = email;
		this.extensionData = extensionData;
		this.caName = caName;
		this.certificateProfileName = certificateProfileName;
		this.endEntityProfileName = endEntityProfileName;
		this.token = token;
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

        public EndEntityInformation toEntity(final AddEndEntityRestRequest addEndEntityRestRequest, Integer caId,
        		Integer endEntityProfileId, Integer certificateProfileId) throws RestException {
            final EndEntityInformation eeInformation = new EndEntityInformation();
            eeInformation.setUsername(addEndEntityRestRequest.getUsername());
            eeInformation.setPassword(addEndEntityRestRequest.getPassword());
            eeInformation.setDN(addEndEntityRestRequest.getSubjectDn());
            eeInformation.setSubjectAltName(addEndEntityRestRequest.getSubjectAltName());
            eeInformation.setEmail(addEndEntityRestRequest.getEmail());
            if (addEndEntityRestRequest.getExtensionData() != null && !addEndEntityRestRequest.getExtensionData().isEmpty()) {
            	ExtendedInformation ei = new ExtendedInformation();
            	addEndEntityRestRequest.getExtensionData().forEach((extendedInformation) -> {
            		ei.setCustomData(extendedInformation.getName(), extendedInformation.getValue());
            	});
            	eeInformation.setExtendedInformation(ei);
            }
            eeInformation.setCAId(caId);
            eeInformation.setCertificateProfileId(certificateProfileId);
            eeInformation.setEndEntityProfileId(endEntityProfileId);
            eeInformation.setStatus(EndEntityConstants.STATUS_NEW);
            eeInformation.setTokenType(TokenType.resolveEndEntityTokenByName(addEndEntityRestRequest.getToken()).getTokenValue());
        	
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
    	PEM(EndEntityConstants.TOKEN_SOFT);

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
