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

import java.util.List;

import io.swagger.annotations.ApiModelProperty;
import org.cesecore.certificates.endentity.EndEntityConstants;

/**
 * A class representing general information about end entity. Is used for REST services' responses.
 */
public class EndEntityRestResponse {

    @ApiModelProperty(value = "Username", example = "JohnDoe")
    private String username;
    @ApiModelProperty(value = "Subject Distinguished Name", example = "CN=John Doe,SURNAME=Doe,GIVENNAME=John,C=SE")
    private String dn;
    @ApiModelProperty(value = "Subject Alternative Name (SAN)", example = "rfc822Name=john.doe@example.com")
    private String subjectAltName;
    @ApiModelProperty(value = "Email", example = "john.doe@example.com")
    private String email;
    @ApiModelProperty(value = "End Entity status", example = "NEW",
            allowableValues = "NEW, FAILED, INITIALIZED, INPROCESS, GENERATED, REVOKED, HISTORICAL, KEYRECOVERY, WAITINGFORADDAPPROVAL"
    )
    private String status;
    @ApiModelProperty(value = "Token type", example = "P12", allowableValues = "USERGENERATED, P12, BCFKS, JKS, PEM")
    private String token;
    @ApiModelProperty(value = "Extended Information")
    private List<ExtendedInformationRestResponseComponent> extensionData;

    private EndEntityRestResponse(String username, String dn, String subjectAltName, String email, String status, String token,
    		List<ExtendedInformationRestResponseComponent> extensionData) {
        this.username = username;
        this.dn = dn;
        this.subjectAltName = subjectAltName;
        this.email = email;
        this.status = status;
        this.token = token;
        this.extensionData = extensionData;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static EndEntityRestResponseBuilder builder() {
        return new EndEntityRestResponseBuilder();
    }

    public String getUsername() {
        return username;
    }
    
    public String getDn() {
		return dn;
	}

	public String getSubjectAltName() {
		return subjectAltName;
	}

	public String getEmail() {
		return email;
	}

	public String getStatus() {
		return status;
	}
	
	public String getToken() {
		return token;
	}
	
	public List<ExtendedInformationRestResponseComponent> getExtensionData() {
		return extensionData;
	}
    
    public static class EndEntityRestResponseBuilder {
        private String username;
        private String dn;
        private String subjectAltName;
        private String email;
        private String status;
        private String token;
        private List<ExtendedInformationRestResponseComponent> extensionData;
        
        private EndEntityRestResponseBuilder() {
        }

        public EndEntityRestResponseBuilder setUsername(String username) {
            this.username = username;
            return this;
        }
        public EndEntityRestResponseBuilder setDn(String dn) {
            this.dn = dn;
            return this;
        }
        public EndEntityRestResponseBuilder setEmail(String email) {
            this.email = email;
            return this;
        }
        public EndEntityRestResponseBuilder setSubjectAltName(String subjectAltName) {
            this.subjectAltName = subjectAltName;
            return this;
        }
        public EndEntityRestResponseBuilder setStatus(String status) {
            this.status = status;
            return this;
        }
        public EndEntityRestResponseBuilder setToken(int token) {
            this.token = getTokenType(token);
            return this;
        }
        public EndEntityRestResponseBuilder setExtensionData(List<ExtendedInformationRestResponseComponent> extensionData) {
        	this.extensionData = extensionData;
        	return this;
        }
        
        public EndEntityRestResponse build() {
            return new EndEntityRestResponse(username, dn, subjectAltName, email, status, token, extensionData);
        }
        
        public String getTokenType(int token) {
            switch (token) {
            case EndEntityConstants.TOKEN_USERGEN:
                return "USERGENERATED";
            case EndEntityConstants.TOKEN_SOFT_JKS:
                return "JKS";
            case EndEntityConstants.TOKEN_SOFT_P12:
                return "P12";
            case EndEntityConstants.TOKEN_SOFT_PEM:
                return "PEM";
            }
            return "?";
        }
    }

}
