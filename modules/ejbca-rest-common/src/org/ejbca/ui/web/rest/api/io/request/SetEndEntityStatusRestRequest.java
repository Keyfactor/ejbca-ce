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

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.ui.web.rest.api.validator.ValidEndEntityStatusRestRequest;

/**
 * JSON input for editing of end entity.
 */
@ApiModel(description = "Use one of allowed values as property(see enum values below).\n" +
        "Available TOKEN - USERGENERATED, P12, BCFKS, JKS, PEM; \n" +
        "Available STATUS - NEW, FAILED, INITIALIZED, INPROCESS, GENERATED, REVOKED, HISTORICAL, KEYRECOVERY, WAITINGFORADDAPPROVAL;\n"
)
@ValidEndEntityStatusRestRequest
public class SetEndEntityStatusRestRequest {

    @ApiModelProperty(value = "Password", example = "foo123")
    private String password;
    @ApiModelProperty(value = "Token type property", example = "USERGENERATED",
            allowableValues = "USERGENERATED, P12, BCFKS, JKS, PEM"
    )
    private String token;
    @ApiModelProperty(value = "End entity status property", example = "NEW",
            allowableValues = "NEW, FAILED, INITIALIZED, INPROCESS, GENERATED, REVOKED, HISTORICAL, KEYRECOVERY, WAITINGFORADDAPPROVAL"
    )
    private String status;
    
    public SetEndEntityStatusRestRequest() {}
    
    public SetEndEntityStatusRestRequest(String password, String token, String status) {
		super();
		this.password = password;
		this.token = token;
		this.status = status;
	}
    
    public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
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
        BCFKS(EndEntityConstants.TOKEN_SOFT_BCFKS),
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
