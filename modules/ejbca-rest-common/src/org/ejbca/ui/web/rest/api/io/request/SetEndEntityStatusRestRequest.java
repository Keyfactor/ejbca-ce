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

import io.swagger.v3.oas.annotations.media.Schema;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.ui.web.rest.api.validator.ValidEndEntityStatusRestRequest;

/**
 * JSON input for editing of end entity.
 */
@Schema(description = "Use one of allowed values as property(see enum values below).\n" +
        "Available TOKEN - USERGENERATED, P12, BCFKS, JKS, PEM; \n" +
        "Available STATUS - NEW, FAILED, INITIALIZED, INPROCESS, GENERATED, REVOKED, HISTORICAL, KEYRECOVERY, WAITINGFORADDAPPROVAL;\n"
)
@ValidEndEntityStatusRestRequest
public class SetEndEntityStatusRestRequest {

    @Schema(description = "Password", example = "foo123")
    private String password;
    @Schema(description = "Token type property", example = "USERGENERATED",
            allowableValues = "USERGENERATED, P12, BCFKS, JKS, PEM"
    )
    private String token;
    @Schema(description = "End entity status property", example = "NEW",
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


}
