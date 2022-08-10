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
import org.ejbca.ui.web.rest.api.validator.ValidEndEntityRevocationRestRequest;

/**
 * JSON input representation of end entity revocation request through REST API.
 */
@ValidEndEntityRevocationRestRequest
@ApiModel(description = "End Entity revocation request. Available reason codes: \n" +
        " 0 - Unspecified,\n" +
        " 1 - Key Compromise,\n" +
        " 2 - CA Compromise,\n" +
        " 3 - Affiliation Changed,\n" +
        " 4 - Superseded,\n" +
        " 5 - Cessation of Operation,\n" +
        " 6 - Certificate Hold,\n" +
        " 8 - Remove from CRL,\n" +
        " 9 - Privileges Withdrawn,\n" +
        " 10 - AA Compromise")
public class EndEntityRevocationRestRequest {

    @ApiModelProperty(value = "Reason code", example = "2", allowableValues = "0, 1, 2, 3, 4, 5, 6, 8, 9, 10")
    private int reasonCode;
    @ApiModelProperty(value = "Delete", example = "true", allowableValues = "true, false")
    private boolean delete;
    
    public EndEntityRevocationRestRequest() {}

    public EndEntityRevocationRestRequest(int reasonCode, boolean delete) {
        this.reasonCode = reasonCode;
        this.delete = delete;
    }
    
    public int getReasonCode() {
        return reasonCode;
    }

    public void setReasonCode(int reasonCode) {
        this.reasonCode = reasonCode;
    }

    public boolean isDelete() {
    	return delete;
    }
    
    public void setDelete(boolean delete) {
    	this.delete = delete;
    }
}
