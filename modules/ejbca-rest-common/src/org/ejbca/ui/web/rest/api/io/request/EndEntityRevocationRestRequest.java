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

import org.ejbca.ui.web.rest.api.validator.ValidEndEntityRevocationRestRequest;

/**
 * JSON input representation of end entity revocation request through REST API.
 */
@ValidEndEntityRevocationRestRequest
public class EndEntityRevocationRestRequest {

    private int reasonCode;
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
