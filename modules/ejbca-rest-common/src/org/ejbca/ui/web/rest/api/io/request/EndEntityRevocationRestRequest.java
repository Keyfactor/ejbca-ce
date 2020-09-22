/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
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
