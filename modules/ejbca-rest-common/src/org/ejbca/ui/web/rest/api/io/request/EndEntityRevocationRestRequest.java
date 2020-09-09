package org.ejbca.ui.web.rest.api.io.request;

/**
 * JSON input representation of end entity revocation request through REST API.
 */
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
