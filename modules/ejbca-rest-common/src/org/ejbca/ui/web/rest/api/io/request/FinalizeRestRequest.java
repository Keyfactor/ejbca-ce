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

/**
 * JSON input representation of finalize enrollment
 * @version $Id: FinalizeRestRequest.java 29317 2018-06-25 08:14:47Z henriks $
 *
 */
public class FinalizeRestRequest {

    private String responseFormat;
    private String password;
    
    public FinalizeRestRequest() {}
    
    public FinalizeRestRequest(String responseFormat, String password) {
        this.responseFormat = responseFormat;
        this.password = password;
    }
    
    public String getResponseFormat() {
        return responseFormat;
    }
    
    /**
     * @param responseFormat of the certificate or keystore. Must be one of
     * 'P12', 'JKS', 'PEM' or 'DER'
     */
    public void setResponseFormat(String responseFormat) {
        this.responseFormat = responseFormat;
    }
    
    public String getPassword() {
        return password;
    }
    
    /**
     * @param password used for inital request
     */
    public void setPassword(String password) {
        this.password = password;
    }
}
