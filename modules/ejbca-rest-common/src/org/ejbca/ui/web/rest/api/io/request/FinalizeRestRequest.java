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
