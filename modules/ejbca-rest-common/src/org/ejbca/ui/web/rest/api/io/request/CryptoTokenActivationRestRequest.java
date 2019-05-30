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
 * JSON input representation of crypto token activation request through REST API.
 * @version $Id: CryptoTokenActivationRestRequest.java 32242 2019-04-30 15:30:51Z henriks $
 *
 */
public class CryptoTokenActivationRestRequest {

    private String activationCode;
    
    public CryptoTokenActivationRestRequest() {}

    public CryptoTokenActivationRestRequest(String activationCode) {
        this.activationCode = activationCode;
    }
    
    public String getActivationCode() {
        return activationCode;
    }

    public void setActivationCode(String activationCode) {
        this.activationCode = activationCode;
    }

}
