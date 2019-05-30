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
 * JSON input representation of crypto token key generation request through REST API.
 * @version $Id: CryptoTokenKeyGenerationRestRequest.java 32299 2019-05-08 13:23:48Z lauri_k_helmes $
 *
 */
public class CryptoTokenKeyGenerationRestRequest {

    private String keyPairAlias;
    private String keyAlg;
    private String keySpec;
    
    public CryptoTokenKeyGenerationRestRequest() {}

    public CryptoTokenKeyGenerationRestRequest(String keyPairAlias, String keyAlg, String keySpec) {
        this.keyPairAlias = keyPairAlias;
        this.keyAlg = keyAlg;
        this.keySpec = keySpec;
    }
    
    public String getKeyPairAlias() {
        return keyPairAlias;
    }

    public void setKeyPairAlias(String keyPairAlias) {
        this.keyPairAlias = keyPairAlias;
    }
    
    public String getKeyAlg() {
        return keyAlg;
    }

    public void setKeyAlg(String keyAlg) {
        this.keyAlg = keyAlg;
    }
    
    public String getKeySpec() {
        return keySpec;
    }

    public void setKeySpec(String keySpec) {
        this.keySpec = keySpec;
    }

}
