/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise CryptoToken Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.response;

/**
 * A class representing information about a crypto token. Is used for REST services' responses.
 *
 * @version $Id$
 */
public class CryptoTokenRestResponse {

    private String message;

    private CryptoTokenRestResponse(String message) {
        this.message = message;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static CryptoTokenRestResponseBuilder builder() {
        return new CryptoTokenRestResponseBuilder();
    }

    public String getMessage() {
        return message;
    }
    
    public static class CryptoTokenRestResponseBuilder {
        private String message;
        
        private CryptoTokenRestResponseBuilder() {
            
        }

        public CryptoTokenRestResponseBuilder message(String message) {
            this.message = message;
            return this;
        }
        
        public CryptoTokenRestResponse build() {
            return new CryptoTokenRestResponse(message);
        }
    }
}
