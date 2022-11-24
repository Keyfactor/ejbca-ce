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
package org.ejbca.ui.web.rest.api.io.response;

import io.swagger.annotations.ApiModelProperty;

/**
 * A class representing information about a crypto token. Is used for REST services' responses.
 *
 * @version $Id: CryptoTokenRestResponse.java 32295 2019-05-07 13:00:44Z lauri_k_helmes $
 */
public class CryptoTokenRestResponse {

    @ApiModelProperty(value = "Response message", example = "The crypto token was deactivated successfully.")
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
