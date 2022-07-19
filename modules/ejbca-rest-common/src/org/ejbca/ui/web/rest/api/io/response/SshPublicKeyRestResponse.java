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

/**
 * A class containing a public key in SSH format
 *
 */
public class SshPublicKeyRestResponse {

    private final String caName;
    private final byte[] response;

    public SshPublicKeyRestResponse(final String caName, final byte[] response) {
        this.caName = caName;
        this.response = response;
    }


    public String getCaName() {
        return caName;
    }


    public byte[] getResponse() {
        return response;
    }
  
}
