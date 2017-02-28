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
package org.ejbca.core.model.era;

import java.io.Serializable;

import org.apache.commons.lang.builder.HashCodeBuilder;

/**
 * Data for all types of requests from the ACME module on the RA to the CA.
 * 
 * @version $Id$
 */
public class RaAcmeRequest implements Serializable {

    private static final long serialVersionUID = 1L;
    
    /** Certificate Request. <b>Input:</b> CSR. <b>Output:</b> Certificate */
    public static final int TYPE_CERTREQ = 1;
    
    /** Type of request, one of the TYPE_... constants */
    private int type;
    private String acmeBaseUrl;
    
    private byte[] csr;
    
    
    public RaAcmeRequest(final String acmeBaseUrl, final int type) {
        this.acmeBaseUrl = acmeBaseUrl;
        this.type = type;
    }
    
    
    public String getAcmeBaseUrl() { return acmeBaseUrl; }
    public void setAcmeBaseUrl(final String acmeBaseUrl) { this.acmeBaseUrl = acmeBaseUrl; }
    
    public int getType() { return type; }
    public void setType(final int type) { this.type = type; }
    
    public byte[] getCsr() { return csr; }
    public void setCsr(final byte[] csr) { this.csr = csr; }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

}
