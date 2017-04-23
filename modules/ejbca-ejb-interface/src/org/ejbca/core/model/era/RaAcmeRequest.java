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

import org.apache.commons.lang.builder.HashCodeBuilder;

import java.io.Serializable;
import java.util.HashMap;

/**
 * Data for all types of requests from the ACME module on the RA to the CA.
 * 
 * @version $Id$
 */
public class RaAcmeRequest implements Serializable {

    private static final long serialVersionUID = 1L;
    
    /** Certificate Request. <b>Input:</b> CSR. <b>Output:</b> Certificate */
    public static final int TYPE_GETCERT = 10;

    public static final int TYPE_GETNONCE = 20;
    public static final int TYPE_SETNONCE = 21;
    public static final int TYPE_ISNONCE = 22;
    public static final int TYPE_REMNONCE = 23;

    public static final int TYPE_GETREGOBJ = 30;
    public static final int TYPE_SETREGOBJ = 31;
    public static final int TYPE_ISREGOBJ = 32;
    public static final int TYPE_REMREGOBJ = 33;

    public static final int TYPE_GETAUTHOBJ = 40;
    public static final int TYPE_SETAUTHOBJ = 41;
    public static final int TYPE_ISAUTHOBJ = 42;
    public static final int TYPE_REMAUTHOBJ = 43;

    public static final int TYPE_UNSUPPORTED = 90;

    /** Type of request, one of the TYPE_... constants */
    private int type;
    private String acmeBaseUrl;
    
    private byte[] csr;

    /**
     * This contains all the data requested
     */
    private HashMap<String,Object> data = new HashMap();

    public RaAcmeRequest(final String acmeBaseUrl, final int type) {
        this.acmeBaseUrl = acmeBaseUrl;
        this.type = type;
    }

    public void setData(HashMap data){
        this.data = data;
    }

    public void setDataTuple(String k,Object v){
        data.put(k,v);
    }

    public HashMap getData(){
        return this.data;
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
