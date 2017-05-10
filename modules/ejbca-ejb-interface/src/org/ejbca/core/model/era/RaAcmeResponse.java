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
import java.util.Map;

/**
 * A response from the CA to the ACME module on the RA
 * 
 * @version $Id$
 */
public class RaAcmeResponse implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private byte[] certificate;

    private Map<String, Object> result;
    private int operation = 0;

    public byte[] getCertificate() { return certificate; }
    public void setCertificate(final byte[] certificate) { this.certificate = certificate; }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

    /**
     * Sets the operation, and the result. since the acme method on the RA contains multiple operations we setup the computed
     * result and operation inside the ACMERESPONSE
     * @param operation
     * @param result
     */
    public void setOperation(int operation, Map<String, Object> result){
        this.operation = operation;
        this.result = result;
    }
    /**
     * This returns an object with information about the response operation and the type of object related to it.
     * @return
     */
    public Map<String, Object> getResult(){
        HashMap<String, Object> result = new HashMap<>();
        result.put("result",this.result);
        result.put("operation",this.operation);
        return result;
    }
}
