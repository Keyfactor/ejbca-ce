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
 * A response from the CA to the ACME module on the RA
 * 
 * @version $Id$
 */
public class RaAcmeResponse implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private byte[] certificate;
    
    public byte[] getCertificate() { return certificate; }
    public void setCertificate(final byte[] certificate) { this.certificate = certificate; }

    @Override
    public int hashCode() {
        return HashCodeBuilder.reflectionHashCode(this);
    }

}
