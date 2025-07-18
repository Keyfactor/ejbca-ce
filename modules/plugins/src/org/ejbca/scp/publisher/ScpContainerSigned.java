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
package org.ejbca.scp.publisher;

public class ScpContainerSigned {

    private String signature;
    private ScpContainerWrapper data;

    public ScpContainerSigned() {
        this.data =  new ScpContainerWrapper();
    }

    public ScpContainerSigned(final ScpContainerWrapper containerWrapper) {
        this.data = containerWrapper;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getSignature() {
        return signature;
    }

    public ScpContainerWrapper getData() {
        return data;
    }

    public void setData(ScpContainerWrapper data) {
        this.data = data;
    }
}

    