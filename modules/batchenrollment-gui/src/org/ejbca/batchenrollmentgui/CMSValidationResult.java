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
package org.ejbca.batchenrollmentgui;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 *
 * @author markus
 * @version $Id$
 */
public class CMSValidationResult {
    
    private boolean validSignature;
    private boolean validChain;
    private String error;
    private byte[] content;
    private List<X509Certificate> signerChain;

    public boolean isValidSignature() {
        return validSignature;
    }

    public void setValidSignature(boolean validSignature) {
        this.validSignature = validSignature;
    }

    public boolean isValidChain() {
        return validChain;
    }

    public void setValidChain(boolean validChain) {
        this.validChain = validChain;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    public List<X509Certificate> getSignerChain() {
        return signerChain;
    }

    public void setSignerChain(List<X509Certificate> signerChain) {
        this.signerChain = signerChain;
    }

    
    
}
