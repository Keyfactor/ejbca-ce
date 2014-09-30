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

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.List;

import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;

/**
 * Represents a certificate signing request.
 * 
 * @author markus
 * @version $Id$
 */
public class Request {

    private File inFile;
    private List<X509Certificate> signerChain;
    private byte[] requestBytes;
    private UserDataVOWS endEntity;
    private File outFile;
    private String result;
    private boolean done;
    private String requestedDN;

    public Request() {
    }

    public UserDataVOWS getEndEntity() {
        return endEntity;
    }

    public void setEndEntity(UserDataVOWS endEntity) {
        this.endEntity = endEntity;
    }

    public File getInFile() {
        return inFile;
    }

    public void setInFile(File inFile) {
        this.inFile = inFile;
    }

    public File getOutFile() {
        return outFile;
    }

    public void setOutFile(File outFile) {
        this.outFile = outFile;
    }

    public byte[] getRequestBytes() {
        return requestBytes;
    }

    public void setRequestBytes(byte[] requestBytes) {
        this.requestBytes = requestBytes;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public List<X509Certificate> getSignerChain() {
        return signerChain;
    }

    public void setSignerChain(List<X509Certificate> signerChain) {
        this.signerChain = signerChain;
    }

    public boolean isDone() {
        return done;
    }

    public void setDone(boolean done) {
        this.done = done;
    }

    public String getRequestedDN() {
        return requestedDN;
    }

    public void setRequestedDN(String requestedDN) {
        this.requestedDN = requestedDN;
    }

}
