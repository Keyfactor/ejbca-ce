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

/**
 * 
 * @version $Id$
 */
public final class RaApprovalEditRequest implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private final int approvalId;
    private final RaEditableRequestData editableData;
    
    /*// Add end entity requests (from AddEndEntityApprovalRequest)
    private String username;
    private String subjectDN;
    private String subjectAltName;
    private String subjectEmail;
    private int status;
    private int type;
    private int endentityprofileid;
    private int certificateprofileid;*/
    
    // TODO other types of requests
    
    public RaApprovalEditRequest(final int approvalId, final RaEditableRequestData editableData) {
        this.approvalId = approvalId;
        this.editableData = editableData;
    }
    
    public int getApprovalId() {
        return approvalId;
    }
    
    public RaEditableRequestData getEditableData() {
        return editableData;
    }

    /*public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getSubjectDN() {
        return subjectDN;
    }

    public void setSubjectDN(String subjectDN) {
        this.subjectDN = subjectDN;
    }

    public String getSubjectAltName() {
        return subjectAltName;
    }

    public void setSubjectAltName(String subjectAltName) {
        this.subjectAltName = subjectAltName;
    }

    public String getSubjectEmail() {
        return subjectEmail;
    }

    public void setSubjectEmail(String subjectEmail) {
        this.subjectEmail = subjectEmail;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getEndentityprofileid() {
        return endentityprofileid;
    }

    public void setEndentityprofileid(int endentityprofileid) {
        this.endentityprofileid = endentityprofileid;
    }

    public int getCertificateprofileid() {
        return certificateprofileid;
    }

    public void setCertificateprofileid(int certificateprofileid) {
        this.certificateprofileid = certificateprofileid;
    }*/
    
}
