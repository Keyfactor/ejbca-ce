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
public class RaEditableRequestData implements Serializable, Cloneable {

    private static final long serialVersionUID = 1L;

    // For add end entity requests
    private String username;
    private String subjectDN;
    private String subjectAltName;
    private String subjectDirAttrs;
    private String email;
    
    public String getUsername() {
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

    public String getSubjectDirAttrs() {
        return subjectDirAttrs;
    }

    public void setSubjectDirAttrs(String subjectDirAttrs) {
        this.subjectDirAttrs = subjectDirAttrs;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public RaEditableRequestData clone() {
        try {
            return (RaEditableRequestData) super.clone();
        } catch (CloneNotSupportedException e) {
            throw new IllegalStateException("Object should be clonable");
        }
    }
    
}
