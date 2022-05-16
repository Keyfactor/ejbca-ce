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

import org.cesecore.util.StringTools;

import java.io.Serializable;

public class RaSelfRenewCertificateData  implements Serializable {

    private static final long serialVersionUID = 1L;

    private String username;
    private String password;
    private String newSubjectDn;
    private String clientIPAddress;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return StringTools.getBase64String(password);
    }

    public void setPassword(String password) {
        this.password = StringTools.putBase64String(password);;
    }

    public String getNewSubjectDn() {
        return newSubjectDn;
    }

    public void setNewSubjectDn(String newSubjectDn) {
        this.newSubjectDn = newSubjectDn;
    }

    public String getClientIPAddress() {
        return clientIPAddress;
    }

    public void setClientIPAddress(String clientIPAddress) {
        this.clientIPAddress = clientIPAddress;
    }
}
