/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.keyimport;

import java.io.Serializable;
import java.util.List;

/**
 * Holds data about a key import request.
 */
public class KeyImportRequestData implements Serializable {

    private static final long serialVersionUID = 1L;

    private String issuerDn;
    private String certificateProfileName;
    private String endEntityProfileName;
    private List<KeyImportKeystoreData> keystores;

    public KeyImportRequestData(final String caName, final String certificateProfileName,
                                final String endEntityProfileName, final List<KeyImportKeystoreData> keystores) {
        this.issuerDn = caName;
        this.certificateProfileName = certificateProfileName;
        this.endEntityProfileName = endEntityProfileName;
        this.keystores = keystores;
    }

    public String getIssuerDn() {
        return issuerDn;
    }

    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    public String getCertificateProfileName() {
        return certificateProfileName;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return endEntityProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    public List<KeyImportKeystoreData> getKeystores() {
        return keystores;
    }

    public void setKeystores(List<KeyImportKeystoreData> keystores) {
        this.keystores = keystores;
    }
}
