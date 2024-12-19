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
package org.ejbca.ui.web.rest.api.io.request;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;
import io.swagger.v3.oas.annotations.media.Schema;
import org.ejbca.ui.web.rest.api.validator.ValidKeyImportRestRequest;

import java.util.List;

/**
 * JSON input for import of one or many keystores to CA.
 */
@ValidKeyImportRestRequest
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public class KeyImportRestRequest {

    @Schema(description = "Certificate Profile Name", example = "ENDUSER")
    private String certificateProfileName;
    @Schema(description = "End Entity Profile Name", example = "ExampleEEP")
    private String endEntityProfileName;
    private List<KeystoreRestRequestComponent> keystores;

    public KeyImportRestRequest() {
    }

    public KeyImportRestRequest(String certificateProfileName, String endEntityProfileName, List<KeystoreRestRequestComponent> keystores) {
        this.certificateProfileName = certificateProfileName;
        this.endEntityProfileName = endEntityProfileName;
        this.keystores = keystores;
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

    public List<KeystoreRestRequestComponent> getKeystores() {
        return keystores;
    }

    public void setKeystores(List<KeystoreRestRequestComponent> keystores) {
        this.keystores = keystores;
    }
}
