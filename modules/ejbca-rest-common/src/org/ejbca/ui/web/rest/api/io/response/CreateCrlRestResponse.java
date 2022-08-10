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
package org.ejbca.ui.web.rest.api.io.response;

import io.swagger.annotations.ApiModelProperty;

import java.util.Map;

public class CreateCrlRestResponse {

    @ApiModelProperty(value = "Issuer Distinguished Name", example = "CN=ExampleCA")
    private String issuerDn;

    @ApiModelProperty(value = "Latest base CRL version", example = "10")
    private int latestCrlVersion;

    @ApiModelProperty(value = "Latest delta CRL version", example = "5")
    private int latestDeltaCrlVersion;

    private Map<String, Integer> latestPartitionCrlVersions;

    private Map<String, Integer> latestPartitionDeltaCrlVersions;
    
    private boolean allSuccess;

    public String getIssuerDn() {
        return issuerDn;
    }

    public void setIssuerDn(String issuerDn) {
        this.issuerDn = issuerDn;
    }

    public int getLatestCrlVersion() {
        return latestCrlVersion;
    }

    public void setLatestCrlVersion(int latestCrlVersion) {
        this.latestCrlVersion = latestCrlVersion;
    }

    public int getLatestDeltaCrlVersion() {
        return latestDeltaCrlVersion;
    }

    public void setLatestDeltaCrlVersion(int latestDeltaCrlVersion) {
        this.latestDeltaCrlVersion = latestDeltaCrlVersion;
    }

    public Map<String, Integer> getLatestPartitionCrlVersions() {
        return latestPartitionCrlVersions;
    }

    public void setLatestPartitionCrlVersions(Map<String, Integer> latestPartitionCrlVersions) {
        this.latestPartitionCrlVersions = latestPartitionCrlVersions;
    }

    public Map<String, Integer> getLatestPartitionDeltaCrlVersions() {
        return latestPartitionDeltaCrlVersions;
    }

    public void setLatestPartitionDeltaCrlVersions(Map<String, Integer> latestPartitionDeltaCrlVersions) {
        this.latestPartitionDeltaCrlVersions = latestPartitionDeltaCrlVersions;
    }

    public boolean isAllSuccess() {
        return allSuccess;
    }

    public void setAllSuccess(boolean allSuccess) {
        this.allSuccess = allSuccess;
    }
    
}
