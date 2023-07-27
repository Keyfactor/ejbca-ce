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

import java.util.List;

/**
 * A class representing the response for EST Alias Configuration requests with CoAP REST method, to discover
 * configured EST aliases.
 *
 * Used for communicating with CoAP Proxy
 */
public class CoapEstAliasConfigurationsRestResponse {

    @ApiModelProperty(value = "Aliases", example = "")
    private List<CoapEstAliasConfigurationRestResponse> aliases;

    public CoapEstAliasConfigurationsRestResponse() {}

    public CoapEstAliasConfigurationsRestResponse(List<CoapEstAliasConfigurationRestResponse> aliases) {
        this.aliases = aliases;
    }

    public List<CoapEstAliasConfigurationRestResponse> getAliases() {
        return aliases;
    }

    public void setAliases(List<CoapEstAliasConfigurationRestResponse> aliases) {
        this.aliases = aliases;
    }
}
