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

import io.swagger.annotations.ApiModelProperty;

/**
 * A class representing the input for critical options in SSH certificate request REST method.
 */
public class SshCriticalOptions {
    @ApiModelProperty(value = "force-command", example = "./init.sh")
    String forceCommand;
    @ApiModelProperty(value = "source-address", example = "1.2.3.0/24,1.10.10.1/32")
    String sourceAddress;

    public SshCriticalOptions() {
    }

    public SshCriticalOptions(String forceCommand, String sourceAddress) {
        this.forceCommand = forceCommand;
        this.sourceAddress = sourceAddress;
    }

    public String getForceCommand() {
        return forceCommand;
    }

    public void setForceCommand(String forceCommand) {
        this.forceCommand = forceCommand;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }

    public void setSourceAddress(String sourceAddress) {
        this.sourceAddress = sourceAddress;
    }
}
