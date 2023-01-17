package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.annotations.ApiModelProperty;

public class SshCriticalOptions {
    @ApiModelProperty(value = "force-command", example = "./init.sh")
    String forceCommand;
    @ApiModelProperty(value = "source-address", example = "1.2.3.0/24,1.10.10.1/32")
    String sourceAddress;

    public SshCriticalOptions() {
    }

    public SshCriticalOptions(String forceCommand, String sourceAddress, String verifyRequired) {
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
