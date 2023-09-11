package org.ejbca.ui.web.rest.api.io.response;

import io.swagger.annotations.ApiModelProperty;

public class RunServiceRestResponse {
    @ApiModelProperty(value = "service_name", example = "Running service: SERVICE NAME")
    private String run_service;
    private String serviceName;

    private RunServiceRestResponse(String serviceName) {
        this.serviceName = serviceName;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static RunServiceRestResponseBuilder builder() {
        return new RunServiceRestResponseBuilder();
    }

    public String getServiceName() {
        return serviceName;
    }

    public static class RunServiceRestResponseBuilder {
        private String serviceName;

        private RunServiceRestResponseBuilder() {

        }

        public RunServiceRestResponseBuilder message(String serviceName) {
            this.serviceName = serviceName;
            return this;
        }

        public RunServiceRestResponse build() {
            return new RunServiceRestResponse(serviceName);
        }
    }

}
