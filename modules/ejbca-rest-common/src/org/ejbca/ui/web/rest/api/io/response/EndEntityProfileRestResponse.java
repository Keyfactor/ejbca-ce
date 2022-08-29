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

/**
 * This is used to build a response for authorized eep key-values.
 */
public class EndEntityProfileRestResponse {

    @ApiModelProperty(value = "End Entity profile name", example = "ExampleEEP")
    private String name;
    @ApiModelProperty(value = "End Entity profile ID", example = "1234567890")
    private long id;
    @ApiModelProperty(value = "Description", example = "Example End Entity profile")
    private String description;

    private EndEntityProfileRestResponse(final String name, final long id, final String description) {
        this.name = name;
        this.id = id;
        this.description = description;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
    
    
    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static EndEntityProfileRestResponseBuilder builder() {
        return new EndEntityProfileRestResponseBuilder();
    }
    

    public static class EndEntityProfileRestResponseBuilder {
        private String name;
        private long id;
        private String description;

        private EndEntityProfileRestResponseBuilder() {
        }

        public EndEntityProfileRestResponseBuilder setName(final String name) {
            this.name = name;
            return this;
        }

        public EndEntityProfileRestResponseBuilder setId(final long id) {
            this.id = id;
            return this;
        }

        public EndEntityProfileRestResponseBuilder setDescription(final String description) {
            this.description = description;
            return this;
        }

        public EndEntityProfileRestResponse build() {
            return new EndEntityProfileRestResponse(name, id, description);
        }

    }

}
