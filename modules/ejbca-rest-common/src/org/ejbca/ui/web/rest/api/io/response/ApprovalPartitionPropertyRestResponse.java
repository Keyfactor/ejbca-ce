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

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

@Schema(name = "ApprovalPartitionPropertyRestResponse", description = "Information about an approval partition properties")
public class ApprovalPartitionPropertyRestResponse {
    @Schema(description = "Property label")
    private String label;
    @Schema(description = "Property value")
    private String  value;
    @Schema(description = "Property type")
    private String  type;
    @Schema(description = "Property possible values")
    private List<String> possibleValues;

    public ApprovalPartitionPropertyRestResponse(Builder builder) {
        this.label = builder.label;
        this.value = builder.value;
        this.type = builder.type;
        this.possibleValues = builder.possibleValues;
    }

    public String getLabel() {
        return label;
    }

    public String getValue() {
        return value;
    }

    public String getType() {
        return type;
    }

    public List<String> getPossibleValues() {
        return possibleValues;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {
        private String label;
        private String  value;
        private String  type;
        private List<String> possibleValues;

        public Builder label(String label) {
            this.label = label;
            return this;
        }

        public Builder value(String value) {
            this.value = value;
            return this;
        }
        public Builder type(String type) {
            this.type = type;
            return this;
        }
        public Builder possibleValues(List<String> possibleValues) {
            this.possibleValues = possibleValues;
            return this;
        }

        public ApprovalPartitionPropertyRestResponse build(){
            return new ApprovalPartitionPropertyRestResponse(this);
        }

    }
}
