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

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.ArrayList;
import java.util.List;
import org.ejbca.ui.web.rest.api.io.response.ApprovalPartitionPropertyRestResponse;

/**
 * Represents a single approval partition in an approval request.
 */
@Schema(name = "ApprovalPartitionRestRequest", description = "Information about approval partitions")
public class ApprovalPartitionRestRequest {
    @Schema(description = "Partition identifier", example = "0123456")
    private int partitionIdentifier;

    @Schema(description = "Partition properties provided with the approval action")
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ApprovalPartitionPropertyRestResponse> propertyList = new ArrayList<>();

    public ApprovalPartitionRestRequest() {
    }

    public ApprovalPartitionRestRequest(int partitionIdentifier, List<ApprovalPartitionPropertyRestResponse> propertyList) {
        this.partitionIdentifier = partitionIdentifier;
        this.propertyList = propertyList;
    }

    public int getPartitionIdentifier() {
        return partitionIdentifier;
    }

    public void setPartitionIdentifier(int partitionIdentifier) {
        this.partitionIdentifier = partitionIdentifier;
    }

    public List<ApprovalPartitionPropertyRestResponse> getPropertyList() {
        return propertyList;
    }

    public void setPropertyList(List<ApprovalPartitionPropertyRestResponse> propertyList) {
        this.propertyList = propertyList;
    }
}
