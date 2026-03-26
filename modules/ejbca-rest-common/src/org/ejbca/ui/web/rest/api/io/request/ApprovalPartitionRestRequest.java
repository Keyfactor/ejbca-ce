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

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.Valid;
import java.util.ArrayList;
import java.util.List;

/**
 * Represents a single approval partition in an approval request.
 */
@Schema(name = "ApprovalPartitionRestRequest", description = "Information about approval partitions")
public class ApprovalPartitionRestRequest {
    @Schema(description = "Partition identifier", example = "0123456")
    private int partitionIdentifier;

    @Schema(description = "Partition properties provided with the approval action")
    @Valid
    private List<ApprovalPartitionPropertyRestRequest> propertyList = new ArrayList<>();

    public ApprovalPartitionRestRequest() {
    }

    public int getPartitionIdentifier() {
        return partitionIdentifier;
    }

    public void setPartitionIdentifier(int partitionIdentifier) {
        this.partitionIdentifier = partitionIdentifier;
    }

    public List<ApprovalPartitionPropertyRestRequest> getPropertyList() {
        return propertyList;
    }

    public void setPropertyList(List<ApprovalPartitionPropertyRestRequest> propertyList) {
        this.propertyList = propertyList;
    }
}
