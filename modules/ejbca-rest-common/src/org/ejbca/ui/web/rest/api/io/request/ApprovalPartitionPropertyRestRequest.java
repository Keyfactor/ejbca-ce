package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import org.ejbca.ui.web.rest.api.validator.ValidApprovalPartitionPropertyRestRequest;

@ValidApprovalPartitionPropertyRestRequest
@Schema(name = "ApprovalPartitionPropertyRestRequest", description = "Information about an approval partition properties")
public class ApprovalPartitionPropertyRestRequest {
    @Schema(description = "Property label")
    @NotNull
    private String label;
    @Schema(description = "Property value")
    private String  value;
    @Schema(description = "Property type")
    private String  type;
    @Schema(description = "Property possible values")
    private List<String> possibleValues;

    public ApprovalPartitionPropertyRestRequest() {
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<String> getPossibleValues() {
        return possibleValues;
    }

    public void setPossibleValues(List<String> possibleValues) {
        this.possibleValues = possibleValues;
    }
}
