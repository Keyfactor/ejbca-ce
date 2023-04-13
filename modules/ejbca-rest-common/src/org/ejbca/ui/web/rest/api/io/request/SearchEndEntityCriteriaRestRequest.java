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

import com.fasterxml.jackson.annotation.JsonIgnore;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequest;

import java.util.EnumSet;

/**
 * JSON input for end entity search containing a single search criteria.
 * <br/>
 * The content of this class should be valid.
 *
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequest
 */
@ApiModel(description = "Use one of allowed values as property(see enum values below).\n" +
		"QUERY - multiplicity [0, 1] - is used to search by SubjectDn, SubjectAn, Username; \n" +
        "Available STATUS - multiplicity [0, 9] - values are: NEW, FAILED, " +
        "INITIALIZED, INPROCESS, GENERATED, REVOKED, " +
        "HISTORICAL, KEYRECOVERY, WAITINGFORADDAPPROVAL;\n" +
        "\n" +
        "END_ENTITY_PROFILE, CERTIFICATE_PROFILE, CA - multiplicity [0, *) - exact match of the name for referencing End Entity Profile, Certificate Profile or CA; \n"
)
@ValidSearchEndEntityCriteriaRestRequest
public class SearchEndEntityCriteriaRestRequest {

    @ApiModelProperty(value = "A search property",
            allowableValues = "QUERY, END_ENTITY_PROFILE, CERTIFICATE_PROFILE, CA, STATUS, MODIFIED_BEFORE, MODIFIED_AFTER"
    )
    private String property;

    @ApiModelProperty(value = "A search value. This could be string value, an appropriate string name of End Entity Profile or Certificate Profile or CA",
            example = "exampleUsername")
    private String value;

    @ApiModelProperty(value = "An operation for property on inserted value. 'EQUALS' for string, 'LIKE' for string value ('QUERY')",
            allowableValues = "EQUAL, LIKE",
            dataType = "java.lang.String")
    private String operation;

    // Internal usage of identifier for EndEntityProfile, CertificateProfile or CAId
    @JsonIgnore
    private int identifier;

    public SearchEndEntityCriteriaRestRequest() {
    }

    public String getProperty() {
        return property;
    }

    public void setProperty(String property) {
        this.property = property;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public int getIdentifier() {
        return identifier;
    }

    public void setIdentifier(int identifier) {
        this.identifier = identifier;
    }

    /**
     * The set of criteria property values that are expected for SearchEndEntityCriteriaRestRequest.property attribute.
     */
    public enum CriteriaProperty {
    	QUERY,
        END_ENTITY_PROFILE,
        CERTIFICATE_PROFILE,
        CA,
        STATUS,
        MODIFIED_BEFORE,
        MODIFIED_AFTER;

        /**
         * Resolves the CriteriaProperty using its name or returns null.
         *
         * @param property property name.
         *
         * @return CriteriaProperty using its name or null.
         */
        public static CriteriaProperty resolveCriteriaProperty(final String property) {
            for (CriteriaProperty criteriaProperty : values()) {
                if (criteriaProperty.name().equalsIgnoreCase(property)) {
                    return criteriaProperty;
                }
            }
            return null;
        }
        
        /**
         * The subset of criteria properties that expect String input for SearchEndEntityCriteriaRestRequest.value.
         *
         * @return subset of criteria properties.
         */
        public static EnumSet<CriteriaProperty> STRING_PROPERTIES() {
            return EnumSet.of(QUERY, STATUS);
        }

    }

    /**
     * The set of criteria operation values that are expected for SearchEndEntityCriteriaRestRequest.operation attribute.
     */
    public enum CriteriaOperation {
        EQUAL,
        LIKE;

        /**
         * Resolves the CriteriaOperation using its name or returns null.
         *
         * @param operation operation name.
         *
         * @return CriteriaOperation using its name or null.
         */
        public static CriteriaOperation resolveCriteriaOperation(final String operation) {
            for (CriteriaOperation criteriaOperation : values()) {
                if (criteriaOperation.name().equalsIgnoreCase(operation)) {
                    return criteriaOperation;
                }
            }
            return null;
        }

    }

    /**
     * The set of end entity status values that are expected for SearchEndEntityCriteriaRestRequest.value attribute in case SearchEndEntityCriteriaRestRequest.property = 'STATUS'.
     */
    public enum EndEntityStatus {
    	NEW(EndEntityConstants.STATUS_NEW),
    	FAILED(EndEntityConstants.STATUS_FAILED),
    	INITIALIZED(EndEntityConstants.STATUS_INITIALIZED),
    	INPROCESS(EndEntityConstants.STATUS_INPROCESS),
    	GENERATED(EndEntityConstants.STATUS_GENERATED),
    	REVOKED(EndEntityConstants.STATUS_REVOKED),
    	HISTORICAL(EndEntityConstants.STATUS_HISTORICAL),
    	KEYRECOVERY(EndEntityConstants.STATUS_KEYRECOVERY),
    	WAITINGFORADDAPPROVAL(EndEntityConstants.STATUS_WAITINGFORADDAPPROVAL);

        private final int statusValue;

        EndEntityStatus(final int statusValue) {
            this.statusValue = statusValue;
        }

        public int getStatusValue() {
            return statusValue;
        }

        /**
         * Resolves the EndEntityStatus using its name or returns null.
         *
         * @param name status name.
         *
         * @return EndEntityStatus using its name or null.
         */
        public static EndEntityStatus resolveEndEntityStatusByName(final String name) {
            for (EndEntityStatus endEntityStatus : values()) {
                if (endEntityStatus.name().equalsIgnoreCase(name)) {
                    return endEntityStatus;
                }
            }
            return null;
        }

    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static SearchEndEntityCriteriaRestRequestBuilder builder() {
        return new SearchEndEntityCriteriaRestRequestBuilder();
    }

    public static class SearchEndEntityCriteriaRestRequestBuilder {
        private String property;
        private String value;
        private String operation;
        private int identifier;

        private SearchEndEntityCriteriaRestRequestBuilder() {
        }

        public SearchEndEntityCriteriaRestRequestBuilder property(final String property) {
            this.property = property;
            return this;
        }

        public SearchEndEntityCriteriaRestRequestBuilder value(final String value) {
            this.value = value;
            return this;
        }

        public SearchEndEntityCriteriaRestRequestBuilder operation(final String operation) {
            this.operation = operation;
            return this;
        }

        public SearchEndEntityCriteriaRestRequestBuilder identifier(final int identifier) {
            this.identifier = identifier;
            return this;
        }

        public SearchEndEntityCriteriaRestRequest build() {
            final SearchEndEntityCriteriaRestRequest searchEndEntityCriteriaRestRequest = new SearchEndEntityCriteriaRestRequest();
            searchEndEntityCriteriaRestRequest.setProperty(property);
            searchEndEntityCriteriaRestRequest.setValue(value);
            searchEndEntityCriteriaRestRequest.setOperation(operation);
            searchEndEntityCriteriaRestRequest.setIdentifier(identifier);
            return searchEndEntityCriteriaRestRequest;
        }
    }

}
