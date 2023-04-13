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

import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntitiesSortRestRequest;

import com.fasterxml.jackson.annotation.JsonIgnore;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;

/**
 * JSON input for certificate search containing a single order by clause.
 * <br/>
 * 
 * The content of this class should be valid.
 * 
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntitiesSortRestRequest
 */
@ApiModel(description = "Use one of allowed values as property and operation.\n" +
        "Available properties" +
        "USERNAME \n" +
        "SUBJECT_DN \n" +
        "SUBJECT_ALT_NAME \n" +
        "END_ENTITY_PROFILE(by databse identifier, not user-given name) \n" +
        "CERTIFICATE_PROFILE(by identifier) \n" +
        "CA(by identifier) \n" +
        "STATUS \n" +
        "UPDATE_TIME \n" +
        "CREATED_DATE \n" +
        "\n" +
        "Available operations" +
        "ASC \n" +
        "DESC \n"
)
@ValidSearchEndEntitiesSortRestRequest
public class SearchEndEntitiesSortRestRequest {

    @ApiModelProperty(value = "Sorted by",
            allowableValues = "USERNAME, SUBJECT_DN, SUBJECT_ALT_NAME, END_ENTITY_PROFILE, CERTIFICATE_PROFILE, STATUS, UPDATE_TIME, CREATED_TIME",
            dataType = "java.lang.String")
    private String property;

    @ApiModelProperty(value = "Sort ascending or descending. 'ASC' for ascending, 'DESC' for descending.",
            allowableValues = "ASC, DESC",
            dataType = "java.lang.String")
    private String operation;

    public SearchEndEntitiesSortRestRequest() {
    }

    public String getProperty() {
        return property;
    }

    public void setProperty(String property) {
        this.property = property;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    @JsonIgnore
    public String getQueryString() {
        // already validated non-null, 'a.' is to conform to @see RaMasterApiSessionBean.searchForEndEntities
        return " ORDER BY a." +  SortProperty.resolveCriteriaProperty(this.property).getColumnName() + " " + this.operation;
    }
    
    @JsonIgnore
    public String getAdditionalConstraint() {
        if(!isSortPropertyDiscrete()) {
           return ""; 
        }
        return " AND a." + SortProperty.resolveCriteriaProperty(this.property).getColumnName() + "=:sortconstraint ";
    }
    
    @JsonIgnore
    public boolean isSortPropertyDiscrete() {
        SortProperty prop = SortProperty.resolveCriteriaProperty(this.property);
        if(prop == SortProperty.CA || prop == SortProperty.CERTIFICATE_PROFILE 
                || prop == SortProperty.END_ENTITY_PROFILE) {
            return true;
        } else {
            return false;
        }
    }
    
    /**
     * The set of criteria property values that are expected for SearchEndEntitiesCriteriaRestRequest.property attribute.
     */
    public enum SortProperty {
        USERNAME("username"),
        SUBJECT_DN("subjectDN"),
        SUBJECT_ALT_NAME("subjectAltName"),
        END_ENTITY_PROFILE("endEntityProfileId"), // order by id, not name; same for CERTIFICATE_PROFILE and CA
        CERTIFICATE_PROFILE("certificateProfileId"),
        CA("caId"),
        STATUS("status"),
        UPDATE_TIME("timeModified"),
        CREATED_TIME("timeCreated");
        
        private String columnName;

        SortProperty(String columnName) {
            this.columnName = columnName;
        }

        /**
         * Resolves the sort property using its name or returns null.
         *
         * @param property property name.
         *
         * @return SortProperty using its name or null.
         */
        public static SortProperty resolveCriteriaProperty(final String property) {
            for (SortProperty criteriaProperty : values()) {
                if (criteriaProperty.name().equalsIgnoreCase(property)) {
                    return criteriaProperty;
                }
            }
            return null;
        }

        public String getColumnName() {
            return columnName;
        }
        
    }

    /**
     * The set of sort operation values that are expected for SearchCertificateSortRestRequest.operation attribute.
     */
    public enum SortOperation {
        ASC,
        DESC;

        /**
         * Resolves the sort operation using its name or returns null.
         *
         * @param operation operation name.
         *
         * @return SortOperation using its name or null.
         */
        public static SortOperation resolveCriteriaOperation(final String operation) {
            for (SortOperation criteriaOperation : values()) {
                if (criteriaOperation.name().equalsIgnoreCase(operation)) {
                    return criteriaOperation;
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
    public static SearchEndEntitiesSortRestRequestBuilder builder() {
        return new SearchEndEntitiesSortRestRequestBuilder();
    }

    public static class SearchEndEntitiesSortRestRequestBuilder {
        private String property;
        private String operation;

        private SearchEndEntitiesSortRestRequestBuilder() {
        }

        public SearchEndEntitiesSortRestRequestBuilder property(final String property) {
            this.property = property;
            return this;
        }

        public SearchEndEntitiesSortRestRequestBuilder operation(final String operation) {
            this.operation = operation;
            return this;
        }

        public SearchEndEntitiesSortRestRequest build() {
            final SearchEndEntitiesSortRestRequest request = new SearchEndEntitiesSortRestRequest();
            request.setProperty(property);
            request.setOperation(operation);
            return request;
        }
    }
    
}
