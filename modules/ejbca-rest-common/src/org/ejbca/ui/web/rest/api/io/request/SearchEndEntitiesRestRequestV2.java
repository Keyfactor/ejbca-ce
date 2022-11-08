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

import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.era.RaEndEntitySearchRequestV2;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntitiesSearchRestRequestV2;
import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntitiesSortRestRequest;
import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequestList;
import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityMaxNumberOfResults;

import javax.validation.Valid;
import javax.ws.rs.core.Response;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * JSON input for a end entity search containing multiple search criteria and output limitation.
 * Along with support for sort and pagination.
 * <br/>
 * The properties of this class has to be valid.
 *
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntitiesSearchRestRequestV2
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequestList
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequest
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityMaxNumberOfResults
 * @see @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntitiesSortRestRequest
 *
 */
@ValidSearchEndEntitiesSearchRestRequestV2
public class SearchEndEntitiesRestRequestV2 {

    @ApiModelProperty(value = "Maximum number of results", example = "10")
    @ValidSearchEndEntityMaxNumberOfResults
    private Integer maxNumberOfResults;

    @ApiModelProperty(value = "Current page number", example = "1")
    private int currentPage = 1;
        
    @ApiModelProperty(value = "A List of search criteria." )
    @ValidSearchEndEntityCriteriaRestRequestList
    @Valid
    private List<SearchEndEntityCriteriaRestRequest> criteria = new ArrayList<>();
    
    @ApiModelProperty(value = "Sort." )
    @ValidSearchEndEntitiesSortRestRequest
    @Valid
    private SearchEndEntitiesSortRestRequest sortOperation;

    public Integer getMaxNumberOfResults() {
        return maxNumberOfResults;
    }

    public void setMaxNumberOfResults(Integer maxNumberOfResults) {
        this.maxNumberOfResults = maxNumberOfResults;
    }

    public List<SearchEndEntityCriteriaRestRequest> getCriteria() {
        return criteria;
    }

    public void setCriteria(List<SearchEndEntityCriteriaRestRequest> criteria) {
        this.criteria = criteria;
    }
    
    public int getCurrentPage() {
        return currentPage;
    }

    public void setCurrentPage(int currentPage) {
        this.currentPage = currentPage;
    }

    public SearchEndEntitiesSortRestRequest getSortOperation() {
        return sortOperation;
    }

    public void setSortOperation(SearchEndEntitiesSortRestRequest sortOperation) {
        this.sortOperation = sortOperation;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static SearchEndEntitiesRestRequestBuilder builder() {
        return new SearchEndEntitiesRestRequestBuilder();
    }

    public static class SearchEndEntitiesRestRequestBuilder {
        private Integer maxNumberOfResults;
        private Integer currentPage;
        private List<SearchEndEntityCriteriaRestRequest> criteria;
        private SearchEndEntitiesSortRestRequest sortOperation;

        private SearchEndEntitiesRestRequestBuilder() {
        }

        public SearchEndEntitiesRestRequestBuilder maxNumberOfResults(final Integer maxNumberOfResults) {
            this.maxNumberOfResults = maxNumberOfResults;
            return this;
        }

        public SearchEndEntitiesRestRequestBuilder currentPage(final int currentPage) {
            this.currentPage = currentPage;
            return this;
        }

        public SearchEndEntitiesRestRequestBuilder criteria(final List<SearchEndEntityCriteriaRestRequest> criteria) {
            this.criteria = criteria;
            return this;
        }
        
        public SearchEndEntitiesRestRequestBuilder sortOperation(final SearchEndEntitiesSortRestRequest sortOperation) {
            this.sortOperation = sortOperation;
            return this;
        }

        public SearchEndEntitiesRestRequestV2 build() {
            final SearchEndEntitiesRestRequestV2 searchEndEntitiesRestRequest = new SearchEndEntitiesRestRequestV2();
            searchEndEntitiesRestRequest.setMaxNumberOfResults(maxNumberOfResults);
            searchEndEntitiesRestRequest.setCurrentPage(currentPage);
            searchEndEntitiesRestRequest.setCriteria(criteria);
            searchEndEntitiesRestRequest.setSortOperation(sortOperation);
            return searchEndEntitiesRestRequest;
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static SearchEndEntitiesRestRequestConverter converter() {
        return new SearchEndEntitiesRestRequestConverter();
    }

    public static class SearchEndEntitiesRestRequestConverter {

        public RaEndEntitySearchRequestV2 toEntity(final SearchEndEntitiesRestRequestV2 searchEndEntitiesRestRequest) throws RestException {
            final RaEndEntitySearchRequestV2 raEndEntitySearchRequest = new RaEndEntitySearchRequestV2();
            raEndEntitySearchRequest.setMaxResults(searchEndEntitiesRestRequest.getMaxNumberOfResults());
            raEndEntitySearchRequest.setPageNumber(Math.max(0, searchEndEntitiesRestRequest.getCurrentPage()));
            raEndEntitySearchRequest.setEepIds(new ArrayList<Integer>());
            raEndEntitySearchRequest.setCpIds(new ArrayList<Integer>());
            raEndEntitySearchRequest.setCaIds(new ArrayList<Integer>());
            raEndEntitySearchRequest.setStatuses(new ArrayList<Integer>());
            raEndEntitySearchRequest.setSubjectDnSearchString("");
            raEndEntitySearchRequest.setSubjectAnSearchString("");
            raEndEntitySearchRequest.setUsernameSearchString("");
            
            for(final SearchEndEntityCriteriaRestRequest searchEndEntityCriteriaRestRequest : searchEndEntitiesRestRequest.getCriteria()) {
                final SearchEndEntityCriteriaRestRequest.CriteriaProperty criteriaProperty = SearchEndEntityCriteriaRestRequest.CriteriaProperty.resolveCriteriaProperty(searchEndEntityCriteriaRestRequest.getProperty());
                if(criteriaProperty == null) {
                    throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
                }
                final String criteriaValue = searchEndEntityCriteriaRestRequest.getValue();
                final SearchEndEntityCriteriaRestRequest.CriteriaOperation criteriaOperation = SearchEndEntityCriteriaRestRequest.CriteriaOperation.resolveCriteriaOperation(searchEndEntityCriteriaRestRequest.getOperation());
                switch (criteriaProperty) {
                    case QUERY: {
                        if (criteriaOperation == SearchEndEntityCriteriaRestRequest.CriteriaOperation.EQUAL) {
                            raEndEntitySearchRequest.setSubjectDnSearchExact(true);
                            raEndEntitySearchRequest.setSubjectAnSearchExact(true);
                            raEndEntitySearchRequest.setUsernameSearchExact(true);
                        }
                        raEndEntitySearchRequest.setSubjectDnSearchString(criteriaValue);
                        raEndEntitySearchRequest.setSubjectAnSearchString(criteriaValue);
                        raEndEntitySearchRequest.setUsernameSearchString(criteriaValue);
                        break;
                    }
                    case END_ENTITY_PROFILE: {
                        raEndEntitySearchRequest.getEepIds().add(searchEndEntityCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case CERTIFICATE_PROFILE: {
                        raEndEntitySearchRequest.getCpIds().add(searchEndEntityCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case CA: {
                        raEndEntitySearchRequest.getCaIds().add(searchEndEntityCriteriaRestRequest.getIdentifier());
                        break;
                    }
                    case STATUS: {
                        final SearchEndEntityCriteriaRestRequest.EndEntityStatus endEntityStatus = SearchEndEntityCriteriaRestRequest.EndEntityStatus.resolveEndEntityStatusByName(criteriaValue);
                        if(endEntityStatus == null) {
                            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
                        }
                        raEndEntitySearchRequest.getStatuses().add(endEntityStatus.getStatusValue());
                        break;
                    }
                    case MODIFIED_BEFORE: {
                        Date modifiedBefore;
                        try {
                            modifiedBefore = ValidityDate.parseAsIso8601(criteriaValue);
                        } catch (ParseException e) {
                            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid date format for modifiedBefore value.");
                        }
                        raEndEntitySearchRequest.setModifiedBefore(modifiedBefore.getTime());
                        break;
                    }
                    case MODIFIED_AFTER: {
                        Date modifiedAfter;
                        try {
                            modifiedAfter = ValidityDate.parseAsIso8601(criteriaValue);
                        } catch (ParseException e) {
                            throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Invalid date format for modifiedAfter value.");
                        }
                        raEndEntitySearchRequest.setModifiedAfter(modifiedAfter.getTime());
                        break;
                    }
                    default:
                        break;
                }
            }
            if(searchEndEntitiesRestRequest.getSortOperation()!=null) {
                raEndEntitySearchRequest.setSortOperation(
                        searchEndEntitiesRestRequest.getSortOperation().getQueryString());
                raEndEntitySearchRequest.setAdditionalConstraint(
                        searchEndEntitiesRestRequest.getSortOperation().getAdditionalConstraint());
            } else {
                raEndEntitySearchRequest.setSortOperation("");
                raEndEntitySearchRequest.setAdditionalConstraint("");
            }
            return raEndEntitySearchRequest;
        }
    }

}
