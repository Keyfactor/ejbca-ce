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
import org.ejbca.core.model.era.RaEndEntitySearchRequest;
import org.ejbca.ui.web.rest.api.exception.RestException;
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
 * <br/>
 * The properties of this class has to be valid.
 *
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequestList
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequest
 * @see org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityMaxNumberOfResults
 *
 */
public class SearchEndEntitiesRestRequest {

    @ApiModelProperty(value = "Maximum number of results", example = "10")
    @ValidSearchEndEntityMaxNumberOfResults
    private Integer maxNumberOfResults;

    @ApiModelProperty(value = "Current page number", example = "0")
    private int currentPage;
    
    @ApiModelProperty(value = "A List of search criteria." )
    @ValidSearchEndEntityCriteriaRestRequestList
    @Valid
    private List<SearchEndEntityCriteriaRestRequest> criteria = new ArrayList<>();

    public Integer getMaxNumberOfResults() {
        return maxNumberOfResults;
    }

    public void setMaxNumberOfResults(Integer maxNumberOfResults) {
        this.maxNumberOfResults = maxNumberOfResults;
    }
    
    public int getCurrentPage() {
        return currentPage;
    }

    public void setCurrentPage(int currentPage) {
        this.currentPage = currentPage;
    }

    public List<SearchEndEntityCriteriaRestRequest> getCriteria() {
        return criteria;
    }

    public void setCriteria(List<SearchEndEntityCriteriaRestRequest> criteria) {
        this.criteria = criteria;
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
        private List<SearchEndEntityCriteriaRestRequest> criteria;
        private int currentPage;

        private SearchEndEntitiesRestRequestBuilder() {
        }

        public SearchEndEntitiesRestRequestBuilder maxNumberOfResults(final Integer maxNumberOfResults) {
            this.maxNumberOfResults = maxNumberOfResults;
            return this;
        }
        
        public SearchEndEntitiesRestRequestBuilder currentPage(final Integer currentPage) {
            this.currentPage = currentPage;
            return this;
        }

        public SearchEndEntitiesRestRequestBuilder criteria(final List<SearchEndEntityCriteriaRestRequest> criteria) {
            this.criteria = criteria;
            return this;
        }

        public SearchEndEntitiesRestRequest build() {
            final SearchEndEntitiesRestRequest searchEndEntitiesRestRequest = new SearchEndEntitiesRestRequest();
            searchEndEntitiesRestRequest.setMaxNumberOfResults(maxNumberOfResults);
            searchEndEntitiesRestRequest.setCriteria(criteria);
            searchEndEntitiesRestRequest.setCurrentPage(currentPage);
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

        public RaEndEntitySearchRequest toEntity(final SearchEndEntitiesRestRequest searchEndEntitiesRestRequest) throws RestException {
            if(searchEndEntitiesRestRequest.getMaxNumberOfResults() == null || searchEndEntitiesRestRequest.getCriteria() == null || searchEndEntitiesRestRequest.getCriteria().isEmpty()) {
                throw new RestException(Response.Status.BAD_REQUEST.getStatusCode(), "Malformed request.");
            }
            final RaEndEntitySearchRequest raEndEntitySearchRequest = new RaEndEntitySearchRequest();
            raEndEntitySearchRequest.setPageNumber(Math.max(0, searchEndEntitiesRestRequest.getCurrentPage()));
            raEndEntitySearchRequest.setMaxResults(searchEndEntitiesRestRequest.getMaxNumberOfResults());
            raEndEntitySearchRequest.setEepIds(new ArrayList<Integer>());
            raEndEntitySearchRequest.setCpIds(new ArrayList<Integer>());
            raEndEntitySearchRequest.setCaIds(new ArrayList<Integer>());
            raEndEntitySearchRequest.setStatuses(new ArrayList<Integer>());
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
            return raEndEntitySearchRequest;
        }
    }

}
