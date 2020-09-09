package org.ejbca.ui.web.rest.api.io.request;

import io.swagger.annotations.ApiModelProperty;

import org.ejbca.core.model.era.RaEndEntitySearchRequest;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityCriteriaRestRequestList;
import org.ejbca.ui.web.rest.api.validator.ValidSearchEndEntityMaxNumberOfResults;

import javax.validation.Valid;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
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

    @ValidSearchEndEntityMaxNumberOfResults
    private Integer maxNumberOfResults;
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

        private SearchEndEntitiesRestRequestBuilder() {
        }

        public SearchEndEntitiesRestRequestBuilder maxNumberOfResults(final Integer maxNumberOfResults) {
            this.maxNumberOfResults = maxNumberOfResults;
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
            raEndEntitySearchRequest.setMaxResults(raEndEntitySearchRequest.getMaxResults());
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
                    default:
                    	break;
                }
            }
            return raEndEntitySearchRequest;
        }
    }

}
