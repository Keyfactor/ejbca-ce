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

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.model.era.RaEndEntitySearchResponse;

import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;
import java.util.Objects;

/**
 * JSON output for end entity search.
 */
public class SearchEndEntitiesRestResponse {

    private List<EndEntityRestResponse> endEntities = new ArrayList<>();
    private boolean moreResults;

    public SearchEndEntitiesRestResponse(){
    }

    public List<EndEntityRestResponse> getEndEntities() {
        return endEntities;
    }

    public void setEndEntities(final List<EndEntityRestResponse> endEntities) {
        this.endEntities = endEntities;
    }

    public boolean isMoreResults() {
        return moreResults;
    }

    public void setMoreResults(final boolean moreResults) {
        this.moreResults = moreResults;
    }

    /**
     * Return a builder instance for this class.
     *
     * @return builder instance for this class.
     */
    public static SearchEndEntitiesRestResponseBuilder builder() {
        return new SearchEndEntitiesRestResponseBuilder();
    }

    public static class SearchEndEntitiesRestResponseBuilder {
        private boolean moreResults;
        private List<EndEntityRestResponse> endEntities;

        private SearchEndEntitiesRestResponseBuilder() {
        }

        public SearchEndEntitiesRestResponseBuilder moreResults(final boolean moreResults) {
            this.moreResults = moreResults;
            return this;
        }

        public SearchEndEntitiesRestResponseBuilder endEntities(final List<EndEntityRestResponse> endEntities) {
            this.endEntities = endEntities;
            return this;
        }

        public SearchEndEntitiesRestResponse build() {
            final SearchEndEntitiesRestResponse searchEndEntitiesRestResponse = new SearchEndEntitiesRestResponse();
            searchEndEntitiesRestResponse.setMoreResults(moreResults);
            searchEndEntitiesRestResponse.setEndEntities(endEntities);
            return searchEndEntitiesRestResponse;
        }
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static SearchEndEntitiesRestResponseConverter converter() {
        return new SearchEndEntitiesRestResponseConverter();
    }

    public static class SearchEndEntitiesRestResponseConverter {

        public SearchEndEntitiesRestResponse toRestResponse(final RaEndEntitySearchResponse raEndEntitySearchResponse) {
            final SearchEndEntitiesRestResponse searchEndEntitiesRestResponse = new SearchEndEntitiesRestResponse();
            searchEndEntitiesRestResponse.setMoreResults(raEndEntitySearchResponse.isMightHaveMoreResults());
            
            for (final EndEntityInformation endEntity : raEndEntitySearchResponse.getEndEntities()) {
            	final EndEntityRestResponse endEntityRestResponse;
            	if (endEntity.getExtendedInformation() != null) {
            		List<ExtendedInformationRestResponseComponent> extensionData = new ArrayList<ExtendedInformationRestResponseComponent>();
            		for (Entry<Object, Object> entry : endEntity.getExtendedInformation().getRawData().entrySet()) {
            		    String name = (String) entry.getKey();
            		    String value = Objects.toString(entry.getValue()); // This can be String, Float, Integer, etc
            		    extensionData.add(ExtendedInformationRestResponseComponent.builder()
            		    		.setName(name)
            		    		.setValue(value)
            		    		.build());
            		}
	            	endEntityRestResponse = EndEntityRestResponse.builder()
	            			.setUsername(endEntity.getUsername())
	            			.setDn(endEntity.getDN())
	            			.setEmail(endEntity.getEmail())
	            			.setSubjectAltName(endEntity.getSubjectAltName())
	            			.setStatus(EndEntityConstants.getStatusText(endEntity.getStatus()))
	            			.setToken(endEntity.getTokenType())
	            			.setExtensionData(extensionData)
	            			.build();
            	} else {
            		endEntityRestResponse = EndEntityRestResponse.builder()
	            			.setUsername(endEntity.getUsername())
	            			.setDn(endEntity.getDN())
	            			.setEmail(endEntity.getEmail())
	            			.setSubjectAltName(endEntity.getSubjectAltName())
	            			.setStatus(EndEntityConstants.getStatusText(endEntity.getStatus()))
	            			.setToken(endEntity.getTokenType())
	            			.build();
            	}
            	searchEndEntitiesRestResponse.getEndEntities().add(endEntityRestResponse);
            }
            
            return searchEndEntitiesRestResponse;
        }
    }
}
