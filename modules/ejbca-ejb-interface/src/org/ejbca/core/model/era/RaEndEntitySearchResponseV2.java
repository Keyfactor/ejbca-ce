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
package org.ejbca.core.model.era;

import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cesecore.certificates.endentity.EndEntityInformation;

public class RaEndEntitySearchResponseV2 extends RaEndEntitySearchResponse {
    
    private static final long serialVersionUID = 265294093582155646L;

    private Set<String> userNames = new HashSet<>();
    
    // mainly relevant for sorting with end entity profile, certificate profile or certification authority
    // may be enhanced in future to removed repetition across pages
    private RaEndEntitySearchPaginationSummary searchSummary;
    
    public RaEndEntitySearchResponseV2(RaEndEntitySearchResponse searchResponse, 
            RaEndEntitySearchPaginationSummary searchSummary) {
        this.setEndEntities(searchResponse.getEndEntities());
        this.setMightHaveMoreResults(searchResponse.isMightHaveMoreResults());
        this.searchSummary = searchSummary;
    }

    public RaEndEntitySearchResponseV2() {
    }

    public RaEndEntitySearchPaginationSummary getSearchSummary() {
        return searchSummary;
    }
    
    public void setSearchSummary(RaEndEntitySearchPaginationSummary summary) {
        searchSummary = summary;
    }
    
    public void merge(final RaEndEntitySearchResponseV2 other) {
        if(other==null) {
            return;
        }
        for (final EndEntityInformation endEntity : other.getEndEntities()) {
            if(userNames.contains(endEntity.getUsername())) {
                continue;
            }
            this.userNames.add(endEntity.getUsername());
            this.getEndEntities().add(endEntity);
        }
        // one node may not have more result but other node previously searched might have
        setMightHaveMoreResults(isMightHaveMoreResults() || other.isMightHaveMoreResults());
       
    }
    
    public void sortMergedMembers() {
        Collections.sort(getEndEntities(), new EndEntitiesSearchResultSorter(
                searchSummary.getSortingProperty(), searchSummary.getSortPropertyIdentifiers()));
        if(searchSummary.getSortingProperty().contains("DESC")) {
            Collections.reverse(getEndEntities());
        }
    }
    
    class EndEntitiesSearchResultSorter implements Comparator<EndEntityInformation> {

        private int sortingProperty; // same as SearchEndEntitiesSortRestRequest.SortProperty
        private Map<Integer, Integer> orderedIds; // for faster access, instead of List.find
        
        public EndEntitiesSearchResultSorter(String sortingProperty, List<Integer> orderedIdList) {
            this.sortingProperty = convertSortingProperty(sortingProperty);
            this.orderedIds = new HashMap<>();
            if(orderedIdList!=null) {
                int i=0;
                for(int id: orderedIdList) {
                    this.orderedIds.put(id, i);
                    i++;
                }
            }
        }
        
        @Override
        public int compare(EndEntityInformation eei0, EndEntityInformation eei1) {
            switch(sortingProperty) {
            case 1:
                return eei0.getDN().compareTo(eei1.getDN());
            case 2:
                return eei0.getSubjectAltName().compareTo(eei1.getSubjectAltName());
            case 3:
                return orderedIds.get(eei0.getEndEntityProfileId())
                        .compareTo(orderedIds.get(eei1.getEndEntityProfileId()));
            case 4:
                return orderedIds.get(eei0.getCertificateProfileId())
                        .compareTo(orderedIds.get(eei1.getCertificateProfileId()));
            case 5:
                return orderedIds.get(eei0.getCAId())
                        .compareTo(orderedIds.get(eei1.getCAId()));
            case 6:
                return eei0.getStatus() - eei1.getStatus();
            case 7:
                return eei0.getTimeModified().compareTo(eei1.getTimeModified());
            case 8:
                return eei0.getTimeCreated().compareTo(eei1.getTimeCreated());
            case 0:
            default:
                return eei0.getUsername().compareTo(eei1.getUsername());
            }
        }        
        
        private int convertSortingProperty(String sortingProperty) {
            final String[] orderedSortPropertyTypes = new String[]{"username", "subjectDN", "subjectAltName", 
                    "endEntityProfileId", "certificateProfileId", "caId", "status", "timeModified", "timeCreated"};
            for(int i=0; i<orderedSortPropertyTypes.length; i++) {
                if(sortingProperty.contains(orderedSortPropertyTypes[i])) {
                    return i;
                }
            }
            return 0;
        }
        
    }
    
    

}
