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

import java.util.List;

public class RaEndEntitySearchPaginationSummary {
    
    private String sortingProperty; // same as SearchEndEntitiesSortRestRequest.SortProperty

    private List<Integer> sortPropertyIdentifiers; // ordered e.g. end entity profile id
    
    private int currentIdentifierIndex;
    
    // resets to zero after sort property moves to next id
    // e.g. search with next end entity profile
    private int currentIdentifierSearchOffset;
    
    private int nextPageNumber; // to distinguish between repeated search
    
    private boolean onlyUpdateCache; // used to update currentIdentifierSearchOffset at remote
    
    private int maxResultsPerPage; 

    public String getSortingProperty() {
        return sortingProperty;
    }

    public void setSortingProperty(String sortingProperty) {
        this.sortingProperty = sortingProperty;
    }

    public List<Integer> getSortPropertyIdentifiers() {
        return sortPropertyIdentifiers;
    }

    public void setSortPropertyIdentifiers(List<Integer> sortPropertyIdentifiers) {
        this.sortPropertyIdentifiers = sortPropertyIdentifiers;
    }

    public int getCurrentIdentifierIndex() {
        return currentIdentifierIndex;
    }
    
    public int getCurrentIdentifier() {
        if(sortPropertyIdentifiers==null) {
            return -1;
        }
        return sortPropertyIdentifiers.get(currentIdentifierIndex);
    }

    public void setCurrentIdentifierIndex(int currentIdentifierIndex) {
        this.currentIdentifierIndex = currentIdentifierIndex; // set from Rest Resource
    }

    public boolean incrementCurrentIdentifierIndex() {
        if(sortPropertyIdentifiers!=null && 
                currentIdentifierIndex < (sortPropertyIdentifiers.size()-1)) {
            currentIdentifierIndex += 1;        
            return true;
        }
        return false;
    }
    
    public int getNextPageNumber() {
        return nextPageNumber;
    }

    public void setNextPageNumber(int nextPageNumber) {
        this.nextPageNumber = nextPageNumber;
    }
    
    public void incrementNextPageNumber() {
        this.nextPageNumber += 1;
    }

    public int getCurrentIdentifierSearchOffset() {
        return currentIdentifierSearchOffset;
    }

    public void setCurrentIdentifierSearchOffset(int currentIdentifierSearchOffset) {
        this.currentIdentifierSearchOffset = currentIdentifierSearchOffset;
    }
    
    public void incrementCurrentIdentifierSearchOffset(int pageSize) {
        this.currentIdentifierSearchOffset += pageSize;
    }

    public boolean isOnlyUpdateCache() {
        return onlyUpdateCache;
    }

    public void setOnlyUpdateCache(boolean onlyUpdateCache) {
        this.onlyUpdateCache = onlyUpdateCache;
    }

    public int getMaxResultsPerPage() {
        return maxResultsPerPage;
    }

    public void setMaxResultsPerPage(int maxResultsPerPage) {
        this.maxResultsPerPage = maxResultsPerPage;
    }    
    
}
