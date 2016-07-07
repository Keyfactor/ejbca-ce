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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Response of end entity search from RA UI.
 * 
 * @version $Id$
 */
public class RaEndEntitySearchResponse implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<EndEntityInformation> endEntities = new ArrayList<>();
    private boolean mightHaveMoreResults = false;

    public List<EndEntityInformation> getEndEntities() { return endEntities; }
    public void setEndEntities(List<EndEntityInformation> endEntities) { this.endEntities = endEntities; }

    public boolean isMightHaveMoreResults() { return mightHaveMoreResults; }
    public void setMightHaveMoreResults(boolean mightHaveMoreResults) { this.mightHaveMoreResults = mightHaveMoreResults; }
    
    public void merge(final RaEndEntitySearchResponse other) {
        final Map<String,EndEntityInformation> endEntitiesMap = new HashMap<>();
        for (final EndEntityInformation endEntity : endEntities) {
            endEntitiesMap.put(endEntity.getUsername(), endEntity);
        }
        for (final EndEntityInformation endEntity : other.endEntities) {
            endEntitiesMap.put(endEntity.getUsername(), endEntity);
        }
        this.endEntities.clear();
        this.endEntities.addAll(endEntitiesMap.values());
        if (other.isMightHaveMoreResults()) {
            setMightHaveMoreResults(true);
        }
    }
}
