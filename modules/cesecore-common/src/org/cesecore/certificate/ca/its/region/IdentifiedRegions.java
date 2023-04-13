/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificate.ca.its.region;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.IdentifiedRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfIdentifiedRegion;

public class IdentifiedRegions implements ItsGeographicElement {
    
    // should only be populated by IdentifiedRegionCountry and IdentifiedRegionCountryRegions
    private List<ItsGeographicElement> identifiedRegions;

    public IdentifiedRegions(String element) {
        String[] regions = element.split(ItsGeographicRegion.SEQUENCE_SEPARATOR);
        identifiedRegions = new ArrayList<>(regions.length);
        for(String region: regions) {
            identifiedRegions.add(ItsGeographicRegion.getItsGeographicElementFromString(region));
        }
    }

    @Override
    public String getFormatHint() {
        return "";
    }

    @Override
    public String toStringFormat() {
        StringBuilder sb = new StringBuilder();
        sb.append(ItsGeographicRegion.REGION_TYPE_IDENTIFIED);
        for(ItsGeographicElement region: this.identifiedRegions) {
            sb.append(region.toStringFormat());
            sb.append(ItsGeographicRegion.SEQUENCE_SEPARATOR);
        }
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return this.toStringFormat();
    }

    @Override
    public ItsGeographicElement fromString(String formattedString) {
        return new IdentifiedRegions(formattedString);
    }

    @Override
    public GeographicRegion getGeographicRegion() {
        List<IdentifiedRegion> regions = new ArrayList<>();
        for(ItsGeographicElement region: this.identifiedRegions) {
            regions.add(region.getIdentifiedRegion());
        }
        return new GeographicRegion(GeographicRegion.identifiedRegion, new SequenceOfIdentifiedRegion(regions));
    }

    @Override
    public void validateArgs() {
        // nothing to do
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        return null;
    }

    @Override
    public List<String> getGuiDescription() {
        List<String> guiStrings = new ArrayList<>();
        for(ItsGeographicElement region: identifiedRegions) {
            guiStrings.addAll(region.getGuiDescription());
        }
        return guiStrings;
    }

    @Override
    public boolean isSubregion(ItsGeographicElement requestedRegion) {
        
        if(toStringFormat().contains(ItsSupportedCountries.WHOLE_EUROPE.getDisplayName())) {
            return true;
        }
        if(requestedRegion instanceof IdentifiedRegions) {
            for(ItsGeographicElement region: ((IdentifiedRegions)requestedRegion).identifiedRegions) {
                boolean result = false;
                for(ItsGeographicElement superRegion: this.identifiedRegions) {
                    
                    if(superRegion.isSubregion(region)) {
                        result = true; // each identified region is sub-region to one
                        break;
                    }
                }
                if(result==false) {
                    return false;
                }
            }
            return true;
        }
        
        return false;
    }
    
}