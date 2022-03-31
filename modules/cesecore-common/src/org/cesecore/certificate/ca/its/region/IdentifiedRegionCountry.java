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

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.oer.its.ieee1609dot2.basetypes.CountryOnly;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.IdentifiedRegion;

public class IdentifiedRegionCountry implements ItsGeographicElement {
    
    private ItsSupportedCountries country;
    
    public IdentifiedRegionCountry(ItsSupportedCountries country) {
        this.country = country;
    }
    
    public IdentifiedRegionCountry(String country) {
        this.country = ItsSupportedCountries.fromDisplayName(country);
    }
    
    public ItsSupportedCountries getCountry() {
        return country;
    }

    public void setCountry(ItsSupportedCountries country) {
        this.country = country;
    }

    @Override
    public String getFormatHint() {
        return "";
    }

    @Override
    public String toStringFormat() {
        return ItsGeographicRegion.REGION_TYPE_IDENTIFIED_COUNTRY + country.getDisplayName();
    }
    
    @Override
    public String toString() {
        return this.toStringFormat();
    }

    @Override
    public ItsGeographicElement fromString(String formattedString) {
        return new IdentifiedRegionCountry(formattedString.trim());
    }

    @Override
    public GeographicRegion getGeographicRegion() {
        return null;
    }

    @Override
    public void validateArgs() {
        // nothing to do
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        return new IdentifiedRegion(IdentifiedRegion.countryOnly, new CountryOnly(country.getM49Code()));
    }

    @Override
    public List<String> getGuiDescription() {
        return Arrays.asList(country.getDisplayName());
    }

    @Override
    public boolean isSubregion(ItsGeographicElement requestedRegion) {
        if(requestedRegion instanceof IdentifiedRegionCountryRegions) {
            IdentifiedRegionCountryRegions anotherRegion = (IdentifiedRegionCountryRegions) requestedRegion;
            if(anotherRegion.getCountry()==country) {
                return true;
            }
        }
        
        if(requestedRegion instanceof IdentifiedRegionCountry) {
            IdentifiedRegionCountry anotherRegion = (IdentifiedRegionCountry) requestedRegion;
            if(anotherRegion.getCountry()==country) {
                return true;
            }
        }
        return false;
    }
    
}