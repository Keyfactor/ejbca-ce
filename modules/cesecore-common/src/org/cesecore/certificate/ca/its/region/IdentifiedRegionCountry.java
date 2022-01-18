package org.cesecore.certificate.ca.its.region;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.oer.its.CountryOnly;
import org.bouncycastle.oer.its.GeographicRegion;
import org.bouncycastle.oer.its.IdentifiedRegion;

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
    
}