package org.cesecore.certificate.ca.its.region;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.oer.its.CountryAndRegions;
import org.bouncycastle.oer.its.CountryOnly;
import org.bouncycastle.oer.its.GeographicRegion;
import org.bouncycastle.oer.its.IdentifiedRegion;
import org.bouncycastle.oer.its.Region;

public class IdentifiedRegionCountryRegions implements ItsGeographicElement {

    private ItsSupportedCountries country;
    private List<Integer> regions;
    
    public static final String COUNTRY_REGION_HINT = "Expected format: region1,region2,region3 e.g. 123,456,789"; 
    
    public IdentifiedRegionCountryRegions() {
    }
    
    public IdentifiedRegionCountryRegions(String formattedString) {
        String[] parts = formattedString.split(ItsGeographicRegion.SEPARATOR);
        this.country = ItsSupportedCountries.fromDisplayName(parts[0]);
        this.regions = new ArrayList<>();
        for(int i=1; i<parts.length; i++) {
            int j = Integer.parseInt(parts[i]);
            if(j<0 || j>0xffff) {
                throw new IllegalArgumentException("Expected unsigned 16bit integer(0-65535) as region.");
            }
            this.regions.add(j);
        }
    }

    public IdentifiedRegionCountryRegions(ItsSupportedCountries country, List<Integer> regions) {
        this.country = country;
        this.regions = regions;
    }

    public ItsSupportedCountries getCountry() {
        return country;
    }

    public void setCountry(ItsSupportedCountries country) {
        this.country = country;
    }

    public List<Integer> getRegions() {
        return regions;
    }

    public void setRegions(List<Integer> regions) {
        this.regions = regions;
    }

    @Override
    public String getFormatHint() {
        return COUNTRY_REGION_HINT;
    }

    @Override
    public String toStringFormat() {
        return ItsGeographicRegion.REGION_TYPE_IDENTIFIED_COUNTRY_REGION + country.getDisplayName() + 
                ItsGeographicRegion.SEPARATOR + regions.toString().replace(" ","")
                                                    .replace("[","").replace("]","");
    }
    
    @Override
    public String toString() {
        return this.toStringFormat();
    }

    @Override
    public ItsGeographicElement fromString(String formattedString) {
        return new IdentifiedRegionCountryRegions(formattedString);
    }

    @Override
    public GeographicRegion getGeographicRegion() {
        return null;
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        List<Region> regions = new ArrayList<>();
        return new IdentifiedRegion(IdentifiedRegion.countryAndRegions, 
                new CountryAndRegions(new CountryOnly(country.getM49Code()),
                        regions ));
    }

    @Override
    public void validateArgs() {
        // nothing to do
    }

    @Override
    public List<String> getGuiDescription() {
        List<String> guiStrings = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        sb.append("<b>Country:</b> ");
        sb.append(country.getDisplayName());
        sb.append("<br><b>Regions:</b> ");
        for(Integer region: regions) {
            sb.append(region);
            sb.append(ItsGeographicRegion.SEPARATOR);
        }
        guiStrings.add(sb.toString());
        return guiStrings;
    }

}
