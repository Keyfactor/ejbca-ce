package org.cesecore.certificate.ca.its.region;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.oer.its.GeographicRegion;
import org.bouncycastle.oer.its.IdentifiedRegion;
import org.bouncycastle.oer.its.SequenceOfIdentifiedRegion;

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
        sb.deleteCharAt(sb.length()-1);
        return sb.toString();
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
    
}