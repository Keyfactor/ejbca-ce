package org.cesecore.certificate.ca.its.region;

import org.bouncycastle.oer.its.GeographicRegion;
import org.bouncycastle.oer.its.IdentifiedRegion;

public interface ItsGeographicElement {
    
    public String getFormatHint();
    
    // to enforce override of toString
    public String toStringFormat();
    
    public ItsGeographicElement fromString(String formattedString);
    
    public GeographicRegion getGeographicRegion();
    
    public IdentifiedRegion getIdentifiedRegion();
    
    public void validateArgs();
    
}