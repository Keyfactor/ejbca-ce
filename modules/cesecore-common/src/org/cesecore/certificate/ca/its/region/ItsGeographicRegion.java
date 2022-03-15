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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT8;

/**
 * Intermediate representation of GeographicRegion region object for GUI and persistence.
 */
public class ItsGeographicRegion implements Serializable {

    private static final long serialVersionUID = 8480860776365248654L;
    
    public static final String SEPARATOR = ",";
    public static final String SEQUENCE_SEPARATOR = ";";
    
    public static final String TYPE_SEPARATOR = ":";
    
    protected static final int IDENTIFIED_REGION_EUROPE = 0xFFFF;
    
    public static final String REGION_TYPE_CIRCULAR = "circular:";
    public static final String REGION_TYPE_RECTANGLE = "rectangle:";
    public static final String REGION_TYPE_IDENTIFIED_COUNTRY = "country:";
    public static final String REGION_TYPE_IDENTIFIED_COUNTRY_REGION = "country_region:";
    public static final String REGION_TYPE_IDENTIFIED = "identifed:";
    
    public static final double METER_PER_TENTH_MICRODEGREE_LATITUDE = 0.011;
    
    public enum RegionType {
        // not supporting extension and polygonal for now
        NONE("None"),
        CIRCULAR("Circular"), 
        RECTANGULAR("Rectangular"), 
        IDENTIFIED("Identified");
        
        private final String displayName;

        RegionType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
        
        public static RegionType fromDisplayName(String country) {
            for(RegionType r : values()){
                if(r.getDisplayName().equalsIgnoreCase(country)){
                    return r;
                }
            }
            throw new IllegalArgumentException("Invalid region type: " + country);
        }
    }
    
    public enum IdentifiedRegionType { 
        // they have identical representation in UI
        COUNTRY, COUNTRY_WITH_REGIONS
    }
    
    private RegionType regionType;
    private ItsGeographicElement geographicElement;
    
    public static ItsGeographicRegion getDefaultRegion() {
        ItsGeographicRegion region = new ItsGeographicRegion();
        region.setRegionType(RegionType.IDENTIFIED);
        region.setGeographicElement(new IdentifiedRegions("country:-Europe"));
        return region;
    }

    public RegionType getRegionType() {
        return regionType;
    }

    public void setRegionType(RegionType regionType) {
        this.regionType = regionType;
    }

    public ItsGeographicElement getGeographicElement() {
        return geographicElement;
    }

    public void setGeographicElement(ItsGeographicElement geographicElement) {
        this.geographicElement = geographicElement;
    }
    
    public static ItsGeographicElement getItsGeographicElementFromString(String formattedString) {
        
        String[] parts = formattedString.split(TYPE_SEPARATOR);
        String element = formattedString.substring(parts[0].length()+1);
        switch(parts[0] + TYPE_SEPARATOR) {
            case REGION_TYPE_CIRCULAR:
                return new CircularRegion(element);
            case REGION_TYPE_RECTANGLE:
                return new RectangularRegions(element);
            case REGION_TYPE_IDENTIFIED:
                return new IdentifiedRegions(element);
            case REGION_TYPE_IDENTIFIED_COUNTRY:
                return new IdentifiedRegionCountry(element);
            case REGION_TYPE_IDENTIFIED_COUNTRY_REGION:
                return new IdentifiedRegionCountryRegions(element);
            default:
                throw new IllegalStateException("Invalid geographic region type: " + parts[0]);
        }
        
    }
    
    private void parseAndSetRegionType(String region) {
        if(region.indexOf(TYPE_SEPARATOR)==-1) {
            throw new IllegalArgumentException("Invalid region: " + region);
        }
        String regionType = region.substring(0, region.indexOf(TYPE_SEPARATOR)) + TYPE_SEPARATOR;
        switch(regionType.trim()) {
            case REGION_TYPE_CIRCULAR:
                setRegionType(RegionType.CIRCULAR);
                break;
            case REGION_TYPE_RECTANGLE:
                setRegionType(RegionType.RECTANGULAR);
                break;
            case REGION_TYPE_IDENTIFIED:
                setRegionType(RegionType.IDENTIFIED);
                break;
            default:
                throw new IllegalStateException("Invalid region type: " + regionType);
        }
    }
    
    public String toString() {
        return getGeographicElement().toStringFormat();
    }

    public static ItsGeographicRegion fromString(String region) {
        if(StringUtils.isEmpty(region)) {
            return null;
        }
        ItsGeographicRegion itsGeographicRegion = new ItsGeographicRegion();
        itsGeographicRegion.parseAndSetRegionType(region);
        itsGeographicRegion.setGeographicElement(getItsGeographicElementFromString(region));
        return itsGeographicRegion;
    }
    
    public static ItsGeographicElement fromGeographicRegion(GeographicRegion region) {
        //TODO: testing
        switch(region.getChoice()) {
            case GeographicRegion.circularRegion:
                org.bouncycastle.oer.its.ieee1609dot2.basetypes.CircularRegion circular = 
                                (org.bouncycastle.oer.its.ieee1609dot2.basetypes.CircularRegion)region.getGeographicRegion();
                return new CircularRegion(circular.getCenter().getLatitude().getValue().intValue(), 
                        circular.getCenter().getLongitude().getValue().intValue(), circular.getRadius().getValue().intValue());
            case GeographicRegion.rectangularRegion:
                org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfRectangularRegion rectangularRegions = 
                    (org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfRectangularRegion)region.getGeographicRegion();
                List<Long[]> rectangles = new ArrayList<>();
                for(org.bouncycastle.oer.its.ieee1609dot2.basetypes.RectangularRegion rectangle: 
                                            rectangularRegions.getRectangularRegions()) {
                    rectangles.add(new Long[] {rectangle.getNorthWest().getLatitude().getValue().longValueExact(), 
                            rectangle.getNorthWest().getLongitude().getValue().longValueExact(),
                            rectangle.getSouthEast().getLatitude().getValue().longValueExact(), 
                            rectangle.getSouthEast().getLongitude().getValue().longValueExact()});
                }
                return new RectangularRegions(rectangles);
            case GeographicRegion.identifiedRegion:
                org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfIdentifiedRegion identifiedRegions = 
                    (org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfIdentifiedRegion)region.getGeographicRegion();
                StringBuilder sb = new StringBuilder();
                for(org.bouncycastle.oer.its.ieee1609dot2.basetypes.IdentifiedRegion identifiedRegion: 
                                                                    identifiedRegions.getIdentifiedRegions()) {
                    if(identifiedRegion.getChoice()==
                            org.bouncycastle.oer.its.ieee1609dot2.basetypes.IdentifiedRegion.countryOnly) {
                        sb.append(REGION_TYPE_IDENTIFIED_COUNTRY);
                        sb.append(
                                ItsSupportedCountries.fromCountryCode((
                                        (org.bouncycastle.oer.its.ieee1609dot2.basetypes.CountryOnly)identifiedRegion.getIdentifiedRegion())
                                        .getValue().intValue()).getDisplayName());
                    } else if(identifiedRegion.getChoice()==
                                org.bouncycastle.oer.its.ieee1609dot2.basetypes.IdentifiedRegion.countryAndRegions){
                        sb.append(REGION_TYPE_IDENTIFIED_COUNTRY_REGION);
                        org.bouncycastle.oer.its.ieee1609dot2.basetypes.CountryAndRegions countryAndRegion =
                                (org.bouncycastle.oer.its.ieee1609dot2.basetypes.CountryAndRegions) identifiedRegion.getIdentifiedRegion();
                        sb.append(ItsSupportedCountries.fromCountryCode(
                                countryAndRegion.getCountryOnly().getValue().intValue()).getDisplayName());
                        sb.append(SEPARATOR);
                        for(UINT8 r: countryAndRegion.getRegions().getUint8s()) {
                            sb.append(r.getValue().intValue());
                            sb.append(SEPARATOR);
                        }
                        
                    } else {
                        // country and sub-region, region and sub-region
                        throw new IllegalArgumentException("Provided identified region type is not supported.");
                    }
                    sb.append(SEQUENCE_SEPARATOR);
                }
                return new IdentifiedRegions(sb.toString());
            default: // polygonal, extension
                throw new IllegalArgumentException("Provided region type is not supported: " + region.getChoice());
        }
    }

    public static double getRadianFromItsLatitude(double latitude) {
        latitude /= 100_000_00;
        return (Math.PI/ 180.0) * latitude;
    }
}
