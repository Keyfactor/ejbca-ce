/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;

/**
 * Intermediate representation of GeographicRegion region object for GUI and persistence.
 */
public class ItsGeographicRegion implements Serializable {

    private static final long serialVersionUID = 8480860776365248654L;
    
    public static final String SEPARATOR = ",";
    public static final String SEQUENCE_SEPARATOR = ";";
    
    private static final String TYPE_SEPARATOR = ":";
    
    protected static final int IDENTIFIED_REGION_EUROPE = 0xFFFF;
    
    public static final String REGION_TYPE_CIRCULAR = "circular:";
    public static final String REGION_TYPE_RECTANGLE = "rectangle:";
    public static final String REGION_TYPE_IDENTIFIED_COUNTRY = "country:";
    public static final String REGION_TYPE_IDENTIFIED_COUNTRY_REGION = "country_region:";
    public static final String REGION_TYPE_IDENTIFIED = "identifed:";
    
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
    
//    private static final Map<RegionType, Class> regionTypeImplementations;
//    static {
//        regionTypeImplementations = new HashMap<>();
//        regionTypeImplementations.put(RegionType.CIRCULAR, CircularRegion.class);
//        //regionTypeImplementations.get(RegionType.CIRCULAR).getConstructor(String.class).newInstance(null);
//    }
    
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
    
    private RegionType parseAndSetRegionType(String region) {
        if(region.indexOf(TYPE_SEPARATOR)==-1) {
            throw new IllegalArgumentException("Invalid region: " + region);
        }
        String regionType = region.substring(0, region.indexOf(TYPE_SEPARATOR)) + TYPE_SEPARATOR;
        switch(regionType) {
        case REGION_TYPE_CIRCULAR:
            return RegionType.CIRCULAR;
        case REGION_TYPE_RECTANGLE:
            return RegionType.RECTANGULAR;
        case REGION_TYPE_IDENTIFIED:
            return RegionType.IDENTIFIED;
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

}
