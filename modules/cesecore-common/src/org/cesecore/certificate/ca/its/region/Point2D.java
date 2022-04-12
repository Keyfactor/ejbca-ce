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

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.IdentifiedRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Latitude;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.Longitude;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.TwoDLocation;

public class Point2D implements ItsGeographicElement {
    /**
     * Intended to represent TwoDLocation(latitude, longitude) class. 
     * Validations are handled by corresponding BouncyCastle classes. 
     */
    private long latitude;
    private long longitude;
    
    public static final String POINT_FORMAT_HINT = "Expected Point2D format[without braces]: {latitude,longitude} e.g. {680000,-1500000}." +
            "Range of Latitude: {-900000000,900000000} and range of Longitude: {-1799999999,1800000000}";
    
    public Point2D(long latitude, long longitude) {
        this.latitude = latitude;
        this.longitude = longitude;
        validateArgs();
    }
    
    public Point2D(String formattedPoint) {
        //TODO: move exception messages to resource
        if(StringUtils.isEmpty(formattedPoint)) {
            throw new IllegalArgumentException("Point2D could not be null or empty.");
        }
        
        String[] points = formattedPoint.split(ItsGeographicRegion.SEPARATOR);
        if(points.length!=2) {
            throw new IllegalArgumentException(POINT_FORMAT_HINT);
        }
        
        // let the exception propagate
        this.latitude = Long.parseLong(points[0]);
        this.longitude = Long.parseLong(points[1]);
        validateArgs();
    }
    
    public long getLatitude() {
        return latitude;
    }

    public void setLatitude(long latitude) {
        this.latitude = latitude;
    }

    public long getLongitude() {
        return longitude;
    }

    public void setLongitude(long longitude) {
        this.longitude = longitude;
    }

    public TwoDLocation getTwoDLocation() {
        // let the original exception message propagate
        return new TwoDLocation(new Latitude(latitude), new Longitude(longitude));
    }
    
    /**
     * Used for representation in both GUI and DB
     */
    public String toStringFormat() {
        return latitude + ItsGeographicRegion.SEPARATOR + longitude;
    }
    
    @Override
    public String toString() {
        return this.toStringFormat();
    }

    @Override
    public String getFormatHint() {
        return POINT_FORMAT_HINT;
    }

    @Override
    public ItsGeographicElement fromString(String formattedString) {
        return new Point2D(formattedString);
    }

    @Override
    public GeographicRegion getGeographicRegion() {
        throw new IllegalArgumentException("Point2D can not represented as GeographicRegion.");
    }

    @Override
    public void validateArgs() {
        new Latitude(getLatitude());
        new Longitude(getLongitude());
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        return null;
    }

    @Override
    public List<String> getGuiDescription() {
        List<String> guiStrings = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        sb.append("<em>latitude:</em> ");
        sb.append(getLatitude());
        sb.append(";&nbsp;");
        sb.append("<em>longitude:</em> ");
        sb.append(getLongitude());
        guiStrings.add(sb.toString());
        return guiStrings;
    }

    @Override
    public boolean isSubregion(ItsGeographicElement requestedRegion) {
        return false; // irrelevant
    }
    
}