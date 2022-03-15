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
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.UINT16;

public class CircularRegion implements ItsGeographicElement {
    
    private Point2D center;
    private int radius;
    
    public static final String CIRCLE_FORMAT_HINT = "Expected format: centerLatitude,centerLongitude,radius "
                                            + "e.g. 12892199,994123,13222. max radius: 65535";
    
    public CircularRegion(long centerLatitude, long centerLongitude, int radius) {
        this.center = new Point2D(centerLatitude, centerLongitude);
        this.radius = radius;
        validateArgs();
    }
    
    public CircularRegion(String formattedString) {
        if(StringUtils.isEmpty(formattedString)) {
            throw new IllegalArgumentException("CircularRegion could not be null or empty.");
        }
        
        String[] points = formattedString.split(ItsGeographicRegion.SEPARATOR);
        if(points.length!=3) {
            throw new IllegalArgumentException(CIRCLE_FORMAT_HINT);
        }
        
        // let the exception propagate
        this.center = new Point2D(Long.parseLong(points[0]), Long.parseLong(points[1]));
        this.radius = Integer.parseInt(points[2]);
        validateArgs();
    }        

    public Point2D getCenter() {
        return center;
    }

    public void setCenter(Point2D center) {
        this.center = center;
    }

    public int getRadius() {
        return radius;
    }

    public void setRadius(int radius) {
        this.radius = radius;
    }

    @Override
    public String getFormatHint() {
        return CIRCLE_FORMAT_HINT;
    }

    @Override
    public ItsGeographicElement fromString(String formattedString) {
        return new CircularRegion(formattedString);
    }

    @Override
    public GeographicRegion getGeographicRegion() {
        return new GeographicRegion(GeographicRegion.circularRegion, 
                new org.bouncycastle.oer.its.ieee1609dot2.basetypes.
                    CircularRegion(this.center.getTwoDLocation(), new UINT16(this.radius)));
    }

    @Override
    public String toStringFormat() {
        return ItsGeographicRegion.REGION_TYPE_CIRCULAR + getCenter().toStringFormat() 
                + ItsGeographicRegion.SEPARATOR + getRadius();
    }

    @Override
    public void validateArgs() {
        new UINT16(getRadius());
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        return null;
    }
    
    @Override
    public String toString() {
        return this.toStringFormat();
    }

    @Override
    public List<String> getGuiDescription() {
        List<String> guiStrings = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        sb.append("<b>Center</b>: ");
        sb.append(center.getGuiDescription().get(0));
        sb.append("<br><b>Radius:</b> ");
        sb.append(radius);
        guiStrings.add(sb.toString());
        return guiStrings;
    }

    @Override
    public boolean isSubregion(ItsGeographicElement requestedRegion) {
        if(requestedRegion instanceof CircularRegion) {
            CircularRegion possibleSubregion = (CircularRegion) requestedRegion;
            if(radius < possibleSubregion.getRadius()) {
                return false;
            }
            
            double distanceCenters = calculateDistance(possibleSubregion.getCenter());
            if(radius > distanceCenters + possibleSubregion.getRadius()) {
                return true;
            }
        }
        
        if(requestedRegion instanceof RectangularRegions) {
            for(Point2D[] bound: ((RectangularRegions) requestedRegion).getRectangles()) {
                double maxDistance = 0.0;
                // NW
                maxDistance = Math.max(maxDistance, calculateDistance(
                        new Point2D(bound[0].getLatitude(), bound[0].getLongitude())));
                // SW
                maxDistance = Math.max(maxDistance, calculateDistance(
                        new Point2D(bound[0].getLatitude(), bound[1].getLongitude())));
                // NE
                maxDistance = Math.max(maxDistance, calculateDistance(
                        new Point2D(bound[1].getLatitude(), bound[0].getLongitude())));
                // SE
                maxDistance = Math.max(maxDistance, calculateDistance(
                        new Point2D(bound[1].getLatitude(), bound[1].getLongitude())));
                if(radius > maxDistance) {
                    return true;
                }
            }
        }
        return false;
    }
    
    protected double calculateDistance(Point2D anotherPoint) {
        long latitudeDiffCenters = Math.abs(center.getLatitude() - anotherPoint.getLatitude());
        long longitudeDiffCenters = Math.abs(center.getLongitude() - anotherPoint.getLongitude());
        
        double distanceLatitude = latitudeDiffCenters * ItsGeographicRegion.METER_PER_TENTH_MICRODEGREE_LATITUDE;
        double distanceLongitude = longitudeDiffCenters
                * ItsGeographicRegion.METER_PER_TENTH_MICRODEGREE_LATITUDE 
                * Math.cos(ItsGeographicRegion.getRadianFromItsLatitude(center.getLatitude()));
        
        return Math.sqrt(distanceLatitude*distanceLatitude + distanceLongitude*distanceLongitude);
    }
    
}