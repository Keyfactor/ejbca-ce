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
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.RectangularRegion;
import org.bouncycastle.oer.its.ieee1609dot2.basetypes.SequenceOfRectangularRegion;

public class RectangularRegions implements ItsGeographicElement {

    private List<Point2D[]> rectangles;
    public static final String RECTANGLE_FORMAT_HINT =  "Expected format: "
          + "for each recatangle: latitudeNorthWest,longitudeNorthWest,latitudeSouthEast,longitudeSouthEast";
    
    public RectangularRegions(List<Long[]> rectangles) {
        this.rectangles = new ArrayList<Point2D[]>();
        for(Long[] coord: rectangles) {
            if(coord.length!=4) {
                throw new IllegalArgumentException(RECTANGLE_FORMAT_HINT);
            }
            this.rectangles.add(reorderGeographicPoints(coord));
        }
    }
    
    private Point2D[] reorderGeographicPoints(Long[] coord) {
        try {
            long northMostLatitude;
            long southMostLatitude;
            
            long eastMostLongitude;
            long westMostLongitude;
            
            if(coord[0] > coord[2]) {
                northMostLatitude = coord[0];
                southMostLatitude = coord[2];
            } else {
                northMostLatitude = coord[2];
                southMostLatitude = coord[0];
            }
            
            if(coord[1] > coord[3]) {
                eastMostLongitude = coord[1];
                westMostLongitude = coord[3];
            } else {
                eastMostLongitude = coord[3];
                westMostLongitude = coord[1];
            }
            
            Point2D pointNW = new Point2D(northMostLatitude, westMostLongitude);
            Point2D pointSE = new Point2D(southMostLatitude, eastMostLongitude);
            return new Point2D[] {pointNW, pointSE};
        } catch(Exception e) {
            throw new IllegalArgumentException("Error processing: " + coord + ", " + e.getMessage());
        }
    }
    
    public RectangularRegions(String formattedString) {
        if(StringUtils.isEmpty(formattedString)) {
            throw new IllegalArgumentException("RectangularRegions could not be null or empty.");
        }
        
        String[] rectangles = formattedString.split(ItsGeographicRegion.SEQUENCE_SEPARATOR);
        this.rectangles = new ArrayList<Point2D[]>();
        
        for(String rectangle: rectangles){
            if(StringUtils.isEmpty(rectangle)) {
                continue;
            }
            String[] coords = rectangle.split(ItsGeographicRegion.SEPARATOR);
            if(coords.length!=4) {
                throw new IllegalArgumentException(RECTANGLE_FORMAT_HINT + " : " + rectangle);
            }
            Long[] coordinates = new Long[4];
            for(int i=0; i<4; i++) {
                coordinates[i] = Long.parseLong(coords[i]);
            }
            try {
                this.rectangles.add(reorderGeographicPoints(coordinates));
            } catch(Exception e) {
                throw new IllegalArgumentException("Error processing: " + rectangle + ", " + e.getMessage());
            }
        }
    }
    
    @Override
    public String getFormatHint() {
        return RECTANGLE_FORMAT_HINT;
    }

    @Override
    public String toStringFormat() {
        StringBuilder sb = new StringBuilder();
        sb.append(ItsGeographicRegion.REGION_TYPE_RECTANGLE);
        for(Point2D[] point: this.rectangles) {
            sb.append(point[0].toStringFormat());
            sb.append(ItsGeographicRegion.SEPARATOR);
            sb.append(point[1].toStringFormat());
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
        return new RectangularRegions(formattedString);
    }

    @Override
    public GeographicRegion getGeographicRegion() {
        List<RectangularRegion> rectangularRegions = new ArrayList<>();
        for(Point2D[] points: this.rectangles) {
            RectangularRegion rectangle = new RectangularRegion(points[0].getTwoDLocation(), points[1].getTwoDLocation());
            rectangularRegions.add(rectangle);
        }
        
        return new GeographicRegion(GeographicRegion.rectangularRegion, 
                                    new SequenceOfRectangularRegion(rectangularRegions));
    }

    @Override
    public void validateArgs() {
        // nothing to do
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        return null;
    }
    
    public List<Point2D[]> getRectangles() {
        return rectangles;
    }

    @Override
    public List<String> getGuiDescription() {
        List<String> guiStrings = new ArrayList<>();
        for(Point2D[] rect: rectangles) {
            StringBuilder sb = new StringBuilder();
            sb.append("<b>North-West point:</b> ");
            sb.append(rect[0].getGuiDescription().get(0));
            sb.append("<br><b>South-East point:</b> ");
            sb.append(rect[1].getGuiDescription().get(0));
            guiStrings.add(sb.toString());
        }
        return guiStrings;
    }

    @Override
    public boolean isSubregion(ItsGeographicElement requestedRegion) {
        if(requestedRegion instanceof CircularRegion) {
            CircularRegion circle = (CircularRegion) requestedRegion;
            long centerLatitude = circle.getCenter().getLatitude();
            long centerLongitude = circle.getCenter().getLongitude();
            double radianLatitude = ItsGeographicRegion.getRadianFromItsLatitude(centerLatitude);
            
            double radiusLatitude = circle.getRadius() / ItsGeographicRegion.METER_PER_TENTH_MICRODEGREE_LATITUDE;
            double radiusLongitude = circle.getRadius() 
                    / (ItsGeographicRegion.METER_PER_TENTH_MICRODEGREE_LATITUDE * Math.cos(radianLatitude));
            
            // convert to an rectangle
            long northMostLattitude = centerLatitude + (long)radiusLatitude;
            long southMostLattitude = centerLatitude - (long)radiusLatitude;
            
            long eastMostLongitude = centerLongitude + (long)radiusLongitude;
            long westMostLongitude = centerLongitude - (long)radiusLongitude;
            
            return isSubregion(new RectangularRegions(
                    "" + northMostLattitude + ItsGeographicRegion.SEPARATOR +
                    westMostLongitude + ItsGeographicRegion.SEPARATOR +
                    southMostLattitude + ItsGeographicRegion.SEPARATOR +
                    eastMostLongitude + ItsGeographicRegion.SEQUENCE_SEPARATOR ));
            }
        
        if(requestedRegion instanceof RectangularRegions) {
            boolean result;
            
            // each rectangle should be in another rectangle
            for(Point2D[] requestedRectangle: ((RectangularRegions) requestedRegion).getRectangles()) {
                result = false;
                for(Point2D[] rectangle: rectangles) {
                    if(rectangle[0].getLatitude() >= requestedRectangle[0].getLatitude() &&
                        rectangle[1].getLatitude() <= requestedRectangle[1].getLatitude() && 
                        rectangle[0].getLongitude() <= requestedRectangle[0].getLongitude() &&
                        rectangle[1].getLongitude() >= requestedRectangle[1].getLongitude()) {
                        result = true;
                        break;
                    }
                }
                if(!result) {
                    return false;
                }
            }
            return true;
        }
        
        return false;
    }
    
}