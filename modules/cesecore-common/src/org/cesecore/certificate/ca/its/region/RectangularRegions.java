package org.cesecore.certificate.ca.its.region;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.oer.its.GeographicRegion;
import org.bouncycastle.oer.its.IdentifiedRegion;
import org.bouncycastle.oer.its.RectangularRegion;
import org.bouncycastle.oer.its.SequenceOfRectangularRegion;

public class RectangularRegions implements ItsGeographicElement {

    private List<Point2D[]> rectangles;
    public static final String RECTANGLE_FORMAT_HINT =  "Expected format[without braces]: "
          + "for each recatangle: {latitudeNorthWest,longitudeNorthWest,latitudeSouthEast,longitudeSouthEast}";
    
    public RectangularRegions(List<Long[]> rectangles) {
        createRectangles(rectangles);
    }
    
    private void createRectangles(List<Long[]> rectangles) {
        this.rectangles = new ArrayList<Point2D[]>();
        for(Long[] coord: rectangles) {
            if(coord.length!=4) {
                throw new IllegalArgumentException(RECTANGLE_FORMAT_HINT);
            }
            Point2D pointNW = new Point2D(coord[0], coord[1]);
            Point2D pointSE = new Point2D(coord[2], coord[3]);
            this.rectangles.add(new Point2D[] {pointNW, pointSE});
        }
    }
    
    public RectangularRegions(String formattedString) {
        if(StringUtils.isEmpty(formattedString)) {
            throw new IllegalArgumentException("RectangularRegions could not be null or empty.");
        }
        
        String[] rectangles = formattedString.split(ItsGeographicRegion.SEQUENCE_SEPARATOR);
        List<Long[]> rectangleCoords = new ArrayList<>();
        for(String rectangle: rectangles){
            if(StringUtils.isEmpty(rectangle)) {
                continue;
            }
            String[] coords = rectangle.split(ItsGeographicRegion.SEPARATOR);
            if(coords.length!=4) {
                throw new IllegalArgumentException(RECTANGLE_FORMAT_HINT);
            }
            Long[] coordinates = new Long[4];
            for(int i=0; i<4; i++) {
                coordinates[i] = Long.parseLong(coords[i]);
            }
            rectangleCoords.add(coordinates);
        }
        createRectangles(rectangleCoords);
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
            sb.append(point[0].toString());
            sb.append(ItsGeographicRegion.SEPARATOR);
            sb.append(point[1].toString());
            sb.append(ItsGeographicRegion.SEQUENCE_SEPARATOR);
        }
        return sb.toString();
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
    
}