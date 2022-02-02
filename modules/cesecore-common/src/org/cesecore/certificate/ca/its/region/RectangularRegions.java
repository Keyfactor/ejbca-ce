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
            try {
                Point2D pointNW = new Point2D(coord[0], coord[1]);
                Point2D pointSE = new Point2D(coord[2], coord[3]);
                this.rectangles.add(new Point2D[] {pointNW, pointSE});
            } catch(Exception e) {
                throw new IllegalArgumentException("Error processing: " + coord + ", " + e.getMessage());
            }
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
                Point2D pointNW = new Point2D(coordinates[0], coordinates[1]);
                Point2D pointSE = new Point2D(coordinates[2], coordinates[3]);
                this.rectangles.add(new Point2D[] {pointNW, pointSE});
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
        // TODO: is north east point in north and east of the other point?
        // nothing to do
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        return null;
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
    
}