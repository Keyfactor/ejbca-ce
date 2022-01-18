package org.cesecore.certificate.ca.its.region;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.oer.its.GeographicRegion;
import org.bouncycastle.oer.its.IdentifiedRegion;
import org.bouncycastle.oer.its.Uint16;

public class CircularRegion implements ItsGeographicElement {
    
    private Point2D center;
    private int radius;
    
    public static final String CIRCLE_FORMAT_HINT = "Expected format[without braces]: {centerLatitude,centerLongitude,radius} "
                                            + "e.g. {12892199,994123,13222}. max radius: 65535";
    
    public CircularRegion(int centerLatitude,  int centerLongitude, int radius) {
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
                new org.bouncycastle.oer.its.CircularRegion(this.center.getTwoDLocation(), new Uint16(this.radius)));
    }

    @Override
    public String toStringFormat() {
        return ItsGeographicRegion.REGION_TYPE_CIRCULAR + getCenter().toStringFormat() 
                + ItsGeographicRegion.SEPARATOR + getRadius();
    }

    @Override
    public void validateArgs() {
        new Uint16(getRadius());
    }

    @Override
    public IdentifiedRegion getIdentifiedRegion() {
        return null;
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
    
}