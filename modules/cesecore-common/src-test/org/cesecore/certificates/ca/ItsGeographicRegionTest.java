package org.cesecore.certificates.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.List;

import org.bouncycastle.oer.its.ieee1609dot2.basetypes.GeographicRegion;
import org.cesecore.certificate.ca.its.region.CircularRegion;
import org.cesecore.certificate.ca.its.region.IdentifiedRegionCountryRegions;
import org.cesecore.certificate.ca.its.region.ItsGeographicElement;
import org.cesecore.certificate.ca.its.region.ItsGeographicRegion;
import org.cesecore.certificate.ca.its.region.RectangularRegions;
import org.cesecore.util.CryptoProviderTools;
import org.junit.Before;
import org.junit.Test;

public class ItsGeographicRegionTest {
    
    @Before
    public void installBcProvider() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testCirularRegion() {
        CircularRegion region = new CircularRegion(1234, 5678, 125);
        assertEquals("circular:1234,5678,125", region.toStringFormat());
        
        ItsGeographicElement geoElement = 
                ItsGeographicRegion.getItsGeographicElementFromString("circular:-9090,89882,12509");
        
        assertEquals("<b>Center</b>: "
                + "<em>latitude:</em> -9090;&nbsp;<em>longitude:</em> 89882<br>"
                + "<b>Radius:</b> 12509", geoElement.getGuiDescription().get(0));
    }
    
    @Test
    public void testCirularRegionInvalid() {
        try {
            new CircularRegion("circular:-9090,89882,12509");
            fail("badly formatted string");
        } catch(Exception e) {
            assertTrue(e.getClass().getSimpleName().contains("NumberFormatException"));
        }
        
        try {
            new CircularRegion("909082,12509");
            fail("badly formatted gui string");
        } catch(Exception e) {
            assertEquals(e.getMessage(), CircularRegion.CIRCLE_FORMAT_HINT);
        }
        
        try {
            new CircularRegion("");
            fail("blank gui string");
        } catch(Exception e) {
            assertEquals(e.getMessage(), "CircularRegion could not be null or empty.");
        }
        
        try {
            new CircularRegion("9090,99999999999,12509");
            fail("invalid longitude");
        } catch(Exception e) {
            assertTrue(e.getClass().getSimpleName().contains("IllegalStateException"));
            assertEquals(e.getMessage(), "one eighty degree int cannot be greater than 1800000000");
        }
        
        try {
            new CircularRegion("99999999999,123,12509");
            fail("invalid latitude");
        } catch(Exception e) {
            assertTrue(e.getClass().getSimpleName().contains("IllegalStateException"));
            assertEquals(e.getMessage(), "ninety degree int cannot be greater than 900000000");
        }
        
        try {
            new CircularRegion("99,123,66000");
            fail("invalid radius");
        } catch(Exception e) {
            assertTrue(e.getClass().getSimpleName().contains("IllegalArgumentException"));
        }
    }
    
    @Test
    public void testRectangularRegion() {
        List<Long[]> rectangles = Arrays.asList(new Long[]{1234l, 5678l, 125l, 1234l}, 
                                                new Long[]{898l, 578l, 99005l, 3499l});
        RectangularRegions region = new RectangularRegions(rectangles);
        assertEquals("rectangle:1234,5678,125,1234;898,578,99005,3499;", region.toStringFormat());
        
        region = new RectangularRegions(rectangles.subList(0, 1));
        assertEquals("rectangle:1234,5678,125,1234;", region.toStringFormat());
        
        ItsGeographicElement geoElement = 
                ItsGeographicRegion.getItsGeographicElementFromString("rectangle:1234,5678,125,1234;898,578,99005,3499;");
        
        assertEquals("<b>North-West point:</b> "
                + "<em>latitude:</em> 1234;&nbsp;<em>longitude:</em> 5678<br>"
                + "<b>South-East point:</b> "
                + "<em>latitude:</em> 125;&nbsp;<em>longitude:</em> 1234", geoElement.getGuiDescription().get(0));
        
        assertEquals("<b>North-West point:</b> "
                + "<em>latitude:</em> 898;&nbsp;<em>longitude:</em> 578<br>"
                + "<b>South-East point:</b> "
                + "<em>latitude:</em> 99005;&nbsp;<em>longitude:</em> 3499", geoElement.getGuiDescription().get(1));
    }
    
    @Test
    public void testRectangularRegionInvalid() {
        try {
            new RectangularRegions("rectangle:1234,5678,125,1234;");
            fail("badly formatted string");
        } catch(Exception e) {
            assertTrue(e.getClass().getSimpleName().contains("NumberFormatException"));
        }
        
        try {
            new RectangularRegions("1234,5678,125;");
            fail("badly formatted gui string");
        } catch(Exception e) {
            assertEquals(e.getMessage(), RectangularRegions.RECTANGLE_FORMAT_HINT +  " : 1234,5678,125");
        }
        
        try {
            new RectangularRegions("1234,5678,125,1234;1234,5678,125;");
            fail("badly formatted gui string");
        } catch(Exception e) {
            assertEquals(e.getMessage(), RectangularRegions.RECTANGLE_FORMAT_HINT + " : 1234,5678,125");
        }
        
        try {
            new RectangularRegions("");
            fail("blank gui string");
        } catch(Exception e) {
            assertEquals(e.getMessage(), "RectangularRegions could not be null or empty.");
        }
    }
    
    @Test
    public void testIdentifiedRegion() {
        ItsGeographicElement geoElement = 
                ItsGeographicRegion.getItsGeographicElementFromString(
                        "identifed:country:Denmark;country_region:Belgium,1234,456,342;"
                        + "country:-Europe;country_region:Austria,4566;");
        
        assertEquals("Denmark", geoElement.getGuiDescription().get(0));
        
        assertEquals("<b>Country:</b> Belgium<br><b>Regions:</b> 1234,456,342,", 
                                                geoElement.getGuiDescription().get(1));
        
        assertEquals("-Europe", geoElement.getGuiDescription().get(2));
        
        assertEquals("<b>Country:</b> Austria<br><b>Regions:</b> 4566,", 
                geoElement.getGuiDescription().get(3));
    }
    
    @Test
    public void testIdentifiedRegionInvalid() {
        
        try {
            new IdentifiedRegionCountryRegions("Belgium,1234,66000,342");
            fail("too large region index.");
        } catch(Exception e) {
            assertEquals(e.getMessage(), "Expected unsigned 16bit integer(0-65535) as region. 66000");
        }
    }
    
    private void roundTripBCtoEJBCA(String regionDescription) {
        GeographicRegion region =
                ItsGeographicRegion.fromString(regionDescription)
                .getGeographicElement().getGeographicRegion();

        assertEquals(ItsGeographicRegion.fromGeographicRegion(region).toStringFormat(), regionDescription);
    }
    
    @Test
    public void testConstructItsRegionFromBCRectangle() {
        roundTripBCtoEJBCA("rectangle:12,23,34,56;78,90,76,65;");
    }
    
    @Test
    public void testConstructItsRegionFromBCCircle() {
        roundTripBCtoEJBCA("circular:1234,5678,125");
    }
    
    @Test
    public void testConstructItsRegionFromBCIdentifedRegion() {
        roundTripBCtoEJBCA("identifed:country:Denmark;country_region:Belgium,1234,456,342;country:-Europe;country_region:Austria,4566;");
    }
    
    @Test
    public void testConstructItsRegionFromBCIdentifedRegion2() {
        roundTripBCtoEJBCA("identifed:country_region:Belgium,1234,456,342;country_region:Austria,4566;");
    }

}
