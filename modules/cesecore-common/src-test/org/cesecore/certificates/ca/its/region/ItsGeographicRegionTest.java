package org.cesecore.certificates.ca.its.region;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
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
import org.junit.Before;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

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
        List<Long[]> rectangles = Arrays.asList(new Long[]{1234l, 5678l, 125l, 1750l}, 
                                                new Long[]{898l, 578l, 99005l, 349l});
        RectangularRegions region = new RectangularRegions(rectangles);
        assertEquals("rectangle:1234,1750,125,5678;99005,349,898,578;", region.toStringFormat());
        
        region = new RectangularRegions(rectangles.subList(0, 1));
        assertEquals("rectangle:1234,1750,125,5678;", region.toStringFormat());
        
        ItsGeographicElement geoElement = 
                ItsGeographicRegion.getItsGeographicElementFromString("rectangle:1234,1750,125,5678;99005,349,898,578;");
        
        assertEquals("<b>North-West point:</b> "
                + "<em>latitude:</em> 1234;&nbsp;<em>longitude:</em> 1750<br>"
                + "<b>South-East point:</b> "
                + "<em>latitude:</em> 125;&nbsp;<em>longitude:</em> 5678", geoElement.getGuiDescription().get(0));
        
        assertEquals("<b>North-West point:</b> "
                + "<em>latitude:</em> 99005;&nbsp;<em>longitude:</em> 349<br>"
                + "<b>South-East point:</b> "
                + "<em>latitude:</em> 898;&nbsp;<em>longitude:</em> 578", geoElement.getGuiDescription().get(1));
    }
    
    @Test
    public void testRectangularRegionSubregion() {
        List<Long[]> rectangles = Arrays.asList(new Long[]{10000l, 5000l, 9000l, 6000l}, 
                                                new Long[]{10500l, 5500l, 10000l, 6250l});
        RectangularRegions region = new RectangularRegions(rectangles);
        assertEquals("rectangle:10000,5000,9000,6000;10500,5500,10000,6250;", region.toStringFormat());
        
        RectangularRegions subregion = new RectangularRegions(rectangles.subList(0, 1));
        assertTrue(region.isSubregion(subregion));
        
        subregion = new RectangularRegions("10350,5800,10100,6100;");
        assertTrue(region.isSubregion(subregion));

        subregion = new RectangularRegions("10000,5000,9000,6000;10350,5800,10100,6100;");
        assertTrue(region.isSubregion(subregion));
        
        // actually subregion but currently not supported
        subregion = new RectangularRegions("10250,5500,9750,6000;");
        assertFalse(region.isSubregion(subregion));
    }
    
    @Test
    public void testGeometricSubregion() {
//        Rönninge - 59.189708, 17.744815
//        Åkersberga - 59.463282, 18.316104
//        Södermalm - 59.315384, 18.068912
//        Norra Botkyrka - 59.238834, 17.849437
//        
        RectangularRegions region = new RectangularRegions(
                "" + 591_897_080 + "," + 177_448_150 + "," // Rönninge
                   + 594_632_820 + "," + 183_161_040 + ";"); // Åkersberga
        
        CircularRegion circle = new CircularRegion(593_153_840, 180_689_120, 10000);// Södermalm
        
        assertTrue(region.isSubregion(circle)); // 594062930,178907679,592244750,182470561;
        
        circle = new CircularRegion(592_388_340, 178_494_370, 20000);// Botkyrka
        
        assertFalse(region.isSubregion(circle)); // 594206521,174939489,590570159,182049251;
        
        circle = new CircularRegion(592_388_340, 178_494_370, 10000);// Botkyrka
        
        assertFalse(region.isSubregion(circle)); // 593297430,176716930,591479250,180271810;

        CircularRegion circle2 = new CircularRegion(592_388_340, 178_494_370, 3000);// Botkyrka
        
        assertTrue(region.isSubregion(circle2)); // 592661067,177961138,592115613,179027602
        
        assertTrue(circle.isSubregion(circle2)); // concentric
        
        circle = new CircularRegion(593_153_840, 180_689_120, 25000);// Södermalm
        
        assertTrue(circle.isSubregion(circle2)); // non concentric - road distance 19.5km, calculated ~15km
        
        assertTrue(circle.isSubregion(region)); // ~24.5km
        
        region = new RectangularRegions("592661067,177961138,592115613,179027602");// Botkyrka, 3000m
        
        assertTrue(circle.isSubregion(region)); // 19km (3 * 1.414 + 15km)
         
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
                        "identifed:country:Denmark;country_region:Belgium,123,45,34;"
                        + "country:Italy;country_region:Austria,66;");
        
        assertEquals("Denmark", geoElement.getGuiDescription().get(0));
        
        assertEquals("<b>Country:</b> Belgium<br><b>Regions:</b> 123,45,34,", 
                                                geoElement.getGuiDescription().get(1));
        
        assertEquals("Italy", geoElement.getGuiDescription().get(2));
        
        assertEquals("<b>Country:</b> Austria<br><b>Regions:</b> 66,", 
                geoElement.getGuiDescription().get(3));
        
        ItsGeographicElement subElement1 = 
                ItsGeographicRegion.getItsGeographicElementFromString(
                        "identifed:country:Denmark;country_region:Belgium,123,45,34;");
        assertTrue(geoElement.isSubregion(subElement1));
        
        ItsGeographicElement subElement2 = 
                ItsGeographicRegion.getItsGeographicElementFromString(
                        "identifed:country_region:Denmark,123,45;country_region:Belgium,123,45,34;");
        assertTrue(geoElement.isSubregion(subElement2));
        
        ItsGeographicElement subElement3 = 
                ItsGeographicRegion.getItsGeographicElementFromString(
                        "identifed:country:Denmark;country_region:Belgium,123,45,34;country:Latvia;");
        assertFalse(geoElement.isSubregion(subElement3));
        
        ItsGeographicElement subElement4 = 
                ItsGeographicRegion.getItsGeographicElementFromString(
                        "identifed:country_region:Belgium,123,99;");
        assertFalse(geoElement.isSubregion(subElement4));
        
        ItsGeographicElement subElement5 = 
                ItsGeographicRegion.getItsGeographicElementFromString(
                        "identifed:country:Latvia;");
        assertFalse(geoElement.isSubregion(subElement5));
        
        ItsGeographicElement geoElement2 = 
                ItsGeographicRegion.getItsGeographicElementFromString(
                        "identifed:country:Denmark;"
                        + "country:-Europe;country_region:Austria,66;");
        assertEquals("-Europe", geoElement2.getGuiDescription().get(1));
        assertTrue(geoElement2.isSubregion(subElement1));
        assertTrue(geoElement2.isSubregion(subElement2));
        assertTrue(geoElement2.isSubregion(subElement3));
        assertTrue(geoElement2.isSubregion(subElement4));
        assertTrue(geoElement2.isSubregion(subElement5));
        
    }
    
    @Test
    public void testIdentifiedRegionInvalid() {
        
        try {
            new IdentifiedRegionCountryRegions("Belgium,256");
            fail("too large region index.");
        } catch(Exception e) {
            assertEquals(e.getMessage(), "Expected unsigned 8bit integer(0-255) as region. 256");
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
        roundTripBCtoEJBCA("rectangle:34,23,12,56;78,65,76,90;");
    }
    
    @Test
    public void testConstructItsRegionFromBCCircle() {
        roundTripBCtoEJBCA("circular:123,56,125");
    }
    
    @Test
    public void testConstructItsRegionFromBCIdentifedRegion() {
        roundTripBCtoEJBCA("identifed:country:Denmark;country_region:Belgium,12,45,34;country:-Europe;country_region:Austria,45;");
    }
    
    @Test
    public void testConstructItsRegionFromBCIdentifedRegion2() {
        roundTripBCtoEJBCA("identifed:country_region:Belgium,123,45,34;country_region:Austria,66;");
    }

}
