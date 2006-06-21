package se.anatom.ejbca.util;

import java.io.ByteArrayOutputStream;
import java.util.HashMap;

import junit.framework.TestCase;

import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.Base64PutHashMap;

/** Tests Base64 HashMap XML encoding and decoding
 * 
 * @author tomasg
 * @version $Id: TestHashMap.java,v 1.4 2006-06-21 14:54:56 anatom Exp $
 */
public class TestHashMap extends TestCase {
    //private static final Logger log = Logger.getLogger(TestHashMap.class);

    public TestHashMap(String name) {
        super(name);
    }

    protected void setUp() throws Exception {
    }

    protected void tearDown() throws Exception {
    }

	public void test01HashMapNormal() throws Exception {
        HashMap a = new HashMap();
        a.put("foo0", Boolean.valueOf(false));
        a.put("foo1", "fooString");
        a.put("foo2", new Integer(2));
        a.put("foo3", Boolean.valueOf(true));
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);
        
        java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(data.getBytes("UTF8")));
        HashMap b = (HashMap) decoder.readObject();
        decoder.close();
        assertEquals(((Boolean)b.get("foo0")).booleanValue(),false);
        assertEquals(((Boolean)b.get("foo3")).booleanValue(),true);
        assertEquals(((String)b.get("foo1")),"fooString");
        assertEquals(((Integer)b.get("foo2")).intValue(),2);

	}
	
    public void test01HashMapStrangeChars() throws Exception {
        HashMap a = new HashMap();
        a.put("foo0", Boolean.valueOf(false));
        a.put("foo1", "\0001\0002fooString");
        a.put("foo2", new Integer(2));
        a.put("foo3", Boolean.valueOf(true));
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);

        try {
            java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(data.getBytes("UTF8")));
            HashMap b = (HashMap) decoder.readObject();
            decoder.close();         
            assertEquals(((Boolean)b.get("foo0")).booleanValue(),false);
        } catch (ClassCastException e) {
            return;
        }
        assertTrue(false);
    }
    public void test01HashMapStrangeCharsSafe() throws Exception {
        HashMap h = new HashMap();
        h.put("foo0", Boolean.valueOf(false));
        h.put("foo1", "\0001\0002fooString");
        h.put("foo2", new Integer(2));
        h.put("foo3", Boolean.valueOf(true));
        h.put("foo4", "");
        HashMap a = new Base64PutHashMap();
        a.putAll(h);
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);

        try {
            java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(data.getBytes("UTF8")));
            HashMap b = (HashMap) decoder.readObject();
            decoder.close();    
            HashMap c = new Base64GetHashMap(b);
            assertEquals(((Boolean)c.get("foo0")).booleanValue(),false);
            assertEquals(((Boolean)c.get("foo3")).booleanValue(),true);
            assertEquals(((String)c.get("foo1")),"\0001\0002fooString");
            assertEquals(((String)c.get("foo4")),"");
            assertEquals(((Integer)c.get("foo2")).intValue(),2);
            
        } catch (ClassCastException e) {
            assertTrue(false);
        }
    }
    public void test01HashMapNormalCharsSafe() throws Exception {
        HashMap h = new HashMap();
        h.put("foo0", Boolean.valueOf(false));
        h.put("foo1", "fooString");
        h.put("foo2", new Integer(2));
        h.put("foo3", Boolean.valueOf(true));
        h.put("foo4", "");
        HashMap a = new Base64PutHashMap();
        a.putAll(h);
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        java.beans.XMLEncoder encoder = new java.beans.XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);

        try {
            java.beans.XMLDecoder decoder = new  java.beans.XMLDecoder(new java.io.ByteArrayInputStream(data.getBytes("UTF8")));
            HashMap b = (HashMap) decoder.readObject();
            decoder.close();    
            HashMap c = new Base64GetHashMap(b);
            assertEquals(((Boolean)c.get("foo0")).booleanValue(),false);
            assertEquals(((Boolean)c.get("foo3")).booleanValue(),true);
            assertEquals(((String)c.get("foo4")),"");
            assertEquals(((String)c.get("foo1")),"fooString");
            assertEquals(((Integer)c.get("foo2")).intValue(),2);
            
        } catch (ClassCastException e) {
            assertTrue(false);
        }
    }
}
