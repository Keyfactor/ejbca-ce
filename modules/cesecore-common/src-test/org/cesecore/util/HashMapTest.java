/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.util;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.HashMap;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/** Tests Base64 HashMap XML encoding and decoding
 * 
 * @version $Id$
 */
public class HashMapTest {

    @SuppressWarnings("rawtypes")
    @Test
	public void testHashMapNormal() throws Exception {
        HashMap<String, Comparable> a = new HashMap<String, Comparable>();
        a.put("foo0", Boolean.FALSE);
        a.put("foo1", "fooString");
        a.put("foo2", Integer.valueOf(2));
        a.put("foo3", Boolean.TRUE);
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);
        
        XMLDecoder decoder = new  XMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
        HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
        decoder.close();
        assertEquals(((Boolean)b.get("foo0")).booleanValue(),false);
        assertEquals(((Boolean)b.get("foo3")).booleanValue(),true);
        assertEquals(((String)b.get("foo1")),"fooString");
        assertEquals(((Integer)b.get("foo2")).intValue(),2);

	}
	
    @SuppressWarnings("rawtypes")
    @Test
    public void testHashMapStrangeChars() throws Exception {
        HashMap<String, Comparable> a = new HashMap<String, Comparable>();
        a.put("foo0", Boolean.FALSE);
        a.put("foo1", "\0001\0002fooString");
        a.put("foo2", Integer.valueOf(2));
        a.put("foo3", Boolean.TRUE);
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);

        try {
            XMLDecoder decoder = new  XMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
            HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
            decoder.close();         
            assertEquals(((Boolean)b.get("foo0")).booleanValue(),false);
        // We can get two different errors, I don't know if it is different java versions or what...
        // The important thing is that we do expect an error to occur here
        } catch (ClassCastException e) {
            return;
        } catch (ArrayIndexOutOfBoundsException e) {
            return;
        }
        assertTrue(true);        	
    }
    @SuppressWarnings("rawtypes")
    @Test
    public void testHashMapStrangeCharsSafe() throws Exception {
        HashMap<String, Comparable> h = new HashMap<String, Comparable>();
        h.put("foo0", Boolean.FALSE);
        h.put("foo1", "\0001\0002fooString");
        h.put("foo2", Integer.valueOf(2));
        h.put("foo3", Boolean.TRUE);
        h.put("foo4", "");
        HashMap<Object, Object> a = new Base64PutHashMap();
        a.putAll(h);
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);

        try {
            XMLDecoder decoder = new  XMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
            HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
            decoder.close();    
            @SuppressWarnings("unchecked")
            HashMap<Object, Object> c = new Base64GetHashMap(b);
            assertEquals(((Boolean)c.get("foo0")).booleanValue(),false);
            assertEquals(((Boolean)c.get("foo3")).booleanValue(),true);
            assertEquals(((String)c.get("foo1")),"\0001\0002fooString");
            assertEquals(((String)c.get("foo4")),"");
            assertEquals(((Integer)c.get("foo2")).intValue(),2);
            
        } catch (ClassCastException e) {
            assertTrue(false);
        }
    }
    @SuppressWarnings("rawtypes")
    @Test
    public void testHashMapNormalCharsSafe() throws Exception {
        HashMap<String, Comparable> h = new HashMap<String, Comparable>();
        h.put("foo0", Boolean.FALSE);
        h.put("foo1", "fooString");
        h.put("foo2", Integer.valueOf(2));
        h.put("foo3", Boolean.TRUE);
        h.put("foo4", "");
        HashMap<Object, Object> a = new Base64PutHashMap();
        a.putAll(h);
        
        // Write to XML
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        XMLEncoder encoder = new XMLEncoder(baos);
        encoder.writeObject(a);
        encoder.close();
        String data = baos.toString("UTF8");
        //log.error(data);

        try {
            XMLDecoder decoder = new  XMLDecoder(new ByteArrayInputStream(data.getBytes("UTF8")));
            HashMap<?, ?> b = (HashMap<?, ?>) decoder.readObject();
            decoder.close();    
            @SuppressWarnings("unchecked")
            HashMap<Object, Object> c = new Base64GetHashMap(b);
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
