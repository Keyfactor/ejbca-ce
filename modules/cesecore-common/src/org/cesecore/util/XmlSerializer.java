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
package org.cesecore.util;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;

/**
 * This is a helper classed that handles the serialization to and deserialization from XML.
 * 
 * Stored Strings in the input are stored as Base64 encoded strings, if not asciiPrintable, where Base64 encoding is not needed then it is stored as is.  
 * 
 * @version $Id$
 */
public class XmlSerializer {

    private static final Logger log = Logger.getLogger(XmlSerializer.class);

	@SuppressWarnings("unchecked")
    public static Map<String, Object> decode(final String input) {
		Map<String, Object> ret = null;
		if (input != null) {
            try (final SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)))) {
                final LinkedHashMap<String,Object> h = (LinkedHashMap<String,Object>) decoder.readObject();
                // Handle Base64 encoded string values
                ret = new Base64GetHashMap(h);
            } catch (IOException e) {
                final String msg = "Failed to parse data map: " + e.getMessage();
                if (log.isDebugEnabled()) {
                    log.debug(msg + ". Data:\n" + input);
                }
                throw new IllegalStateException(msg, e);
            }
		}
		return ret;
	}
	
	private static String encodeInternal(final Map<String, Object> input, final boolean encodeNonPrintableWithBase64) {
		String ret = null;
		if (input != null) {
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			try (final XMLEncoder encoder = new XMLEncoder(baos)) {
    			final LinkedHashMap<Object,Object> linkedHashMap = encodeNonPrintableWithBase64 ? new Base64PutHashMap() : new LinkedHashMap<>();
    			// Copy one by one through the get() method, so the values get transformed if needed
    			for (String key : input.keySet()) {
                    linkedHashMap.put(key, input.get(key));
                }
    			encoder.writeObject(linkedHashMap);
			}
			try {
                ret = baos.toString("UTF8");
            } catch (UnsupportedEncodingException e) {
                // Fatal. No point in handling the lack of UTF-8
                throw new IllegalStateException(e);
            }
		}
		return ret;
	}
	
	/**
	 * Serializes a map using Java's XMLEncoder. Non ASCII printable characters are Base64 encoded.
	 */
	public static String encode(final Map<String, Object> input) {
        return encodeInternal(input, true);
    }
	
	/**
     * Serializes a map using Java's XMLEncoder. No Base64 encoding is done of non-printable characters.
     */
	public static String encodeWithoutBase64(final Map<String, Object> input) {
        return encodeInternal(input, false);
    }
	
	/** A method that mimics java.bean.XMLEncoder for simple Maps, but does it very fast, and falls back to using java.bean.XMLEncoder for more complex objects.
	 * A simple object is a Map that only have keys that are Strings and values that are primitive values or Properties, List or Map in it, where these objects 
	 * are also only simple String keyed ones. 
	 * Handles primitive types:
	 * null, String, Integer, Boolean, Long, Class, Float, Double, Date.
	 * 
	 * Example output:
	 * <?xml version="1.0" encoding="UTF-8"?>
     *   <java version="11.0.7" class="java.beans.XMLDecoder">
     *    <object class="org.cesecore.util.Base64PutHashMap">
     *     <void method="put">
     *      <string>version</string>
     *      <float>4.0</float>
     *     </void>
     *     <void method="put">
     *      <string>type</string>
     *      <int>0</int>
     *     </void>
     *     <void method="put">
     *      <string>mystring</string>
     *      <string>I am from Sweden</string>
     *     </void>
     *     <void method="put">
     *      <string>CERTIFICATESERIALNUMBER</string>
     *      <string>ew==</string>
     *     </void>
     *     <void method="put">
     *      <string>SCEP_CACHED_APROVAL_TYPE</string>
     *      <class>tomas.TestProfiling$TestApprovalRequest</class>
     *     </void>
     *     <void method="put">
     *      <string>longvalue</string>
     *      <long>123456789</long>
     *     </void>
     *     <void method="put">
     *      <string>boolvalue</string>
     *      <boolean>true</boolean>
     *     </void>
     *     <void method="put">
     *      <string>doublevalue</string>
     *      <double>1.25</double>
     *     </void>
     *     <void method="put">
     *      <string>datevalue</string>
     *      <object class="java.util.Date">
     *       <long>1588783538788</long>
     *      </object>
     *     </void>
     *     <void method="put">
     *      <string>tokenproperties</string>
     *      <object class="java.util.Properties">
     *       <void method="put">
     *        <string>tokensequence</string>
     *        <string>00000</string>
     *       </void>
     *      </object>
     *     </void>
     *     <void method="put">
     *      <string>mylinkedhashmap</string>
     *      <object class="java.util.LinkedHashMap">
     *       <void method="put">
     *        <string>akey</string>
     *        <string>avalue</string>
     *       </void>
     *      </object>
     *     </void>
     *     <void method="put">
     *      <string>myarraylist</string>
     *      <object class="java.util.ArrayList">
     *       <void method="add">
     *        <string>listitem1</string>
     *       </void>
     *      </object>
     *     </void>
     *    </object>
     *   </java>
	 * 
     * @param map to write to XML, in format standardized by java.beans.XMLEncoder
	 * @throws IllegalArgumentException if the map is not a LinkedHashMap or includes types not handled by the simple encoding
	 */
	public static String encodeSimpleMapFast(final Map<Object, Object> map) {
        if (map == null) {
            return null;
        }
	    if (map instanceof LinkedHashMap) {
	        final ByteArrayOutputStream os = new ByteArrayOutputStream(1024);
	        final PrintStream ps = new PrintStream(os);
	        ps.println("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
	        ps.println("<java version=\"" + System.getProperty("java.version") + "\" class=\"java.beans.XMLDecoder\">");
            printObject(map, 1, ps); // Start indent 1        
	        ps.println("</java>");
	        try {
	            return os.toString("UTF-8");
	        } catch (UnsupportedEncodingException e) {
	            // Fatal. No point in handling the lack of UTF-8
	            throw new IllegalStateException(e);
	        }
	    }
        throw new IllegalArgumentException("Input to encodeSimpleObjectFast must be a LinkedHashMap: " + map.getClass().getName());
	}

    /** Calls #encodeSimpleObjectFast after first copying the values of map into a Base64PutHashMap, encoding them as Bae64, if they are not asciiPrintable
     * 
     * @param map that is not a Base64PutHashMap
     * @throws IllegalArgumentException if the map is not a LinkedHashMap or includes types not handled by the simple encoding
     */
	public static String encodeSimpleMapFastWithBase64(final Map<String, Object> map) {
	    if (map == null) {
	        return null;
	    }
        final LinkedHashMap<Object,Object> b64DataMap = new Base64PutHashMap();
        b64DataMap.putAll(map);
        return encodeSimpleMapFast(b64DataMap);
	}
    
	/** This will be called recursively, but the encode methods, which is why we include the "indent"
	 * specification handling how many spaces are used for indentation
	 * @param o the object to encode into XML
	 * @param type the type 
	 * @param ps
	 */
    private static void printObject(final Object o, int indent, final PrintStream ps) {
        if (StringUtils.startsWith(getType(o), "object")) {
            // Object objects are handled by the specific handlers 
            printValue(o, indent, ps);
        } else {
            encodePrimitive(o, indent, ps);
        }
    }

    /** Static final Strings in order to make String handling static and fast */
    private static final String[] INDENT = {"", " ", "  ", "   ", "    ", "     ", "      "};
    private static final String getIndent(final int i) {
        if (i > 6) {
            throw new IllegalArgumentException("Input to encodeSimpleMapFast can not have a recursive depth larger than 5 (six steps of indetation");            
        }
        return INDENT[i];
    }
    
    private static void encodePrimitive(final Object o, int indent, PrintStream ps) {
        // primitive objects are a single line
        final String type = getType(o);
        if (type == null) {
            ps.print(getIndent(indent));
            ps.println("<null/>");
        } else {
            ps.print(getIndent(indent));
            ps.print("<" + type + ">");
            if (o instanceof Class) {
                // We need special handling of Class, or org.pkg.ClassName will be printed as "class org.pkg.ClassName"
                ps.print(((Class<?>) o).getName());
            } else {
                ps.print(o.toString());                
            }
            ps.println("</" + type + ">");
        }
    }

    private static void printValue(Object o, int indent, PrintStream ps) {
        if (o instanceof Properties) {
            encodeProperties(o, indent, ps);
        } else if (o instanceof Map) {
            encodeMap(o, indent, ps);
        } else if (o instanceof List) {
            encodeList(o, indent, ps);
        } else if (o instanceof Date) {
            ps.print(getIndent(indent));
            ps.println("<object class=\"java.util.Date\">");
            ps.print(getIndent(indent + 1));
            ps.print("<long>");
            ps.print(((Date) o).getTime());
            ps.println("</long>");
            ps.print(getIndent(indent));
            ps.println("</object>");                        
        } else {
            encodePrimitive(o, indent, ps);
        }
    }

    private static String getType(Object o) {
        if (o == null) {
            return null;
        }
        if (o instanceof String) {
            return "string";
        }
        if (o instanceof Integer) {
            return "int";
        }
        if (o instanceof Boolean) {
            return "boolean";
        }
        if (o instanceof Long) {
            return "long";
        }
        if (o instanceof Class) {
            return "class";
        }
        if (o instanceof Float) {
            return "float";
        }
        if (o instanceof Double) {
            return "double";
        }
        if ((o instanceof Properties) || (o instanceof Date) || (o instanceof Map) || (o instanceof List)) {
            return "object";
        }
        throw new IllegalArgumentException("encodeSimpleMapFast does not handle type: " + o.getClass().getName());
    }

    /** Encodes simple Properties<String,String> as XMLEncoder
     * example output:
     * <object class="java.util.Properties">
     *  <void method="put">
     *   <string>nextCertSignKey</string>
     *   <string>encryptKey</string>
     *  </void>
     *  <void method="put">
     *   <string>certSignKey</string>
     *   <string>signKey</string>
     *  </void>
     *  <void method="put">
     *   <string>crlSignKey</string>
     *   <string>signKey</string>
     *  </void>
     *  <void method="put">
     *   <string>defaultKey</string>
     *   <string>encryptKey</string>
     *  </void>
     * </object>
     *
     * @param prop the properties to XML Encode
     * @param ps PrintStream where XML will be printed
     */
    private static void encodeProperties(final Object prop, int indent, PrintStream ps) {
        if (prop instanceof Properties) {
            final Properties p = (Properties) prop;
            final Set<Object> s = p.keySet();
            ps.print(getIndent(indent));
            ps.println("<object class=\"" + prop.getClass().getName() + "\">");
            for (Object key : s) {
                ps.print(getIndent(indent + 1));
                ps.println("<void method=\"put\">");
                ps.print(getIndent(indent + 2));
                ps.println("<string>" + key + "</string>");
                final Object o = p.get(key);
                encodePrimitive(o, indent + 2, ps);
                ps.print(getIndent(indent + 1));
                ps.println("</void>");
            }
            ps.print(getIndent(indent));
            ps.println("</object>");                        
            return;
        }
        throw new IllegalArgumentException("Input to encodeProperties must be a simple <String,Object> properties: " + prop.getClass().getName());
    }

    /** Encodes simple List<String> as XMLEncoder
     * example output:
     * <object class="java.util.Properties">
     *  <void method="put">
     *   <string>nextCertSignKey</string>
     *   <string>encryptKey</string>
     *  </void>
     *  <void method="put">
     *   <string>certSignKey</string>
     *   <string>signKey</string>
     *  </void>
     *  <void method="put">
     *   <string>crlSignKey</string>
     *   <string>signKey</string>
     *  </void>
     *  <void method="put">
     *   <string>defaultKey</string>
     *   <string>encryptKey</string>
     *  </void>
     * </object>
     *
     * @param prop the List to XML Encode
     * @param ps PrintStream where XML will be printed
     */
    private static void encodeList(final Object o, int indent, PrintStream ps) {
        if (o instanceof List) {
            @SuppressWarnings({ "rawtypes" })
            final List l = (List) o;
            ps.print(getIndent(indent));
            ps.println("<object class=\"" + o.getClass().getName() + "\">");
            for (Object item : l) {
                ps.print(getIndent(indent + 1));
                ps.println("<void method=\"add\">");
                ps.print(getIndent(indent + 2));
                ps.println("<string>" + item + "</string>");
                ps.print(getIndent(indent + 1));
                ps.println("</void>");
            }
            ps.print(getIndent(indent));
            ps.println("</object>");                        
            return;
        }
        throw new IllegalArgumentException("Input to encodeList must be a simple List<String> list: " + o.getClass().getName());
    }

    /** Encodes simple Map<Object,Object> as XMLEncoder,.
     * Writes output to the provided PrintStream
     * example output:
     * <object class="java.util.LinkedHashMap">
     *  <void method="put">
     *   <string>nextCertSignKey</string>
     *   <string>encryptKey</string>
     *  </void>
     *  <void method="put">
     *   <string>akey</string>
     *   <string>avalue</string>
     *  </void>
     *  <void method="put">
     *   <string>bkey</string>
     *   <string>bvalue</string>
     *  </void>
     * </object>
     *
     * @param map the Map to XML Encode
     * @param ps PrintStream where XML will be printed
     */
    private static void encodeMap(final Object o, int indent, final PrintStream ps) {
        if (o instanceof Map) {
            @SuppressWarnings("unchecked")
            Map<Object, Object> map = (Map<Object, Object>) o;
            final Set<Object> s = map.keySet();
            ps.print(getIndent(indent));
            ps.println("<object class=\"" + map.getClass().getName() + "\">");
            for (Object key : s) {
                ps.print(getIndent(indent + 1));
                ps.println("<void method=\"put\">");
                ps.print(getIndent(indent + 2));
                ps.println("<string>" + key + "</string>");
                final Object val = map.get(key);
                printObject(val, indent + 2, ps);
                ps.print(getIndent(indent + 1));
                ps.println("</void>");
            }
            ps.print(getIndent(indent));
            ps.println("</object>");                        
            return;
        }
        throw new IllegalArgumentException("Input to encodeMap must be a simple Map<String, Object> list: " + o.getClass().getName());
    }


}
