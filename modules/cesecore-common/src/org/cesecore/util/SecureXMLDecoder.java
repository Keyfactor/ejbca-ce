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

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

/**
 * <p>Implements a subset of XMLDecoder in a secure way, without allowing arbitrary classes to be loaded or methods to be invoked.
 * Only primitive types, Strings, Lists and Maps are allowed.</p>
 * 
 * <p>Currently unimplemented parts of the XML format:</p>
 * <ul>
 * <li>Multiple references to the same object (id/idref)</li>
 * <li>Non-Unicode characters in strings/chars</li>
 * <li>Deserialization of Class objects</li>
 * <li>Uncommon or custom collection types</li>
 * </ul>
 * 
 * Also, unlike the XMLDecoder, the SecureXMLDecoder throws an IOException on error instead of using the ExceptionListener.
 * 
 * @version $Id$
 */
public class SecureXMLDecoder implements AutoCloseable {

    private final InputStream is;
    private final XmlPullParser parser;
    private boolean seenHeader = false;
    private boolean closed = false;
    
    public SecureXMLDecoder(final InputStream is) {
        this.is = is;
        try {
            final XmlPullParserFactory fact = XmlPullParserFactory.newInstance();
            fact.setFeature(XmlPullParser.FEATURE_PROCESS_DOCDECL, false); // can be abused to cause exponential memory usage
            fact.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false);
            fact.setFeature(XmlPullParser.FEATURE_VALIDATION, false);
            parser = fact.newPullParser();
            parser.setInput(is, "UTF-8");
        } catch (XmlPullParserException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void close() {
        closed = true;
        try {
            is.close();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
    
    /**
     * Reads the next object from the stream, and returns it.
     * 
     * @return The deserialized object.
     * @throws ArrayIndexOutOfBoundsException if there are no more objects. 
     * @throws IOException On parse error or IO error.
     */
    public Object readObject() throws IOException {
        if (closed) {
            throw new IllegalStateException("Decoder object is closed");
        }
        try {
            if (!seenHeader) {
                readHeader();
            }
            
            while (true) {
                switch (parser.getEventType()) {
                case XmlPullParser.START_TAG:
                    return readValue();
                case XmlPullParser.END_TAG:
                    if (parser.next() != XmlPullParser.END_DOCUMENT) {
                        throw new IOException("Data after end of root element");
                    }
                    // NOPMD: Fall through
                case XmlPullParser.END_DOCUMENT:
                    throw new ArrayIndexOutOfBoundsException("Reached end of XML document");
                }
            }
        } catch (XmlPullParserException e) {
            throw new IOException(e);
        }
    }
    
    /** Reads the &lt;java version="xx" class="xx"&gt; header */
    private void readHeader() throws XmlPullParserException, IOException {
        if (parser.getEventType() != XmlPullParser.START_DOCUMENT) {
            throw new IOException("Incorrect header of XML document");
        }
        if (parser.nextTag() != XmlPullParser.START_TAG) {
            throw new IOException("Expected a root element");
        }
        if (!"java".equals(parser.getName())) {
            throw new IOException("Expected <java> root element");
        }
        
        final String className = parser.getAttributeValue(null, "class");
        if (!"java.beans.XMLDecoder".equals(className)) {
            throw new IOException("Unsupported decoder class. Only \"java.beans.XMLDecoder\" is supported");
        }
        parser.nextTag();
        seenHeader = true;
    }
    
    /** Reads an object, array or (boxed) elementary type value. */
    private Object readValue() throws XmlPullParserException, IOException {
        final String tag = parser.getName();
        final Object value;
        // Read the element contents depending on the type
        switch (tag) {
        case "string":
            value = readText();
            break;
        case "boolean":
            value = Boolean.valueOf(readText());
            break;
        case "char":
            String charValue = readText();
            if (charValue.length() != 1) {
                throw new IOException(errorMessage("Invalid length of <char> value."));
            }
            value = charValue.charAt(0);
            break;
        case "byte":
            value = Byte.valueOf(readText());
            break;
        case "short":
            value = Short.valueOf(readText());
            break;
        case "int":
            value = Integer.valueOf(readText());
            break;
        case "long":
            value = Long.valueOf(readText());
            break;
        case "float":
            value = Float.valueOf(readText());
            break;
        case "double":
            value = Double.valueOf(readText());
            break;
        case "null":
            value = null;
            parser.nextTag();
            break;
        case "object":
            final String className = parser.getAttributeValue(null, "class");
            String method = parser.getAttributeValue(null, "method"); // used from java.util.Collections
            parser.nextTag();
            
            // If we need to support a lot of more classes here (or custom classes), we could instead load the
            // classes dynamically with Class.forName (after checking the name whitelist). Then we could check
            // which interface the class implements (Collection or Map) and use the appropriate parse method.
            switch (className) {
            case "java.util.ArrayList": {
                List<Object> list;
                if (isIntValue()) {
                    int capacity = Integer.valueOf(readText());
                    list = new ArrayList<>(capacity);
                    parser.nextTag();
                } else {
                    list = new ArrayList<>();
                }
                value = parseCollection(list);
                break; }
            case "java.util.LinkedList":
                value = parseCollection(new LinkedList<>());
                break;
            case "java.util.HashSet":
                value = parseCollection(new HashSet<>());
                break;
            case "java.util.TreeSet":
                value = parseCollection(new TreeSet<>());
                break;
            case "java.util.HashMap":
                value = parseMap(new HashMap<>());
                break;
            case "java.util.LinkedHashMap":
                value = parseMap(new LinkedHashMap<>());
                break;
            case "java.util.TreeMap":
                value = parseMap(new TreeMap<>());
                break;
            case "java.util.concurrent.ConcurrentHashMap":
                value = parseMap(new ConcurrentHashMap<>());
                break;
            case "java.util.Collections":
                value = parseSpecialCollection(method);
                method = null; // value has been used, don't report error
                break;
            default:
                throw new IOException(errorMessage("Deserialization of class \"" + className + "\" not supported or not allowed."));
            }
            
            if (method != null) {
                throw new IOException(errorMessage("Method attribute on object element of class \"" + className + "\" is not supported or not allowed."));
            }
            
            break;
        case "array":
            value = readArray();
            break;
        case "void":
            throw new IOException(errorMessage("Unexpected <void> tag. Probably there was an earlier parse error."));
        default:
            throw new IOException(errorMessage("Unsupported tag \"" + tag + "\"."));
        }
        
        expectEndTag(tag);
        parser.nextTag();
        return value;
    }
    
    private void expectEndTag(final String tag) throws XmlPullParserException, IOException {
        if (parser.getEventType() != XmlPullParser.END_TAG ||
                !tag.equals(parser.getName())) {
            throw new IOException(errorMessage("Expected end tag of " + tag + "."));
        }
    }
    
    /**
     * Reads the text content between two tags. Stops if there are nested tags, e.g.
     * <code>&lt;text&gt;blabla&lt;nested/&gt;blabla&lt;/text&gt;</code>,
     * so be careful if there could be nested tags.
     */
    private String readText() throws XmlPullParserException, IOException {
        final String text;
        if (parser.next() == XmlPullParser.TEXT) {
            text = parser.getText();
            parser.next();
        } else {
            text = "";
        }
        return text;
    }
    
    /** Checks if the next item is an <int> start tag */
    private boolean isIntValue() throws XmlPullParserException {
        return parser.getEventType() == XmlPullParser.START_TAG && "int".equals(parser.getName());
    }
    
    /** Reads an &lt;array class="xx" length="xx"&gt; element */
    private Object readArray() throws XmlPullParserException, IOException {
        final String className = parser.getAttributeValue(null, "class");
        final String lengthStr = parser.getAttributeValue(null, "length");
        parser.nextTag();
        try {
            if (className == null || lengthStr == null) {
                throw new IOException(errorMessage("Missing attributes on array"));
            }
            
            final Class<?> elemClass;
            switch (className) {
            case "char": elemClass = Character.TYPE; break;
            case "byte": elemClass = Byte.TYPE; break;
            case "short": elemClass = Short.TYPE; break;
            case "int": elemClass = Integer.TYPE; break;
            case "long": elemClass = Long.TYPE; break;
            case "float": elemClass = Float.TYPE; break;
            case "double": elemClass = Double.TYPE; break;
            case "boolean": elemClass = Boolean.TYPE; break;
            default:
                // Note that we do not instantiate the class, so this is OK security-wise
                elemClass = Class.forName(className);
            }
            
            final int length = Integer.parseInt(lengthStr);
            final Object arr = Array.newInstance(elemClass, length);
            
            // Read the array elements
            while (true) {
                // Read <void index="xx">
                if (parser.getEventType() == XmlPullParser.END_TAG) { break; }
                
                if (parser.getEventType() != XmlPullParser.START_TAG && !"void".equals(parser.getName())) {
                    throw new IOException(errorMessage("Expected <void> tag, not \"" + parser.getName() + "\"."));
                }
                
                final String indexStr = parser.getAttributeValue(null, "index");
                if (indexStr == null) {
                    throw new IOException(errorMessage("Missing index attribute on <void> tag."));
                }
                parser.nextTag();
                
                // Read value
                final int index = Integer.parseInt(indexStr);
                final Object value = readValue();
                Array.set(arr, index, value); // Must set using reflection since it could be an array of a primitive type
                
                expectEndTag("void");
                parser.nextTag();
            }
            
            return arr;
        } catch (ClassNotFoundException e) {
            throw new IOException(errorMessage("Failed to load array class \"" + className + "\". "));
        } catch (NumberFormatException e) {
            throw new IOException(errorMessage("Bad length or index \"" + lengthStr + "\"."));
        }
    }
    
    /**
     * Reads a method call start tag, e.g. &lt;void method="add"&gt;.
     * The data inside the void element is the method arguments.
     */
    private String readMethodCall() throws XmlPullParserException, IOException {
        if (parser.getEventType() != XmlPullParser.START_TAG || !"void".equals(parser.getName())) {
            throw new IOException(errorMessage("Expected <void> start tag."));
        }
        
        final String method = parser.getAttributeValue(null, "method");
        if (method == null) {
            throw new IOException(errorMessage("Element <void> is misisng a \"method\" attribute."));
        }
        parser.nextTag();
        return method;
    }
    
    /** Parses data for Collection objects, such as ArrayList, but also HashSet etc. */
    private Object parseCollection(final Collection<Object> col) throws XmlPullParserException, IOException {
        while (true) {
            if (parser.getEventType() == XmlPullParser.END_TAG) {
                break;
            }
            
            final String method = readMethodCall();
            if (!method.equals("add")) {
                throw new IOException(errorMessage("Method \"" + method + "\" not supported or not allowed on Lists."));
            }
            
            final Object element = readValue();
            col.add(element);
            
            expectEndTag("void");
            parser.nextTag();
        }
        return col;
    }

    /** Parses data for Map objects */
    private Object parseMap(final Map<Object,Object> map) throws XmlPullParserException, IOException {
        while (true) {
            if (parser.getEventType() == XmlPullParser.END_TAG) {
                break;
            }
            
            final String method = readMethodCall();
            if (!method.equals("put")) {
                throw new IOException(errorMessage("Method \"" + method + "\" not supported or not allowed on Maps."));
            }
            
            final Object key = readValue();
            final Object value = readValue();
            map.put(key, value);
            
            expectEndTag("void");
            parser.nextTag();
        }
        return map;
    }
    
    private Object parseSpecialCollection(final String method) throws XmlPullParserException, IOException {
        // We do not allow unmodifiable collections to be deserialized (since that could be cause a Denial of Service if used in the wrong place),
        // instead we deserialize them as their modifiable counterpart.
        switch (method) {
        case "emptySet": return new HashSet<>();
        case "emptyList": return new ArrayList<>();
        case "emptyMap": return new HashMap<>();
        case "unmodifiableList":
            final Object list = readValue();
            if (!(list instanceof List)) {
                throw new IOException(errorMessage("Expected List argument to unmodifiableList"));
            }
            return list;
        case "unmodifiableSet":
            final Object set = readValue();
            if (!(set instanceof Set)) {
                throw new IOException(errorMessage("Expected Set argument to unmodifiableSet"));
            }
            return set;
        case "unmodifiableMap":
            final Object map = readValue();
            if (!(map instanceof Map)) {
                throw new IOException(errorMessage("Expected Map argument to unmodifiableMap"));
            }
            return map;
        case "unmodifiableCollection":
            final Object col = readValue();
            if (!(col instanceof Collection)) {
                throw new IOException(errorMessage("Expected Collection argument to unmodifiableCollection"));
            }
            return col;
        default: throw new IOException("Method \"" + method + "\" not supported or not allowed on java.util.Collections.");
        }
    }
    
    private String errorMessage(final String msg) {
        return msg + " (line: " + parser.getLineNumber() + ", column: " + parser.getColumnNumber() + ")";
    }
}
