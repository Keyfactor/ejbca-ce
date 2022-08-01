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

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.ClassUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.PKIDisclosureStatement;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;

import static java.util.Objects.nonNull;


/**
 * <p>Implements a subset of XMLDecoder in a secure way, without allowing arbitrary classes to be loaded or methods to be invoked.
 * Only primitive types, Strings, Lists and Maps are allowed.</p>
 *
 * <p>Currently unimplemented parts of the XML format:</p>
 * <ul>
 * <li>Non-Unicode characters in strings/chars</li>
 * <li>Uncommon or custom collection types</li>
 * </ul>
 *
 * <p>Differences from XMLDecoder:</p>
 * <ul>
 * <li>The SecureXMLDecoder throws an IOException on error instead of using the ExceptionListener.</li>
 * <li>Throws EOFException instead of ArrayIndexOutOfBoundsException at end of file</li>
 * </ul>
 */
public class SecureXMLDecoder implements AutoCloseable {

    private static final Logger log = Logger.getLogger(SecureXMLDecoder.class);

    private final InputStream is;
    private final boolean ignoreErrors;
    private final XmlPullParser parser;
    private boolean seenHeader = false;
    private boolean closed = false;
    /**
     * Map of id-to-object. Used to handle id references (idref) in the XML
     */
    private Map<String, Object> objectIdMap = new HashMap<>();

    public static final class NoValueException extends IOException {
        private static final long serialVersionUID = 1L;
    }

    /**
     * Creates a SecureXMLDecoder. Errors when calling readObject() will generate an IOException.
     *
     * @param is input stream.
     */
    public SecureXMLDecoder(final InputStream is) {
        this(is, false);
    }

    /**
     * @param is           Input stream
     * @param ignoreErrors If recoverable errors should be ignored.
     */
    public SecureXMLDecoder(final InputStream is, final boolean ignoreErrors) {
        this.is = is;
        this.ignoreErrors = ignoreErrors;
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
        objectIdMap = null;
        try {
            is.close();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Reads the next object from the stream, and returns it.
     * <p>
     * Note: This implementation does not throw ArrayIndexOutOfBoundsException on EOF, but returns null instead.
     *
     * @return The deserialized object, or null when there are no more objects.
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
            switch (parser.getEventType()) {
                case XmlPullParser.START_TAG:
                    return readValue();
                case XmlPullParser.END_TAG:
                    if (parser.next() != XmlPullParser.END_DOCUMENT) {
                        throw new IOException("Data after end of root element");
                    }
                    throw new EOFException("Reached end of XML document");
                case XmlPullParser.END_DOCUMENT:
                    throw new EOFException("Reached end of XML document");
                default:
                    throw new IllegalStateException("Got invalid/unsupported XML event type");
            }
        } catch (XmlPullParserException e) {
            throw new IOException(e);
        }
    }

    /**
     * Reads the &lt;java version="xx" class="xx"&gt; header
     */
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

    /**
     * Reads an object, array or (boxed) elementary type value.
     */
    private Object readValue() throws XmlPullParserException, IOException {
        return readValue(true);
    }

    /**
     * Reads an object, array or (boxed) elementary type value.
     *
     * @throws XmlPullParserException On low level XML parse errors
     * @throws IOException            On not valid XMLEncoder XML
     * @throws NoValueException       If no value could be parsed
     */
    private Object readValue(boolean disallowTextAfterElement) throws XmlPullParserException, IOException {
        final String tag = parser.getName();
        final String id = parser.getAttributeValue(null, "id");
        final String idRef = parser.getAttributeValue(null, "idref");
        if (idRef != null) {
            // This is a reference to an existing object, so there is no value in the XML
            parser.nextTag();
            expectEndTag(tag);
            if (disallowTextAfterElement) {
                parser.nextTag();
            }
            if (!objectIdMap.containsKey(idRef)) {
                final String msg = errorMessage("Referenced object in 'idref' not found: '" + idRef + "'");
                throwOrLog(msg, null);
                throw new NoValueException();
            }
            return objectIdMap.get(idRef);
        }
        final Object value;
        // Read the element contents depending on the type
        switch (tag) {
            case "string":
                // Unescape XML special characters
                value = StringEscapeUtils.unescapeXml(readString());
                break;
            case "boolean":
                value = Boolean.valueOf(readText());
                break;
            case "char":
                final String charCode = parser.getAttributeValue(null, "code");
                final String charValue = readText();
                if (charCode != null) {
                    value = (char) Integer.parseInt(charCode.substring(1));
                } else if (charValue.length() == 1) {
                    value = charValue.charAt(0);
                } else {
                    throw new IOException(errorMessage("Invalid length of <char> value, and no \"code\" attribute present."));
                }
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
            case "class":
                try {
                    // Only allow classes from our own hierarchy
                    final String className = readText();
                    if (!(className.startsWith("org.ejbca.") || className.startsWith("org.cesecore.") || className.startsWith("org.signserver."))) {
                        throw new IOException("Unauthorized class was decoded from XML: " + className);
                    }
                    value = Class.forName(className);
                } catch (ClassNotFoundException e) {
                    throw new IOException("Unknown class was sent with import.", e);
                }
                break;
            case "object":
                final String className = parser.getAttributeValue(null, "class");
                String method = parser.getAttributeValue(null, "method"); // used from java.util.Collections
                if (parser.getAttributeCount() == 0) {
                    // Special handling for broken encoding of PKIDisclosureStatement in EJBCA 7.4.0-7.4.2
                    final PKIDisclosureStatement pkids = readBrokenPkiDisclosureStatement();
                    if (pkids != null) { // fall back to code below if it's not a PKIDisclosureStatement
                        value = pkids;
                        break;
                    }
                }
                parser.nextTag();

                // If we need to support a lot of more classes here (or custom classes), we could instead load the
                // classes dynamically with Class.forName (after checking the name whitelist). Then we could check
                // which interface the class implements (Collection or Map) and use the appropriate parse method.
                switch (className) {
                    case "java.util.ArrayList": {
                        List<Object> list;
                        if (isIntValue()) {
                            int capacity = Integer.parseInt(readText());
                            list = new ArrayList<>(capacity);
                            parser.nextTag();
                        } else {
                            list = new ArrayList<>();
                        }
                        value = parseCollection(list);
                        break;
                    }
                    case "java.util.LinkedList":
                        value = parseCollection(new LinkedList<>());
                        break;
                    case "java.util.HashSet":
                        value = parseCollection(new HashSet<>());
                        break;
                    case "java.util.LinkedHashSet":
                        value = parseCollection(new LinkedHashSet<>());
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
                    case "org.cesecore.util.Base64PutHashMap":
                    case "org.ejbca.util.Base64PutHashMap": // old class name, lets upgrade to new one
                        value = parseMap(new Base64PutHashMap());
                        break;
                    case "org.cesecore.util.Base64GetHashMap":
                    case "org.ejbca.util.Base64GetHashMap": // old class name, lets upgrade to new one
                        @SuppressWarnings("unchecked")
                        Map<Object, Object> b64getmap = new Base64GetHashMap();
                        value = parseMap(b64getmap);
                        break;
                    case "org.cesecore.certificates.certificateprofile.CertificatePolicy":
                    case "org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy":
                        value = parseObject(new CertificatePolicy());
                        break;
                    case "org.cesecore.certificates.certificateprofile.PKIDisclosureStatement":
                        value = parseObject(new PKIDisclosureStatement());
                        break;
                    case "org.cesecore.certificates.endentity.EndEntityInformation":
                        // End Entity Type is not exported correctly by XMLEncoder,
                        // so we can't recover that property
                        value = parseObject(new EndEntityInformation());
                        break;
                    case "":
                    case "org.cesecore.certificates.endentity.ExtendedInformation":
                        value = parseObject(new ExtendedInformation());
                        break;
                    case "org.cesecore.keybind.InternalKeyBindingTrustEntry":
                        value = parseObject(new InternalKeyBindingTrustEntry());
                        break;
                    case "org.ejbca.core.model.ra.raadmin.UserNotification":
                    case "org.ejbca.core.model.ra.UserDataVO":
                    case "org.ejbca.core.model.ra.ExtendedInformation": // Used by UserDataVO
                    case "org.ejbca.core.protocol.acme.logic.AcmeAuthorizationImpl":
                    case "org.ejbca.core.protocol.acme.logic.AcmeChallengeImpl":
                    case "org.ejbca.core.protocol.acme.logic.AcmeIdentifierImpl":
                    case "org.ejbca.core.protocol.acme.logic.AcmeOrderImpl":
                    case "org.ejbca.core.protocol.acme.storage.AcmeAccountImpl":
                    case "org.signserver.common.CertificateMatchingRule":
                    case "org.signserver.common.AuthorizedClient":
                    case "org.cesecore.util.SecureXMLDecoderTest$MockObject":
                    case "org.cesecore.certificates.endentity.PSD2RoleOfPSPStatement":
                        try {
                            // EJBCA, SignServer and test classes, so not available in CESeCore.
                            // In the long run we should make the whitelisted class names configurable, e.g. by subclassing (ECA-4916)
                            value = parseObject(Class.forName(className).getConstructor().newInstance());
                        } catch (IllegalArgumentException | ReflectiveOperationException | SecurityException e) {
                            throw new IOException(errorMessage("Deserialization of class '" + className + "' failed: " + e.getMessage()), e);
                        }
                        break;
                    case "java.util.Collections":
                        value = parseSpecialCollection(method);
                        method = null; // value has been used, don't report error
                        break;
                    case "org.apache.commons.lang3.tuple.MutablePair":
                        value = parseMutablePair(parser);
                        break;
                    case "java.util.Date":
                        long dateLongValue = (long) readValue();
                        value = new Date(dateLongValue);
                        break;
                    case "java.util.Properties":
                        // Default values (the argument to the constructor) aren't preserved during serialization by XMLEncoder
                        value = parseMap(new Properties());
                        break;
                    case "java.lang.Enum": {
                        parser.getName();
                        final String enumType = readString();
                        parser.nextTag();
                        parser.getName();
                        final String valueName = readString();
                        value = toEnumValue(enumType, valueName);
                        method = null;
                        parser.nextTag();
                        break;
                    }
                    default:
                        // Special handling for enum serialized in Java 6
                        if ("valueOf".equals(method) && !"java.lang.Enum".equals(className)) {
                            final String nested = parser.getName();
                            if (!"string".equals(nested)) {
                                throw new IOException("Unexpected tag '" + nested + "'. Maybe not an enum?");
                            }
                            final String valueName = readString();
                            parser.nextTag();
                            value = toEnumValue(className, valueName);
                            method = null;
                        } else {
                            /*
                             * We need to add support for plain Java objects that don't need special treatment. In EJBCA we need at least
                             * org.cesecore.certificates.certificateprofile.CertificatePolicy and org.cesecore.keybind.InternalKeyBindingTrustEntry.
                             * For these classes we need to construct an instance and then call the getters and setters. See ECA-4916.
                             */
                            throw new IOException(errorMessage("Deserialization of class \"" + className + "\" not supported or not allowed."));
                        }
                } // end of inner switch
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
        storeObjectById(id, value);

        expectEndTag(tag);
        if (disallowTextAfterElement) {
            parser.nextTag();
        }
        return value;
    }

    /**
     * Tries to read a corrupted encoding of PKIDisclosureStatement from EJBCA 7.4.0 - 7.4.2 (see ECA-9548).
     * @return PKIDisclosureStatement, or null if it is something else.
     * @throws XmlPullParserException On low level XML parse errors
     * @throws IOException On not valid XMLEncoder XML
     */
    private PKIDisclosureStatement readBrokenPkiDisclosureStatement() throws XmlPullParserException, IOException {
        final String encodedValue = readString();
        if (!encodedValue.startsWith("{")) {
            return null;
        }
        final String[] splitted = encodedValue.split("\\}", 2);
        final String language = splitted[0].substring(1);
        final String url = splitted[1];
        return new PKIDisclosureStatement(url, language);
    }

    /**
     * Locates the gives enum value and returns it. Performs a checks that the class is
     * allowed before loading it.
     *
     * @param enumType Fully qualified name of enum class.
     * @param valueName Name of enum value.
     * @return Enum value as a Java object
     * @throws IOException On parse error, or if the class if not allowed.
     */
    @SuppressWarnings("unchecked")
    private Object toEnumValue(final String enumType, final String valueName) throws IOException {
        if (!enumType.startsWith("org.cesecore.") && !enumType.startsWith("org.ejbca.") && !enumType.startsWith("org.signserver.")) {
            throw new IOException(errorMessage("Instantation of enum type \"" + enumType + "\" not allowed"));
        }
        if (valueName.endsWith("INSTANCE")) {
            throw new IOException(errorMessage("Not allowed to use singleton \"" + valueName + "\" from enum type \"" + enumType + "\""));
        }
        try {
            return Enum.valueOf(Class.forName(enumType).asSubclass(Enum.class), valueName);
        } catch (ClassNotFoundException e) {
            throw new IOException(errorMessage("Enum class \"" + enumType + "\" was not found"), e);
        } catch (IllegalArgumentException e) {
            throw new IOException(errorMessage("Invalid enum value \"" + valueName + "\" for enum type \"" + enumType + "\""), e);
        }
    }

    private void storeObjectById(final String id, final Object value) {
        if (id != null && value != null) {
            // The object (or getter) has an ID, so it can be referenced again later
            if (log.isTraceEnabled()) {
                log.trace("Binding id '" + id + "' to " + value);
            }
            objectIdMap.put(id, value);
        }
    }

    private void expectEndTag(final String tag) throws XmlPullParserException, IOException {
        if (parser.getEventType() != XmlPullParser.END_TAG ||
                !tag.equals(parser.getName())) {
            final String msg = "Cannot parse XML. Expected end tag of " + tag;
            log.info(errorMessage(msg + ", but got type " + parser.getEventType() + ", name " + parser.getName()));
            throw new IOException(errorMessage(msg));
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

    /**
     * Reads a string, possibly containing &lt;char code="#xxx"/&gt; escapes.
     *
     * @return String, never null.
     */
    private String readString() throws XmlPullParserException, IOException {
        final StringBuilder sb = new StringBuilder();
        while (true) {
            int eventType = parser.next();
            if (eventType == XmlPullParser.TEXT) {
                sb.append(parser.getText());
            } else if (eventType == XmlPullParser.START_TAG) {
                Object charvalue = readValue(false);
                if (!(charvalue instanceof Character)) {
                    throw new IOException(errorMessage("Unexpected object element inside java string element"));
                }
                sb.append((char) charvalue);
            } else if (eventType == XmlPullParser.END_TAG) {
                break;
            } else {
                throw new IOException(errorMessage("Unexpected XML token in Java string element"));
            }
        }
        return sb.toString();
    }

    /**
     * Checks if the next item is an <int> start tag
     */
    private boolean isIntValue() throws XmlPullParserException {
        return parser.getEventType() == XmlPullParser.START_TAG && "int".equals(parser.getName());
    }

    /**
     * Reads an &lt;array class="xx" length="xx"&gt; element
     */
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
                case "char":
                    elemClass = Character.TYPE;
                    break;
                case "byte":
                    elemClass = Byte.TYPE;
                    break;
                case "short":
                    elemClass = Short.TYPE;
                    break;
                case "int":
                    elemClass = Integer.TYPE;
                    break;
                case "long":
                    elemClass = Long.TYPE;
                    break;
                case "float":
                    elemClass = Float.TYPE;
                    break;
                case "double":
                    elemClass = Double.TYPE;
                    break;
                case "boolean":
                    elemClass = Boolean.TYPE;
                    break;
                default:
                    // Note that we do not instantiate or initialize the class, so this is OK security-wise
                    elemClass = Class.forName(className, false, getClass().getClassLoader());
            }

            final int length = Integer.parseInt(lengthStr);
            final Object arr = Array.newInstance(elemClass, length);

            // Read the array elements
            while (true) {
                // Read <void index="xx">
                if (parser.getEventType() == XmlPullParser.END_TAG) {
                    break;
                }

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
            throw new IOException(errorMessage("Element <void> is missing a \"method\" attribute."));
        }
        parser.nextTag();
        return method;
    }

    /**
     * Parses data for Collection objects, such as ArrayList, but also HashSet etc.
     */
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

    /**
     * Parses data for Map objects.
     *
     * @param map The map to put the parsed data in.
     * @return the parsed map as an object.
     */
    private Object parseMap(final Map<Object, Object> map) throws XmlPullParserException, IOException {
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
            case "emptySet":
                return new HashSet<>();
            case "emptyList":
                return new ArrayList<>();
            case "emptyMap":
                return new HashMap<>();
            case "unmodifiableList":
                final Object list = readValue();
                if (!(list instanceof List)) {
                    throw new IOException(errorMessage("Expected List argument to unmodifiableList"));
                }
                return list;
            case "singletonList":
                return Collections.singletonList(readValue());
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

            default:
                throw new IOException("Method \"" + method + "\" not supported or not allowed on java.util.Collections.");
        }
    }

    // Only supports String value
    private Object parseMutablePair(final XmlPullParser parser) throws XmlPullParserException, IOException {
        MutablePair pair = new MutablePair();
        final String clazz = parser.getAttributeValue(null, "class");
        final String method = parser.getAttributeValue(null, "method");
        if(nonNull(clazz) && nonNull(method) && clazz.equals("org.apache.commons.lang3.tuple.MutablePair") && method.equals("getField")) {
            parser.nextTag();
            parser.next();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            pair.setLeft(parser.nextText());
            parser.next();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            parser.next();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
            pair.setRight(parser.nextText());
            parser.nextTag();
            parser.nextTag();
            parser.nextTag();
        }
        return pair;
    }

    /**
     * Parses an arbitrary object. Note that this method will allow any property to be set.
     */
    private Object parseObject(final Object obj) throws XmlPullParserException, IOException {
        while (true) {
            if (parser.getEventType() == XmlPullParser.END_TAG) {
                break;
            }

            if (parser.getEventType() != XmlPullParser.START_TAG || !"void".equals(parser.getName())) {
                throw new IOException(errorMessage("Expected <void> start tag."));
            }

            final String id = parser.getAttributeValue(null, "id");
            final String property = parser.getAttributeValue(null, "property");
            if (property == null) {
                throw new IOException(errorMessage("Element <void> is missing a \"property\" attribute."));
            }
            parser.nextTag();

            final String methodBase = property.substring(0, 1).toUpperCase(Locale.ROOT) + property.substring(1);
            final String setterName = "set" + methodBase;

            if (parser.getEventType() != XmlPullParser.END_TAG) {
                try {
                    final Object value;
                    if ("void".equals(parser.getName())) {
                        // Call the getter to see if it is a map that should be filled with entries
                        value = fillInExistingMap(obj, methodBase);
                    } else {
                        value = readValue(true);
                        try {
                            // invokeMethod handles mapping to primitive types and superclasses also, if the parameters don't match exactly
                            MethodUtils.invokeMethod(obj, setterName, value);
                        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | SecurityException e) {
                            throw new IOException(errorMessage("Method \"" + setterName + "\" could not be called."), e);
                        } catch (NoSuchMethodException e) {
                            throwOrLog(errorMessage("No setter method \"" + setterName + "\" was found with parameter type " + ClassUtils.getShortClassName(value, "null") + " in object " + obj), e);
                        }
                    }
                    storeObjectById(id, value);
                } catch (NoValueException e) {
                    // Ignore
                }
            } else {
                // Empty = call getter and store by ID
                try {
                    if (!methodExists(obj.getClass(), setterName)) {
                        // Disallow getting non-properties as a safety measure
                        throwOrLog(errorMessage("Property \"" + property + "\" has no setter and may not be used as a property"), null);
                    } else {
                        Object value;
                        try {
                            value = MethodUtils.invokeMethod(obj, "get" + methodBase, ArrayUtils.EMPTY_OBJECT_ARRAY);
                        } catch (NoSuchMethodException e) {
                            value = MethodUtils.invokeMethod(obj, "is" + methodBase, ArrayUtils.EMPTY_OBJECT_ARRAY);
                        }
                        storeObjectById(id, value);
                    }
                } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | SecurityException e) {
                    throw new IOException(errorMessage("Getter for " + property + " could not be called."), e);
                } catch (NoSuchMethodException e) {
                    throwOrLog(errorMessage("Could not find a getter for " + property), e);
                }
            }

            expectEndTag("void");
            parser.nextTag();
        }
        return obj;
    }

    /** Fills in an existing map in a property with more entries from the XML. */
    @SuppressWarnings("unchecked")
    private Object fillInExistingMap(final Object obj, final String methodBase) throws IOException, XmlPullParserException {
        final String getterName = "get" + methodBase;
        try {
            final Object propertyValue = MethodUtils.invokeMethod(obj, getterName);
            if (!(propertyValue instanceof Map<?,?>)) {
                throw new IOException(errorMessage("Unhandled type returned from getter \"" + getterName + "\": " + (propertyValue != null ? propertyValue.getClass().getSimpleName() : null)));
            }
            parseMap((Map<Object,Object>) propertyValue);
            return propertyValue;
        } catch (IllegalAccessException | IllegalArgumentException | InvocationTargetException | SecurityException e) {
            throw new IOException(errorMessage("Method \"" + getterName + "\" could not be called."), e);
        } catch (NoSuchMethodException e) {
            throwOrLog(errorMessage("No getter method \"" + getterName + "\" was found"), e);
            return null;
        }
    }

    private boolean methodExists(final Class<?> klass, final String methodName) {
        for (final Method method : klass.getMethods()) {
            if (methodName.equals(method.getName())) {
                return true;
            }
        }
        return false;
    }

    private void throwOrLog(final String message, final Throwable cause) throws IOException {
        if (ignoreErrors) {
            // When ignoreErrors is true, errors are expected, so just log a debug level
            log.debug(message, cause);
        } else {
            throw new IOException(message, cause);
        }
    }

    private String errorMessage(final String msg) {
        return msg + " (line: " + parser.getLineNumber() + ", column: " + parser.getColumnNumber() + ")";
    }
}
