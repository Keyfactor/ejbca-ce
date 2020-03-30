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
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.log4j.Logger;

/**
 * This is a helper classed that handles the serialization to and deserialization from XML.
 * 
 * Stored Strings in the input are stored as Base64 encoded strings.  
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
}
