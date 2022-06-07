/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ra;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;

import org.apache.commons.lang3.reflect.MethodUtils;
import org.apache.log4j.Logger;
import org.cesecore.util.SecureXMLDecoder;
import org.junit.Test;

/**
 * Tests of SecureXMLDecoder that cannot go into SecureXMLDecoderTest (which is part of CESeCore), because they use EJBCA classes.
 */
public class SecureXMLDecoderEjbcaUnitTest {

    private static final Logger log = Logger.getLogger(SecureXMLDecoderEjbcaUnitTest.class);

    private Object deserializeObject(final String xml) throws IOException {
        Object result = null;
        try (SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(xml.getBytes(StandardCharsets.US_ASCII)))) {
            result = decoder.readObject();
            decoder.readObject(); // Should trigger EOF
            fail("Too many objects in stream?");
        } catch (EOFException e) {
            // NOPMD: Expected, happens when we reach the end
        }
        return result;
    }

    @Test
    public void decodeExtendedInformationEmpty() throws IOException {
        log.trace(">decodeExtendedInformationEmpty");
        // Given
        final String xml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n" +
                "  <object class=\"org.ejbca.core.model.ra.ExtendedInformation\"/>\n" +
                "</java>";
        // When
        final Object result = deserializeObject(xml);
        // Then
        assertNotNull(result);
        assertEquals("org.ejbca.core.model.ra.ExtendedInformation", result.getClass().getName());
        log.trace("<decodeExtendedInformationEmpty");
    }

    @Test
    public void decodeExtendedInformationNormal() throws Exception {
        log.trace(">decodeExtendedInformationNormal");
        // Given
        final String xml =
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><java version=\"1.6.0.0\" class=\"java.beans.XMLDecoder\">\n" +
                "  <object class=\"org.ejbca.core.model.ra.ExtendedInformation\" id=\"ExtendedInformation0\">\n" +
                "    <void id=\"LinkedHashMap0\" property=\"data\">\n" +
                "      <void method=\"put\">\n" +
                "        <string>CERTIFICATESERIALNUMBER</string>\n" +
                "        <string>ew==</string>\n" +
                "      </void>\n" +
                "    </void>\n" +
                "    <void property=\"data\">\n" +
                "      <object idref=\"LinkedHashMap0\"/>\n" +
                "    </void>\n" +
                "  </object>\n" +
                "</java>";
        // When
        final Object result = deserializeObject(xml);
        // Then
        assertNotNull(result);
        assertEquals("org.ejbca.core.model.ra.ExtendedInformation", result.getClass().getName());
        final LinkedHashMap<?,?> rawData = (LinkedHashMap<?,?>) MethodUtils.invokeMethod(result, "getRawData");
        assertNotNull(rawData);
        assertEquals("ew==", rawData.get("CERTIFICATESERIALNUMBER"));
        log.trace("<decodeExtendedInformationNormal");
    }

}
