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
package org.cesecore.audit.log.dto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit test for SecurityEventProperties.
 *
 */
public class SecurityEventPropertiesUnitTest {
    
    private static final ByteArrayOutputStream outStream = new ByteArrayOutputStream();
    private static final PrintStream originalSystemOut = System.out;
    private static final InputStream originalSystemIn = System.in;
    
    @BeforeClass
    public static void beforeClass() {
        System.setProperty("log4j1.compatibility", "true");
        System.setOut(new PrintStream(outStream));
    }
    
    @After
    public void tearDown() {
        // Write log/console outputs to System.err
        System.err.println(outStream.toString());
        outStream.reset();
        // Restore original System.in
        System.setIn(originalSystemIn);
        // Reset expectations
    }

    @AfterClass
    public static void afterClass() {
        // Restore original System.out
        System.setOut(originalSystemOut);
    }
    
    @Test
    public void shouldMapCertSignKey() {
        // given
        final String certSignKey = "MyCertSignKey";
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withCertSignKey(certSignKey)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("certSignKey was not mapped.", certSignKey, resultMap.get(SecurityEventProperties.CERT_SIGN_KEY));
    }

    @Test
    public void shouldMapCrlSignKey() {
        // given
        final String crlSignKey = "MyCrlSignKey";
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withCrlSignKey(crlSignKey)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("crlSignKey was not mapped.", crlSignKey, resultMap.get(SecurityEventProperties.CRL_SIGN_KEY));
    }

    @Test
    public void shouldMapError() {
        // given
        final String error = "MyError";
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withError(error)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("error was not mapped.", error, resultMap.get(SecurityEventProperties.ERROR));
    }

    @Test
    public void shouldMapMsg() {
        // given
        final String msg = "MyMessage";
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withMsg(msg)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("msg was not mapped.", msg, resultMap.get(SecurityEventProperties.MSG));
    }

    @Test
    public void shouldMapOldproperties() {
        // given
        final Properties oldproperties = new Properties();
        oldproperties.put("MyOldProp", "MyOldValue");
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withOldproperties(oldproperties)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("oldproperties was not mapped.", oldproperties, resultMap.get(SecurityEventProperties.OLD_PROPERTIES));
    }

    @Test
    public void shouldMapOldsequence() {
        // given
        final String oldsequence = "MyOldsequence";
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withOldsequence(oldsequence)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("oldsequence was not mapped.", oldsequence, resultMap.get(SecurityEventProperties.OLD_SEQUENCE));
    }

    @Test
    public void shouldMapProperties() {
        // given
        final Properties properties = new Properties();
        properties.put("MyProp", "MyValue");
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withProperties(properties)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("properties was not mapped.", properties, resultMap.get(SecurityEventProperties.PROPERTIES));
    }

    @Test
    public void shouldMapSequence() {
        // given
        final String sequence = "MySequence";
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withSequence(sequence)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("sequence was not mapped.", sequence, resultMap.get(SecurityEventProperties.SEQUENCE));
    }

    @Test
    public void shouldMapCustomMap() {
        // given
        final String customKey = "customKey";
        final String customValue = "customValue";
        final Map<Object, Object> customMap = new HashMap<>();
        customMap.put(customKey, customValue);
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withCustomMap(customMap)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertEquals("customMap was not mapped.", customValue, resultMap.get(customKey));
    }

    @Test
    public void shouldMapCustomMapWithNullObject() {
        // given
        final String customKey = "customKey";
        final Map<Object, Object> customMap = new HashMap<>();
        customMap.put(customKey, null);
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withCustomMap(customMap)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        assertNull("customMap was not mapped.", resultMap.get(customKey));
    }

    @Test
    public void shouldWarnAboutNullKeyByCustomMap() {
        // given
        final String customValue = "customValue";
        final Map<Object, Object> customMap = new HashMap<>();
        customMap.put(null, customValue);
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withCustomMap(customMap)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 0, resultMap.keySet().size());
        
        final String consoleOutput = outStream.toString();
        assertTrue("Event log is missing. It was " + consoleOutput, consoleOutput.contains("WARN"));
        assertTrue("Event log is missing. It was " + consoleOutput, consoleOutput.contains("Got an entry with null key, excluding from the result map."));

    }

    @Test
    public void shouldWarnAboutStandalonePropertyOverrideByCustomMap() {
        // given
        final String msg = "original msg";
        final String customKey = "msg";
        final String customValue = "msg replacement";
        final Map<Object, Object> customMap = new HashMap<>();
        customMap.put(customKey, customValue);
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withMsg(msg)
                .withCustomMap(customMap)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 1, resultMap.keySet().size());
        
        final String consoleOutput = outStream.toString();

        assertTrue("Event log is missing. It was " + consoleOutput, consoleOutput.contains("WARN"));
        assertTrue("Event log is missing. It was " + consoleOutput, consoleOutput.contains("The standalone property [msg] was overridden by property in custom map."));
        
        assertEquals("msg was not mapped from customMap.", customValue, resultMap.get(SecurityEventProperties.MSG));
    }

    @Test
    public void shouldMapAllAttributes() {
        // given
        final String certSignKey = "MyCertSignKey";
        final String crlSignKey = "MyCrlSignKey";
        final String error = "MyError";
        final String msg = "MyMessage";
        final Properties oldproperties = new Properties();
        oldproperties.put("MyOldProp", "MyOldValue");
        final String oldsequence = "MyOldsequence";
        final Properties properties = new Properties();
        properties.put("MyProp", "MyValue");
        final String sequence = "MySequence";
        final String customKey = "customKey";
        final String customValue = "customValue";
        final Map<Object, Object> customMap = new HashMap<>();
        customMap.put(customKey, customValue);
        final SecurityEventProperties securityEventProperties = SecurityEventProperties.builder()
                .withCertSignKey(certSignKey)
                .withCrlSignKey(crlSignKey)
                .withError(error)
                .withMsg(msg)
                .withOldproperties(oldproperties)
                .withOldsequence(oldsequence)
                .withProperties(properties)
                .withSequence(sequence)
                .withCustomMap(customMap)
                .build();
        // when
        final Map<String, Object> resultMap = securityEventProperties.toMap();
        // then
        assertEquals("Resulting map has unexpected number of elements.", 9, resultMap.keySet().size());
        assertEquals("certSignKey was not mapped.", certSignKey, resultMap.get(SecurityEventProperties.CERT_SIGN_KEY));
        assertEquals("crlSignKey was not mapped.", crlSignKey, resultMap.get(SecurityEventProperties.CRL_SIGN_KEY));
        assertEquals("error was not mapped.", error, resultMap.get(SecurityEventProperties.ERROR));
        assertEquals("msg was not mapped.", msg, resultMap.get(SecurityEventProperties.MSG));
        assertEquals("oldproperties was not mapped.", oldproperties, resultMap.get(SecurityEventProperties.OLD_PROPERTIES));
        assertEquals("oldsequence was not mapped.", oldsequence, resultMap.get(SecurityEventProperties.OLD_SEQUENCE));
        assertEquals("properties was not mapped.", properties, resultMap.get(SecurityEventProperties.PROPERTIES));
        assertEquals("sequence was not mapped.", sequence, resultMap.get(SecurityEventProperties.SEQUENCE));
        assertEquals("customMap was not mapped.", customValue, resultMap.get(customKey));
    }

}
