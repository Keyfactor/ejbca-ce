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
package org.cesecore.certificates.util;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.log4j.Logger;
import org.cesecore.util.FileTools;
import org.cesecore.util.StreamSizeLimitExceededException;
import org.junit.Test;

/**
 * Tests the FileTools class.
 * 
 * @version $Id$
 */
public class FileToolsTest {
    private static Logger log = Logger.getLogger(FileToolsTest.class);

    @Test
    public void testStreamCopyWithLimit() throws IOException, StreamSizeLimitExceededException {
        log.trace(">testStreamCopyWithLimit");

        final byte[] array4 = new byte[] { 1, 2, 3, 4 };
        final byte[] array5 = new byte[] { 1, 2, 3, 4, 5 };
        final byte[] array1MB = new byte[1024*1024];
        
        long ret;
        InputStream in;
        ByteArrayOutputStream out;
        
        // Test with size == limit. Should work
        in = new ByteArrayInputStream(array4);
        out = new ByteArrayOutputStream();
        ret = FileTools.streamCopyWithLimit(in, out, 4);
        assertEquals("Wrong return value", 4, ret);
        assertArrayEquals("Wrong data in output buffer", array4, out.toByteArray());
        
        // Test with size >= limit. Should not work
        in = new ByteArrayInputStream(array5);
        out = new ByteArrayOutputStream();
        try {
            FileTools.streamCopyWithLimit(in, out, 4);
            fail("Should throw when input is larger than the limit");
        } catch (StreamSizeLimitExceededException e) {
            // NOPMD expected
        }
        
        // Test with a large stream
        in = new ByteArrayInputStream(array1MB);
        out = new ByteArrayOutputStream();
        ret = FileTools.streamCopyWithLimit(in, out, 2*1024*1024);
        assertEquals("Wrong return value", array1MB.length, ret);
        assertEquals("Wrong number of bytes written to output stream", array1MB.length, out.size());
        
        // Test with zero and negative parameters. This is allowed but should throw
        in = new ByteArrayInputStream(array4);
        out = new ByteArrayOutputStream();
        try {
            FileTools.streamCopyWithLimit(in, out, 0);
            fail("Should throw when limit is 0");
        } catch (StreamSizeLimitExceededException e) {
            // NOPMD expected
        }
        
        in = new ByteArrayInputStream(array4);
        out = new ByteArrayOutputStream();
        try {
            FileTools.streamCopyWithLimit(in, out, -1);
            fail("Should throw when limit is negative");
        } catch (StreamSizeLimitExceededException e) {
            // NOPMD expected
        }
        
        log.trace("<testStreamCopyWithLimit");
    }
    
}
