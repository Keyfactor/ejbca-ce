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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
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

    /** Not a ZIP file */
    private static final byte[] NON_ZIP_FILE = new byte[] { 0x12, 0x34, 0x56 };
    /** An empty ZIP file. Created by copying the onefile.zip file below, and the running "zip -d copy.zip empty.txt" */
    private static final byte[] EMPTY_ZIP_FILE = new byte[] {
            0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    /** A ZIP file with one file. Created with "zip onefile.zip empty.txt" */
    private static final byte[] NONEMPTY_ZIP_FILE = new byte[] {
            0x50, 0x4b, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xb0, 0x5e,
            0x2a, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x09, 0x00, 0x1c, 0x00, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e,
            0x74, 0x78, 0x74, 0x55, 0x54, 0x09, 0x00, 0x03, 0x2c, 0x24, 0x37, 0x5c,
            (byte) 0xd0, 0x49, 0x3f, 0x5c, 0x75, 0x78, 0x0b, 0x00, 0x01, 0x04, 0x18, 0x05,
            0x00, 0x00, 0x04, 0x18, 0x05, 0x00, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x1e,
            0x03, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xb0, 0x5e, 0x2a, 0x4e, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
            0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte) 0xa4,
            (byte) 0x81, 0x00, 0x00, 0x00, 0x00, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e, 0x74,
            0x78, 0x74, 0x55, 0x54, 0x05, 0x00, 0x03, 0x2c, 0x24, 0x37, 0x5c, 0x75,
            0x78, 0x0b, 0x00, 0x01, 0x04, 0x18, 0x05, 0x00, 0x00, 0x04, 0x18, 0x05,
            0x00, 0x00, 0x50, 0x4b, 0x05, 0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x4f, 0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00
    };


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

    @Test
    public void identifyZipFile() {
        log.trace(">identifyZipFile");
        assertFalse("isZipFile return value for non ZIP file",            FileTools.isZipFile(NON_ZIP_FILE));
        assertTrue("isZipFile return value for empty ZIP file",           FileTools.isZipFile(EMPTY_ZIP_FILE));
        assertTrue("isZipFile return value for non-empty ZIP file",       FileTools.isZipFile(NONEMPTY_ZIP_FILE));
        assertFalse("isEmptyZipFile return value for non ZIP file",       FileTools.isEmptyZipFile(NON_ZIP_FILE));
        assertTrue("isEmptyZipFile return value for empty ZIP file",      FileTools.isEmptyZipFile(EMPTY_ZIP_FILE));
        assertFalse("isEmptyZipFile return value for non-empty ZIP file", FileTools.isEmptyZipFile(NONEMPTY_ZIP_FILE));
        log.trace("<identifyZipFile");
    }

}
