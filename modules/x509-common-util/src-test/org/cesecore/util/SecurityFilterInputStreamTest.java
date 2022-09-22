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

import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;

import org.apache.log4j.Logger;
import org.junit.Test;

/** Tests SecurityFilterInputStream class that can be used to prevent java heap-overflow during
 * reading from input stream
 * 
 * @version $Id$
 */
public class SecurityFilterInputStreamTest {

    private static final Logger log = Logger.getLogger(SecurityFilterInputStreamTest.class);

    /**
     * Prepares output stream with exploit string
     * @param outputStream
     *      stream where exploit String objects will be write into
     * @param payloadSize
     *      payloadSize of string that is going to be generated; use high value for exploit (etc. 0x1FFFFFFF);
     *      also be aware that some high values could throw heap error on attacker's JVM
     */
    public static void prepareExploitStream(final OutputStream outputStream, final long payloadSize) throws IOException {

        outputStream.write(ObjectOutputStream.STREAM_MAGIC >>> 8);
        outputStream.write(ObjectOutputStream.STREAM_MAGIC);
        outputStream.write(0); // don't need the high bits set for the version
        outputStream.write(ObjectOutputStream.STREAM_VERSION);

        if (payloadSize <= 0xFFFF) {
            outputStream.write(ObjectOutputStream.TC_STRING);
            outputStream.write((int) payloadSize >>> 8);
            outputStream.write((int) payloadSize);
        } else {
            outputStream.write(ObjectOutputStream.TC_LONGSTRING);
            outputStream.write((int) (payloadSize >>> 56));
            outputStream.write((int) (payloadSize >>> 48));
            outputStream.write((int) (payloadSize >>> 40));
            outputStream.write((int) (payloadSize >>> 32));
            outputStream.write((int) (payloadSize >>> 24));
            outputStream.write((int) (payloadSize >>> 16));
            outputStream.write((int) (payloadSize >>> 8));
            outputStream.write((int) (payloadSize >>> 0));
        }

        for (long i = 0; i < payloadSize; i++) {
            outputStream.write((byte) 'B');
        }
        outputStream.flush();
    }

    /**
     * Test preventing exploit by checking its size with SecurityFilterInputStream
     */
    @Test
    public void testPreventingTheStringBuilderExploit() throws Exception {
        log.trace(">testPreventingTheStringBuilderExploit");
        ObjectInputStream objectInputStream = null;
        ByteArrayOutputStream byteArrayOutputStream = null;
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            prepareExploitStream(byteArrayOutputStream, 0x1FFFFF); // 0x1FFFFF just simulates exploit stream

            objectInputStream = new ObjectInputStream(
                    new SecurityFilterInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()), 0xFFFFF));
            objectInputStream.readObject(); //would throw Java heap error if SecurityFilterInputStream is not applied
            fail("No Java heap error happened for StringBuilder exploit (MaxHeap = " + Runtime.getRuntime().maxMemory() / (1024 * 1024) + "MB) and"
                    + " SecurityFilterInputStream hasn't limited the size of input stream during testPreventingTheStringBuilderExploit");
        } catch (SecurityException e) {
            //Good
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage() + " during testPreventingTheStringBuilderExploit");
        } finally {
            if (byteArrayOutputStream != null) {
                byteArrayOutputStream.close();
            }
            if (objectInputStream != null) {
                objectInputStream.close();
            }
        }
        log.trace("<testPreventingTheStringBuilderExploit");
    }

    /**
     * Test if good input stream (size < SecurityFilterInputStream.maxBytes) can be filtered
     */
    @Test
    public void testAcceptedSizeInputStream() throws Exception {
        log.trace(">testAcceptedSizeInputStream");
        ObjectInputStream objectInputStream = null;
        ByteArrayOutputStream byteArrayOutputStream = null;
        try {
            byteArrayOutputStream = new ByteArrayOutputStream();
            prepareExploitStream(byteArrayOutputStream, 0xFFFF); // 0xFFFF simulates safe stream 

            objectInputStream = new ObjectInputStream(
                    new SecurityFilterInputStream(new ByteArrayInputStream(byteArrayOutputStream.toByteArray()), 0xFFFFF));
            objectInputStream.readObject();
        } catch (Exception e) {
            fail("Unexpected exception: " + e.getMessage() + " during testAcceptedSizeInputStream");
        } finally {
            if (byteArrayOutputStream != null) {
                byteArrayOutputStream.close();
            }
            if (objectInputStream != null) {
                objectInputStream.close();
            }
        }
        log.trace("<testAcceptedSizeInputStream");
    }
}
