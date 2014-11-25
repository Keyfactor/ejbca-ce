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

import java.util.Random;

import org.apache.log4j.Logger;

/**
 * Shamelessly ripped from generated XDoclet source, because I don't want to generate util classes.
 * 
 * @version $Id$
 */
public class GUIDGenerator {
    private static final Logger log = Logger.getLogger(GUIDGenerator.class);

    /** Cached per JVM server IP. */
    private static String hexServerIP = null;

    // Initialize the secure random instance
    private static final Random seeder = new Random();

    /**
     * A 32 byte GUID generator (Globally Unique ID). These artificial keys SHOULD <strong>NOT </strong> be seen by the user, not even touched by the
     * DBA but with very rare exceptions, just manipulated by the database and the programs.
     * NOTE: This guid is not cryptographically secure, and should not be used as such.
     * 
     * Usage: Add an id field (type java.lang.String) to your EJB, and add setId(XXXUtil.generateGUID(this)); to the ejbCreate method.
     */
    public static final String generateGUID(Object o) {

        if (hexServerIP == null) {
            java.net.InetAddress localInetAddress = null;
            try {
                // get the inet address
                localInetAddress = java.net.InetAddress.getLocalHost();
            } catch (java.net.UnknownHostException uhe) {
                log.error("Could not get the local IP address using InetAddress.getLocalHost(): ", uhe);
                // todo: find better way to get around this...
                return null;
            }
            byte serverIP[] = localInetAddress.getAddress();
            hexServerIP = hexFormat(getInt(serverIP), 8);
        }

        final String hashcode = hexFormat(System.identityHashCode(o), 8);
        // Use a combination of milliseconds and nanoseconds:
        // - milliseconds is not good enough for the test case (which makes a lot of calls in a quick succession).
        // - nanoseconds is also not good enough since some of the low-order bits may be always zero (how many is system and JDK dependent).
        long timeNow = System.currentTimeMillis() ^ System.nanoTime();
        int timeLow = (int) timeNow & 0xFFFFFFFF;
        int node = seeder.nextInt();
        final StringBuilder guid = new StringBuilder(32);

        guid.append(hexFormat(timeLow, 8));
        guid.append(hexServerIP);
        guid.append(hashcode);
        guid.append(hexFormat(node, 8));
        return guid.toString();
    }

    private static int getInt(byte bytes[]) {
        int i = 0;
        int j = 24;
        for (int k = 0; j >= 0; k++) {
            int l = bytes[k] & 0xff;
            i += l << j;
            j -= 8;
        }
        return i;
    }

    private static String hexFormat(int i, int j) {
        final String s = Integer.toHexString(i);
        return padHex(s, j) + s;
    }

    private static String padHex(String s, int i) {
        final StringBuilder tmpBuffer = new StringBuilder();
        if (s.length() < i) {
            for (int j = 0; j < i - s.length(); j++) {
                tmpBuffer.append('0');
            }
        }
        return tmpBuffer.toString();
    }
}
