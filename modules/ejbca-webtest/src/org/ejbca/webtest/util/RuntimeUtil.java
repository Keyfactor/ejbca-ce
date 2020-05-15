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
package org.ejbca.webtest.util;

import java.text.DecimalFormat;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.webtest.util.ram.RamMemorySnapshot;

/**
 * This utility class provides Java Runtime information details.
 *
 * @version $Id: RuntimeUtil.java 34938 2020-04-28 14:58:22Z andrey_s_helmes $
 */
public class RuntimeUtil {

    private static final Logger log = Logger.getLogger(RuntimeUtil.class);

    private static final DecimalFormat megabytesDecimalFormat = new DecimalFormat("0000.00");

    /**
     * Returns the current RAM memory snapshot containing for the specific location:
     * <ul>
     *     <li>Used Memory: calculated as Total Memory - Free Memory;</li>
     *     <li>Free Memory: value of Runtime.getRuntime().freeMemory();</li>
     *     <li>Total Memory: value of Runtime.getRuntime().totalMemory();</li>
     *     <li>Maximum Memory: value of Runtime.getRuntime().maxMemory().</li>
     * </ul>
     * @return RamMemorySnapshot
     */
    public static RamMemorySnapshot getRuntimeRamSnapshot(final String location) {
        final Runtime runtime = Runtime.getRuntime();
        final long freeMemory = runtime.freeMemory();
        final long totalMemory = runtime.totalMemory();
        final long usedMemory = totalMemory - freeMemory;
        return RamMemorySnapshot.builder()
                .withUsedMemory(usedMemory)
                .withFreeMemory(freeMemory)
                .withTotalMemory(totalMemory)
                .withMaxMemory(runtime.maxMemory())
                .withLocation(location)
                .build();
    }

    /**
     * Outputs runtime's RAM memory snapshots in MB to log4j. An example:
     * <pre>
     *     |  Used   |  Free   |  Total  |  Max    |     Location
     *     | 0223.76 | 0790.24 | 1014.00 | 1024.00 |     MyTest.myTestMethod1
     *     | 0487.27 | 0526.73 | 1014.00 | 1024.00 |     MyTest.myTestMethod2
     *     | 0460.65 | 0553.35 | 1014.00 | 1024.00 |     The End
     * </pre>
     */
    public static void outputRuntimeRamSnapshots(final List<RamMemorySnapshot> ramMemorySnapshots) {
        log.debug("|  Used   |  Free   |  Total  |  Max    | \tLocation");
        for(RamMemorySnapshot ramMemorySnapshot : ramMemorySnapshots) {
            log.debug(
                    "| " + getMegabytes(ramMemorySnapshot.getUsedMemory()) +
                    " | " + getMegabytes(ramMemorySnapshot.getFreeMemory()) +
                    " | " + getMegabytes(ramMemorySnapshot.getTotalMemory()) +
                    " | " + getMegabytes(ramMemorySnapshot.getMaxMemory()) +
                    " | \t" + ramMemorySnapshot.getLocation()
            );
        }
    }

    // Converts the number of bytes into String representing number of megabytes, where 1048576 bytes = 1 Mb
    private static String getMegabytes(final long numberOfBytes) {
        return megabytesDecimalFormat.format(Long.valueOf(numberOfBytes).doubleValue() / (1024 * 1024));
    }
}
