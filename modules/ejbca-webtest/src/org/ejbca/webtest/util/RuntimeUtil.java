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

/**
 * This utility class provides Java Runtime information details.
 *
 * @version $Id: RuntimeUtil.java 34938 2020-04-28 14:58:22Z andrey_s_helmes $
 */
public class RuntimeUtil {

    private static final DecimalFormat megabytesDecimalFormat = new DecimalFormat("000.00 'mb'");

    /**
     * Outputs runtime's RAM memory state to System.out (Used Memory / Free Memory / Total Memory / Maximum Memory).
     * <ul>
     *     <li>Used Memory: calculated as Total Memory - Free Memory;</li>
     *     <li>Free Memory: value of Runtime.getRuntime().freeMemory();</li>
     *     <li>Total Memory: value of Runtime.getRuntime().totalMemory();</li>
     *     <li>Maximum Memory: value of Runtime.getRuntime().maxMemory().</li>
     * </ul>
     */
    public static void outputRuntimeRAMDetails() {
        final Runtime runtime = Runtime.getRuntime();
        final long freeMemory = runtime.freeMemory();
        final long totalMemory = runtime.totalMemory();
        final long usedMemory = totalMemory - freeMemory;
        System.out.println(
                "Used [" + getMegabytes(usedMemory) + "] | " +
                "Free [" + getMegabytes(freeMemory) + "] | " +
                "Total [" + getMegabytes(totalMemory) + "] | " +
                "Max [" + getMegabytes(runtime.maxMemory()) + "]"
        );
    }

    // Converts the number of bytes into String representing number of megabytes, where 1048576 bytes = 1 Mb
    private static String getMegabytes(final long numberOfBytes) {
        return megabytesDecimalFormat.format(Long.valueOf(numberOfBytes).doubleValue() / (1024 * 1024));
    }
}
