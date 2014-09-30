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
package org.ejbca.core.ejb;

import static org.junit.Assert.assertTrue;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.junit.Rule;
import org.junit.Test;

/**
 * Not really a test, but can be invoked via the JUnit testing framework to extract profiling statistics.
 * 
 * @version $Id$
 */
public class ProfilingTest {
    
    private static final Logger log = Logger.getLogger(ProfilingTest.class);

    private static final long HIGEST_AVERAGE_ALLOWED_MS = 30000L;

    private ProfilingStatsAccessSessionRemote profilingStatsAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(ProfilingStatsAccessSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    @Rule
    public org.junit.rules.TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @Test
    public void retrieveStats() {
        final List<ProfilingStat> profilingStats = profilingStatsAccessSession.getEjbInvocationStats();
        if (profilingStats.isEmpty()) {
            // If there is no profiling enabled, we just log some information on how to enable it.
            log.warn("This test requires EJBCA profiling to be enabled.");      
            log.warn("  In conf/ejbca.properties set ejbca.productionmode=false");      
            log.warn("  Log4J DEBUG log level must be enabled.");
            return;
        }
        // Sort with most consumed time first
        Collections.sort(profilingStats, new Comparator<ProfilingStat>() {
            @Override
            public int compare(ProfilingStat p0, ProfilingStat p1) {
                return (int)(p1.getDurationMilliSeconds() - p0.getDurationMilliSeconds());
            }
        });
        log.info("\n\nInvocations with most consumed time:\n" + getAsString(profilingStats));
        // Sort with highest average (slowest) first
        Collections.sort(profilingStats, new Comparator<ProfilingStat>() {
            @Override
            public int compare(ProfilingStat p0, ProfilingStat p1) {
                return (int)(p1.getAverageMilliSeconds() - p0.getAverageMilliSeconds());
            }
        });
        log.info("\n\nInvocations with average highest invocation time:\n" + getAsString(profilingStats));
        // Sort with most invoked methods first
        Collections.sort(profilingStats, new Comparator<ProfilingStat>() {
            @Override
            public int compare(ProfilingStat p0, ProfilingStat p1) {
                return (int)(p1.getInvocations() - p0.getInvocations());
            }
        });
        log.info("\n\nMost invoked methods:\n" + getAsString(profilingStats));
        // Make a sanity check that the highest average invocation has not run too high
        long highestAverage = 0;
        for (final ProfilingStat profilingStat : profilingStats) {
            highestAverage = Math.max(highestAverage, profilingStat.getAverageMilliSeconds());
        }
        assertTrue("Highest average invocation time was " + highestAverage + "ms. Max allowed for this test to pass is " +
                HIGEST_AVERAGE_ALLOWED_MS +" ms.", highestAverage<HIGEST_AVERAGE_ALLOWED_MS);
    }
    
    // Output in a format that is friendly to post-processing
    private String getAsString(final List<ProfilingStat> profilingStats) {
        final StringBuilder sb = new StringBuilder();
        sb.append(String.format("%1$-120s", "method")).append(' ');
        sb.append(String.format("%1$10s", "sum (ms)")).append(' ');
        sb.append(String.format("%1$10s", "calls")).append(' ');
        sb.append(String.format("%1$10s", "avg (ms)")).append('\n');
        for (final ProfilingStat profilingStat : profilingStats) {
            sb.append(String.format("%1$-120s", profilingStat.getFullmethodName())).append(' ');
            sb.append(String.format("%1$10d", profilingStat.getDurationMilliSeconds())).append(' ');
            sb.append(String.format("%1$10d", profilingStat.getInvocations())).append(' ');
            sb.append(String.format("%10.3f", Long.valueOf(profilingStat.getAverageMicroSeconds()).doubleValue()/1000)).append('\n');
        }
        return sb.toString();
    }
}
