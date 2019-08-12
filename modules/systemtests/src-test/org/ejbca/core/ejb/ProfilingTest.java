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

import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.config.DatabaseConfiguration;
import org.junit.Rule;
import org.junit.Test;

/**
 * Not really a test, but can be invoked via the JUnit testing framework to extract profiling statistics.
 * 
 * @version $Id$
 */
public class ProfilingTest {
    
    private static final Logger log = Logger.getLogger(ProfilingTest.class);

    // Default
    private static final long HIGEST_AVERAGE_ALLOWED_MS_DEFAULT = 30_000L;
    // MariaDB: 31976ms, 34336ms, 38924ms => 39_000L
    private static final long HIGEST_AVERAGE_ALLOWED_MS_FOR_MARIADB = 39_000L;
    // DB2: 37956ms, 41023ms, 34750ms => 42_000L
    private static final long HIGEST_AVERAGE_ALLOWED_MS_FOR_DB2 = 42_000L;
    // MSSQL: 56174ms, 56153ms, 59961ms => 60_000L
    private static final long HIGEST_AVERAGE_ALLOWED_MS_FOR_MSSQL = 60_000L;
    // Oracle: 34098ms, 30731ms, 31835ms => 35_000L
    private static final long HIGEST_AVERAGE_ALLOWED_MS_FOR_ORACLE = 35_000L;

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
        profilingStats.sort((p0, p1) -> (int) (p1.getDurationMilliSeconds() - p0.getDurationMilliSeconds()));
        log.info("\n\nInvocations with most consumed time:\n" + getAsString(profilingStats));
        // Sort with highest average (slowest) first
        profilingStats.sort((p0, p1) -> (int) (p1.getAverageMilliSeconds() - p0.getAverageMilliSeconds()));
        log.info("\n\nInvocations with average highest invocation time:\n" + getAsString(profilingStats));
        // Sort with most invoked methods first
        profilingStats.sort((p0, p1) -> (int) (p1.getInvocations() - p0.getInvocations()));
        log.info("\n\nMost invoked methods:\n" + getAsString(profilingStats));
        // Make a sanity check that the highest average invocation has not run too high
        long highestAverage = 0;
        for (final ProfilingStat profilingStat : profilingStats) {
            highestAverage = Math.max(highestAverage, profilingStat.getAverageMilliSeconds());
        }
        final long higestAverageAllowed = getHigestAverageAllowedMsPerDatabase();
        final String highestAverageInvocationTimeWas = "Highest average invocation time was " + highestAverage + "ms.";
        assertTrue(
                highestAverageInvocationTimeWas + " Max allowed for this test to pass is " + higestAverageAllowed +" ms.",
                highestAverage < higestAverageAllowed);
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

    private long getHigestAverageAllowedMsPerDatabase() {
        final String databaseName = DatabaseConfiguration.getDatabaseName();
        // As in database.properties.sample
        if("mysql".equalsIgnoreCase(databaseName)) {
            return HIGEST_AVERAGE_ALLOWED_MS_FOR_MARIADB;
        }
        else if("db2".equalsIgnoreCase(databaseName)) {
            return HIGEST_AVERAGE_ALLOWED_MS_FOR_DB2;
        }
        else if("mssql".equalsIgnoreCase(databaseName)) {
            return HIGEST_AVERAGE_ALLOWED_MS_FOR_MSSQL;
        }
        else if("oracle".equalsIgnoreCase(databaseName)) {
            return HIGEST_AVERAGE_ALLOWED_MS_FOR_ORACLE;
        }
        log.debug("A value of the higest allowed average for database (" + databaseName + ") was not found, falling back to default (" + HIGEST_AVERAGE_ALLOWED_MS_DEFAULT + ").");
        // Return default
        return HIGEST_AVERAGE_ALLOWED_MS_DEFAULT;
    }
}
