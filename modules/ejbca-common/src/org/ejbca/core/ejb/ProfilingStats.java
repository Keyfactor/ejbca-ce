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

import java.util.AbstractMap.SimpleImmutableEntry;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @see org.ejbca.core.ejb.ProfileAndTraceInterceptor
 * 
 * Limitations:
 * - Maximum allowed sum of duration is 292471 years.. :)
 * - Retrieval of stats is not a perfect point in time snapshot
 * 
 * @version $Id$
 */
public enum ProfilingStats {
    INSTANCE;

    private final ConcurrentHashMap<String,Entry<Long,Long>> sums = new ConcurrentHashMap<String,Entry<Long,Long>>();

    public void add(final String key, final long invocationDuration) {
        Entry<Long, Long> expectedValue = null;
        Entry<Long,Long> currentEntry = null;
        // Since there are likely many parallel invocations to different methods but rarely to the same
        // we use a ConcurrentHashMap to allow concurrent modifications.
        // The drawback is that we another thread might have updated the map while we were doing preparations
        // and in this case we have to retry.
        do {
            currentEntry = sums.get(key);
            final Entry<Long,Long> newEntry;
            if (currentEntry == null) {
                // Populate with a first entry for this key. We expect that the old value should be null
                newEntry = new SimpleImmutableEntry<Long,Long>(Long.valueOf(invocationDuration), Long.valueOf(1L));
                expectedValue = sums.putIfAbsent(key, newEntry);
            } else {
                newEntry = new SimpleImmutableEntry<Long,Long>(Long.valueOf(currentEntry.getKey().longValue()+invocationDuration),
                        Long.valueOf(currentEntry.getValue().longValue()+1L));
                expectedValue = sums.replace(key, newEntry);
            }
        } while (expectedValue!=null && !expectedValue.equals(currentEntry));
    }

    /**
     * Get a shallow copy of the current invocation statistics as a Maps with full method names as keys.
     * The key of the Entry is the sum of durations (µs) and the value is the number of invocations.
     * Since the copy operation is non-locking, this will not be a perfect point in time snapshot.
     */
    private Map<String,Entry<Long,Long>> getBestEffortShallowCopyOfStats() {
        return new HashMap<String,Entry<Long,Long>>(sums);
    }

    /**
     * Get a shallow copy of the current invocation statistics as a list if caller friendly objects.
     * Since the copy operation is non-locking, this will not be a perfect point in time snapshot.
     */
    public List<ProfilingStat> getEjbInvocationStats() {
        final Map<String,Entry<Long,Long>> sums = getBestEffortShallowCopyOfStats();
        final Set<String> keys = sums.keySet();
        final List<ProfilingStat> ret = new ArrayList<ProfilingStat>(keys.size());
        for (final String key : keys) {
            final Entry<Long, Long> durationAndInvocations = sums.get(key);
            final ProfilingStat profilingStat = new ProfilingStat(key, durationAndInvocations.getKey(), durationAndInvocations.getValue());
            ret.add(profilingStat);
        }
        return ret;
    }
}
