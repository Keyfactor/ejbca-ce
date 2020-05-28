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
package org.ejbca.core.ejb.ocsp;

import javax.ejb.ScheduleExpression;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * @version $Id$
 */
public interface OcspResponseCleanupSession {

    static ScheduleExpression convertToScheduleFromMS(final long miliseconds) {
        // Default values:
        //  second          0
        //  minute          0
        //  hour            0
        //  dayOfMonth      *
        //  Year            *
        ScheduleExpression schedule = new ScheduleExpression();

        if (TimeUnit.MILLISECONDS.toDays(miliseconds) > 0) {
            long days = TimeUnit.MILLISECONDS.toDays(miliseconds);

            // dayOfMonth doesn't allow "*/3" like expression for every 3 days for example, so this builds
            // the alternative expression: "1,3,6,..., 30"
            List<String> daysInterval = IntStream.rangeClosed(1, 31)
                                                  .filter(i -> i == 1 || i % days == 0)
                                                  .mapToObj(i -> String.valueOf(i))
                                                  .collect(Collectors.toList());

            return schedule.second(0).minute(0).hour(0).dayOfMonth(String.join(",", daysInterval));
        }

        if (TimeUnit.MILLISECONDS.toHours(miliseconds) > 0) {
            return schedule.second(0).minute(0).hour("*/" + TimeUnit.MILLISECONDS.toHours(miliseconds));
        }

        if (TimeUnit.MILLISECONDS.toMinutes(miliseconds) > 0) {
            return schedule.second(0).minute("*/" + TimeUnit.MILLISECONDS.toMinutes(miliseconds)).hour("*");
        }

        return schedule.second("0").minute("0").hour("*");
    }
}
