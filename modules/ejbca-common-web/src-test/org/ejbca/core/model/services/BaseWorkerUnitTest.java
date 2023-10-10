/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.services;

import static org.junit.Assert.assertEquals;

import java.util.Map;
import java.util.Properties;

import org.junit.Test;

/**
 * Unit tests of BaseWorker
 */
public class BaseWorkerUnitTest {

    @Test
    public void testTimeUnitToSecondsGood() throws ServiceExecutionFailedException {
        final BaseWorker worker = getDummyWorker();
        assertEquals("timeUnitToSeconds(SECONDS) is wrong", 1, worker.timeUnitToSeconds(IWorker.UNIT_SECONDS));
        assertEquals("timeUnitToSeconds(MINUTES) is wrong", 60, worker.timeUnitToSeconds(IWorker.UNIT_MINUTES));
        assertEquals("timeUnitToSeconds(HOURS) is wrong", 60*60, worker.timeUnitToSeconds(IWorker.UNIT_HOURS));
        assertEquals("timeUnitToSeconds(DAYS) is wrong", 24*60*60, worker.timeUnitToSeconds(IWorker.UNIT_DAYS));
    }

    @Test(expected = ServiceExecutionFailedException.class)
    public void testTimeUnitToSecondsBad() throws ServiceExecutionFailedException {
        final BaseWorker worker = getDummyWorker();
        worker.timeUnitToSeconds("BAD");
    }

    @Test
    public void testGetTimeBeforeExpire() throws ServiceExecutionFailedException {
        final String propertyUnit = "PROPERTY_UNIT";
        final String propertyValue = "PROPERTY_VALUE";
        final BaseWorker worker = getDummyWorker();
        worker.properties = new Properties();
        worker.properties.put(propertyUnit, IWorker.UNIT_DAYS);
        worker.properties.put(propertyValue, "3");
        assertEquals("getTimeBeforeExpire(DAYS,3) is wrong", 3*24*60*60*1000, worker.getTimeBeforeExpire(propertyUnit, propertyValue));
    }

    private BaseWorker getDummyWorker() {
        return new BaseWorker() {
            @Override
            public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
                return null;
            }
            @Override
            public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
            }
        };
    }

}
