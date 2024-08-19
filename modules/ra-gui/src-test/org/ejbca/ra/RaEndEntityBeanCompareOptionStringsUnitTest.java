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
 
 
package org.ejbca.ra;

import org.apache.log4j.Logger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;
import java.util.Arrays;
import java.util.Collection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class RaEndEntityBeanCompareOptionStringsUnitTest {
    private static final Logger log = Logger.getLogger(RaEndEntityBeanUnitTest.class);

    private final String first;
    private final String second;
    private final ExpectedCompareResult expectedCompareResult;
    private RaEndEntityBean bean;

    public static enum ExpectedCompareResult {
        EQUAL("0"),
        LESS_THAN("a negative number"),
        GREATER_THAN("a positive number");

        private final String description;

        ExpectedCompareResult(final String description) {
            this.description = description;
        }

        @Override
        public String toString() {
            return description;
        }

    }

    public RaEndEntityBeanCompareOptionStringsUnitTest(final String first,
                                                       final String second,
                                                       final ExpectedCompareResult expectedCompareResult) {
        this.first = first;
        this.second = second;
        this.expectedCompareResult = expectedCompareResult;
    }

    @Before
    public void setUp() {
        bean = new RaEndEntityBean();
    }

    @Parameterized.Parameters
    public static Collection testParameters() {
        return Arrays.asList(new Object[][] {
                { "EMPTY", "EMPTY", ExpectedCompareResult.EQUAL },
                { "EMPTY", "abc", ExpectedCompareResult.GREATER_THAN },
                { "EMPTY", "fgh", ExpectedCompareResult.LESS_THAN },
                { "Def", "abc", ExpectedCompareResult.GREATER_THAN },
                { "Abc", "abc", ExpectedCompareResult.LESS_THAN }
        });
    }

    @Test
    public void testCompareOptionStrings() {
        int actual = bean.compareOptionStrings(first, second);
        String msg = "\nfirst = " + first + ",\nsecond = " + second + ",\nactual = " + actual + ",\nexpected " + expectedCompareResult;
        switch (expectedCompareResult) {
            case EQUAL:
                assertEquals(msg, 0, actual);
                break;
            case LESS_THAN:
                assertTrue(msg, actual < 0);
                break;
            case GREATER_THAN:
                assertTrue(msg, actual > 0);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + expectedCompareResult);
        }
    }

}