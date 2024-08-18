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
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class RaEndEntityBeanCompareOptionStringsUnitTest {
    private static final Logger log = Logger.getLogger(RaEndEntityBeanUnitTest.class);

    private final String first;
    private final String second;
    private final ExpectedCompareResult expectedCompareResult;

    public static enum ExpectedCompareResult {
        EQUAL,
        LESS_THAN,
        GREATER_THAN
    }

    @Rule
    public RaEndEntityBean bean = new RaEndEntityBean();

    public RaEndEntityBeanCompareOptionStringsUnitTest(final String first,
                                                       final String second,
                                                       final CompareResult expectedCompareResult) {
        this.first = first;
        this.second = second;
        this.expectedCompareResult = expectedCompareResult;
    }

    @Parameterized.Parameters
    public static Collection testParameters() {
        return Arrays.asList(new Object[][] {
                { "EMPTY", "EMPTY", ExpectedCompareResult.EQUAL },
                { "EMPTY", "abc", ExpectedCompareResult.LESS_THAN },
                { "EMPTY", "Def", ExpectedCompareResult.LESS_THAN },
                { "Def", "abc", ExpectedCompareResult.GREATER_THAN },
                { "Abc", "abc", ExpectedCompareResult.LESS_THAN }
        });
    }

    @Test
    public void testCompareOptionStrings() {
        var actual = bean.compareOptionStrings(first, second);
        switch (expectedCompareResult) {
            case EQUAL:
                assertEquals(0, actual);
                break;
            case LESS_THAN:
                assertTrue(actual < 0);
                break;
            case GREATER_THAN:
                assertTrue(actual > 0);
                break;
            default:
                throw new IllegalStateException("Unexpected value: " + expectedCompareResult);
        }
    }

}