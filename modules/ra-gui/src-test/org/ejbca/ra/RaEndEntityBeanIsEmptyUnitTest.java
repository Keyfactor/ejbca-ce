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
public class RaEndEntityBeanIsEmptyUnitTest {
    private static final Logger log = Logger.getLogger(RaEndEntityBeanUnitTest.class);

    private final String input;
    private final boolean expected;
    private RaEndEntityBean bean;

    public RaEndEntityBeanIsEmptyUnitTest(final String input,
                                          final boolean expected) {
        this.input = input;
        this.expected = expected;
    }

    @Before
    public void setUp() {
        bean = new RaEndEntityBean();
    }

    @Parameterized.Parameters
    public static Collection testParameters() {
        return Arrays.asList(new Object[][] {
                { null, true },
                { "", true },
                { "   ", true }
        });
    }

    @Test
    public void testIsEmpty() throws Exception {
        var actual = bean.isEmpty(input);
        assertEquals(expected, actual);
    }

}