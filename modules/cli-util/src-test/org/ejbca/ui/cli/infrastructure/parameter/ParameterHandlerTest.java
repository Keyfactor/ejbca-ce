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
package org.ejbca.ui.cli.infrastructure.parameter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.junit.Before;
import org.junit.Test;

/**
 * Unit tests for the ParameterHandler class.
 * 
 * @version $Id$
 *
 */
public class ParameterHandlerTest {

    private ParameterHandler parameterHandler;

    @Before
    public void setup() {
        parameterHandler = new ParameterHandler("unittest");
    }

    @Test
    public void testHandleUnknownParameters() {
        ParameterContainer result = parameterHandler.parseParameters("foo");
        assertNull("Parameterhandler did not return null for unknown parameter", result);
    }

    @Test
    public void testHandleMissingParameters() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        ParameterContainer result = parameterHandler.parseParameters();
        assertNull("Parameterhandler did not return null for missing parameter", result);
    }

    @Test
    public void testHandleStandardParameter() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        parameterHandler.registerParameter(new Parameter("f", "foo", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        ParameterContainer result = parameterHandler.parseParameters("-b", "bar", "f", "foo");
        assertNotNull("Parameterhandler did not return result", result);
        assertEquals("Parameterhandler did not return correct result", "bar", result.get("-b"));
        assertEquals("Parameterhandler did not return correct result", "foo", result.get("f"));
    }

    @Test
    public void testHandleStandardParameterWithEquals() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        ParameterContainer result = parameterHandler.parseParameters("-b=boo");
        assertNotNull("Parameterhandler did not return result", result);
        assertEquals("Parameterhandler did not return correct result", "boo", result.get("-b"));
    }

    @Test
    public void testHandleStandaloneParameter() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        ParameterContainer result = parameterHandler.parseParameters("boo");
        assertNotNull("Parameterhandler did not return result", result);
        assertEquals("Parameterhandler did not return correct result", "boo", result.get("-b"));
    }

    /**
     * Handle the case where a quoted parameter has been split up due to spaces. 
     */
    @Test
    public void testHandleSplitParameter() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        ParameterContainer result = parameterHandler.parseParameters("'fo=o", "bar", "xyz'");
        assertNotNull("Parameterhandler did not return result", result);
        assertEquals("Parameterhandler did not return correct result", "fo=o bar xyz", result.get("-b"));
    }
    
    @Test
    public void testHandleIncompleteArgument() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        parameterHandler.registerParameter(new Parameter("-f", "foo", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG, ""));
        try {
            ParameterContainer result = parameterHandler.parseParameters("-b");
            assertNull("Parameterhandler did not return null for missing parameter value", result);
            result = parameterHandler.parseParameters("-b", "-f");
            assertNull("Parameterhandler did not return null for missing parameter", result);
        } catch (Exception e) {
            fail("Parameterhandler did not fail nicely to incomplete argument");
        }

    }

    @Test
    public void testHandleMultipleParameter() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, ""));
        ParameterContainer result = parameterHandler.parseParameters("-b", "foo", "-b", "bar");
        assertNull("It should not be possible to use the same parameter multiple times.", result);
    }

}
