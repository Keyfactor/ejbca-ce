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
package org.ejbca.ui.cli.infrastructure.parameter;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.Map;

import org.ejbca.ui.cli.infrastructure.command.CommandBase;
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
        Map<String, String> result = parameterHandler.parseParameters(new CommandBaseStub(), "foo");
        assertNull("Parameterhandler did not return null for unknown parameter", result);
    }

    @Test
    public void testHandleMissingParameters() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        Map<String, String> result = parameterHandler.parseParameters(new CommandBaseStub());
        assertNull("Parameterhandler did not return null for missing parameter", result);
    }
    
    @Test
    public void testHandleStandardParameter() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        Map<String, String> result = parameterHandler.parseParameters(new CommandBaseStub(), "-b", "boo");
        assertNotNull("Parameterhandler did not return result", result);
        assertEquals("ParameterHandel did not return correct result", "boo", result.get("-b"));
    }
    
    @Test
    public void testHandleStandaloneParameter() {
        parameterHandler.registerParameter(new Parameter("-b", "bar", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, ""));
        Map<String, String> result = parameterHandler.parseParameters(new CommandBaseStub(), "boo");
        assertNotNull("Parameterhandler did not return result", result);
        assertEquals("ParameterHandel did not return correct result", "boo", result.get("-b"));
    }

    private class CommandBaseStub extends CommandBase {


        @Override
        public String getMainCommand() {
            return "unittest";
        }

        @Override
        public String getCommandDescription() {

            return "";
        }

        @Override
        protected void execute(Map<String, String> parameters) throws IOException {

        }

        @Override
        public String getFullHelpText() {
            return null;
        }

        @Override
        public String getImplementationName() {
            return null;
        }

    }
}
