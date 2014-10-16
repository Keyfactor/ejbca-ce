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
package org.ejbca.ui.cli.keybind;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class SetDefaultOcspResponderCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(SetDefaultOcspResponderCommand.class);

    @Override
    public String[] getCommandPath() {
        return new String[] { "keybind" };
    }

    @Override
    public String getMainCommand() {
        return "setdefaultresponder";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
      
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Sets the default OCSP responder";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }
}
