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
package org.ejbca.ui.cli.config.est;

import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * @version $Id$
 *
 */
public class ListAliasCommand extends BaseEstConfigCommand {

    private static final Logger log = Logger.getLogger(ListAliasCommand.class);

    @Override
    public String getMainCommand() {
        return "listalias";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        List<String> aliaslist = getEstConfiguration().getSortedAliasList();
        for(String alias : aliaslist) {
            log.info(alias);
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Lists all existing EST configuration aliases";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
