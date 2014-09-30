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

package org.ejbca.ui.cli;

import java.util.HashSet;
import java.util.Set;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.util.PrinterManager;

/**
 *
 * Class used to list printers when creating hard token visual layout templates
 * 
 * @version $Id$
 */
public class SVGTemplateListCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(SVGTemplateListCommand.class);

    @Override
    public String[] getCommandPath() {
        return new String[] { "svgtemplate" };
    }

    @Override
    public Set<String[]> getCommandPathAliases() {
        Set<String[]> aliases = new HashSet<String[]>();
        aliases.add(new String[] { "template" });
        return aliases;
    }

    @Override
    public String getMainCommand() {
        return "listprinters";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String[] printerNames = PrinterManager.listPrinters();
        log.info("Found " + printerNames.length + " printer" + (printerNames.length > 1 ? "s" : "") + ":");
        for (String printerName : printerNames) {
            log.info("  " + printerName);
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Tool for listing available printers";
    }

    @Override
    public String getFullHelpText() {
        return "Tool for listing available printers";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
