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

import java.awt.print.PrinterException;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Date;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.util.PrinterManager;
/**
 *
 *
 * Class used as a help tool when creating hard token visual layout templates
 * @version $Id$
 */
public class SVGTemplatePrinterCommand extends EjbcaCommandBase {

    private static final Logger log = Logger.getLogger(SVGTemplatePrinterCommand.class);

    private static final String USERDATAFILENAME = "src/cli/svgtemplateprinttester.properties";
    private static final String TEMPLATEFILENAME_KEYWORD = "-t";
    private static final String PRINTERNAME_KEYWORD = "-p";

    //Register parameters
    {
        registerParameter(new Parameter(TEMPLATEFILENAME_KEYWORD, "Template filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The template file name."));
        registerParameter(new Parameter(PRINTERNAME_KEYWORD, "Printer name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the printer."));
    }

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
        return "print";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String templatefilename = parameters.get(TEMPLATEFILENAME_KEYWORD);
        String printername = parameters.get(PRINTERNAME_KEYWORD);
        Properties data = new Properties();
        try {
            try {
                data.load(new FileInputStream(USERDATAFILENAME));
            } catch (FileNotFoundException e) {
                log.error("File " + USERDATAFILENAME + " does not exist, command cannot run.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            EndEntityInformation userdata = new EndEntityInformation("", data.getProperty("DN"), 0, "", data.getProperty("EMAIL"), 0,
                    new EndEntityType(EndEntityTypes.INVALID), 0, 0, (Date) null, (Date) null, 0, 0, null);
            String[] pins = new String[2];
            String[] puks = new String[2];
            pins[0] = data.getProperty("PIN1");
            pins[1] = data.getProperty("PIN2");
            puks[0] = data.getProperty("PUK1");
            puks[1] = data.getProperty("PUK2");
            String copyofhardtokensn = data.getProperty("COPYOFHARDTOKENSN");
            String hardtokensn = data.getProperty("HARDTOKENSN");
            int validity = Integer.parseInt(data.getProperty("VALIDITY"));
            String hardtokensnprefix = data.getProperty("HARDTOKENSNPREFIX");
            FileInputStream fis;
            try {
                fis = new FileInputStream(templatefilename);
            } catch (FileNotFoundException e) {
                log.error("File " + templatefilename + " could not be found, command cannot run.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            try {
                byte[] byteData = new byte[fis.available()];
                fis.read(byteData);
                String sVGData = new String(byteData, "UTF8");
                try {
                    PrinterManager.print(printername, templatefilename, sVGData, 1, validity, userdata, pins, puks, hardtokensnprefix, hardtokensn,
                            copyofhardtokensn);
                } catch (PrinterException e) {
                    log.error("Printing failed, see associated stack trace.", e);
                }
            } finally {
                fis.close();
            }
            return CommandResult.SUCCESS;
        } catch (IOException e) {
            throw new IllegalStateException("IOException was caught, see underlying error.", e);
        }

    }

    @Override
    public String getCommandDescription() {
        return "Tool for creating hard token visual layout templates";
    }

    @Override
    public String getFullHelpText() {
        return "Tool for creating hard token visual layout templates. User data is configured in  " + USERDATAFILENAME;
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }

}
