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

package org.ejbca.ui.cli.ca;

import org.apache.log4j.Logger;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Remove the CA token keystore from a CA.
 * 
 * @version $Id$
 */
public class CaRemoveKeyStoreCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaRemoveKeyStoreCommand.class);
    
    private static final String CA_NAME_KEY = "--caname";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the CA"));
    }

    @Override
    public String getMainCommand() {
        return "removekeystore";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String caName = parameters.get(CA_NAME_KEY);
        EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).removeCAKeyStore(getAuthenticationToken(), caName);
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Remove the CA token keystore from a CA";
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
