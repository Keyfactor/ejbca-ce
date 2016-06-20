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
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.ui.cli.FieldNotFoundException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Changes fields in a CA.
 *
 * @version $Id$
 */
public class CaGetFieldValueCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaGetFieldValueCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String FIELD_KEY = "--field";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the CA to query."));
        registerParameter(new Parameter(FIELD_KEY, "Field Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The sought field."));
    }

    @Override
    public String getMainCommand() {
        return "getcafield";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        FieldEditor fieldEditor = new FieldEditor(log);
        CryptoProviderTools.installBCProviderIfNotAvailable();;
        final String name = parameters.get(CA_NAME_KEY);
        final String field = parameters.get(FIELD_KEY);
        try {
            final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), name);
            fieldEditor.getBeanValue(field, cainfo);
            return CommandResult.SUCCESS;
        } catch (CADoesntExistsException e) {
            log.info("CA '" + name + "' does not exist.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI User was not authorized to CA " + name);
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (FieldNotFoundException e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Displays the value of a specific field in an existing CA.";
               
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "Example: ca " + getMainCommand() + " CRLPeriod\n";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
