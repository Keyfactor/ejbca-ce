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
import org.cesecore.certificates.ca.CABase;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CmsCertificatePathMissingException;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
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
public class CaEditCaCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaEditCaCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String FIELD_KEY = "--field";
    private static final String VALUE_KEY = "--value";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the CA to edit."));
        registerParameter(new Parameter(FIELD_KEY, "Field Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The sought field."));
        registerParameter(new Parameter(VALUE_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The value to set, if any."));
    }

    @Override
    public String getMainCommand() {
        return "editca";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        FieldEditor fieldEditor = new FieldEditor(log);
        CryptoProviderTools.installBCProviderIfNotAvailable();;
        final String name = parameters.get(CA_NAME_KEY);
        final String field = parameters.get(FIELD_KEY);
        final String value = parameters.get(VALUE_KEY);
        try {
            final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), name);
            // List fields, get values or set value
            try {
                if(field.equals(CABase.NAME)) {
                    // The CA name field is a bit of a special case. Since there's a CESeCore method specifically for it, we should use
                    // it instead
                    try {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).renameCA(getAuthenticationToken(), cainfo.getName(), value);
                        log.info("Renamed CA by the name  '" + cainfo.getName() + "' to '" + value + "'");
                    } catch (CAExistsException e) {
                        log.error("A CA by the name of " + value + " already exists.");
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                } else {                
                    fieldEditor.setValue(name, field, value, cainfo);                
                    log.info("Storing modified CA info for CA '" + name + "'...");
                    EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).editCA(getAuthenticationToken(), cainfo);
                    // Verify our new value.
                    // If the CA Subject DN was changed, then the CA Id might have changed at this point,
                    // so we have to do the lookup by name!
                    log.info("Reading modified value for verification...");
                    final CAInfo cainfomod = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(),
                            name);
                    // Print return value
                    fieldEditor.getBeanValue(field, cainfomod);                    
                }
                return CommandResult.SUCCESS;
            } catch (FieldNotFoundException e) {
                log.error(e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        } catch (CADoesntExistsException e) {
            log.info("CA '" + name + "' does not exist.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI User was not authorized to CA " + name);
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CmsCertificatePathMissingException e) {
            log.error("CA " + name + " could not be modified, CMS certificate path was missing");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Edits CA fields of an existing CA.";
               
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "Fields that can be set are derived from setFieldName of the CA java code. If there is a 'setFieldName(type)' method, the values to use in this command should be 'fieldName value'\n"
                + "Example: ca editca CAName CRLPeriod 2592000000\n"
                + "Example: ca editca CAName CRLIssueInterval 100000\n"
                + "Example: ca editca CAName includeInHealthCheck false\n"
                + "Example: ca editca --caname CAName --field CRLPublishers --value \"1234\"\n"
                + "Example: ca editca --caname CAName --field CRLPublishers --value \"1234;3456\"\n"
                + "Example: ca editca --caname CAName --field CRLPublishers --value \"\"\n";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
