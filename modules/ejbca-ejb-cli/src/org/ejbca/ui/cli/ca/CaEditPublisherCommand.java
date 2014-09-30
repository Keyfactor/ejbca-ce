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
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.ui.cli.FieldEditor;
import org.ejbca.ui.cli.FieldNotFoundException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Changes fields in a Publisher.
 *
 * @version $Id$
 */
public class CaEditPublisherCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaEditPublisherCommand.class);

    private static final String PUBLISHER_NAME_KEY = "--name";
    private static final String FIELD_KEY = "--field";
    private static final String VALUE_KEY = "--value";
    private static final String LISTFIELDS_KEY = "-listFields";
    private static final String GETVALUE_KEY = "-getValue";

    {
        registerParameter(new Parameter(PUBLISHER_NAME_KEY, "Publisher Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the certificate profile."));
        registerParameter(new Parameter(FIELD_KEY, "Field Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The sought field."));
        registerParameter(new Parameter(VALUE_KEY, "Value", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The value to set, if any."));
        registerParameter(new Parameter(LISTFIELDS_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Set to only list available fields in the CA"));
        registerParameter(new Parameter(GETVALUE_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Use this to get the value of a single field"));
    }

    @Override
    public String getMainCommand() {
        return "editpublisher";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        FieldEditor fieldEditor = new FieldEditor(log);
        CryptoProviderTools.installBCProvider();

        boolean listOnly = parameters.get(LISTFIELDS_KEY) != null;
        boolean getOnly = parameters.get(GETVALUE_KEY) != null;
        final String name = parameters.get(PUBLISHER_NAME_KEY);
        final String field = parameters.get(FIELD_KEY);
        final String value = parameters.get(VALUE_KEY);

        final BasePublisher pub = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class).getPublisher(name);
        if (pub == null) {
            log.info("Publisher '" + name + "' does not exist.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } else {
            // List fields, get values or set value
            try {
                if(field == null && !listOnly) {
                    log.error("ERROR: No field value set.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }      
                if (!fieldEditor.listGetOrSet(listOnly, getOnly, name, field, value, pub)) {
                    // Store the modifies object
                    log.info("Storing modified publisher '" + name + "'...");
                    EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class).changePublisher(getAuthenticationToken(), name, pub);
                    // Verify our new value
                    log.info("Reading modified value for verification...");
                    final BasePublisher modpub = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class).getPublisher(name);

                    // Print return value
                    fieldEditor.getBeanValue(field, modpub);
                }
                return CommandResult.SUCCESS;
            } catch (FieldNotFoundException e) {
                log.error(e.getMessage());
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (AuthorizationDeniedException e) {
                log.error("CLI User was not authorized to Publisher " + name);
                return CommandResult.AUTHORIZATION_FAILURE;
            }
        }

    }

    @Override
    public String getCommandDescription() {
        return "Edits publisher fields of an existing publisher in the CA. ";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()
                + "Fields that can be set are derived from setFieldName of the publisher java code. If there is a 'setFieldName(type)' method, the values to use in this command should be 'fieldName value'\n"
                + "Example: ca editpublisher PublisherName hostnames myhost.com\n"
                + "Example: ca editpublisher PublisherName addMultipleCertificates true\n"
                + "Example: ca editpublisher PublisherName connectionTimeOut 10000\n" + "\n"
                + "Use the option -listFields to only list available fields in the publisher.\n"
                + "Example: ca editpublisher PublisherName -listFields\n" + "\n"
                + "Use the option -getValue to only get the value of a field in the publisher.\n"
                + "Example: ca editpublisher PublisherName -getValue hostnames";
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
