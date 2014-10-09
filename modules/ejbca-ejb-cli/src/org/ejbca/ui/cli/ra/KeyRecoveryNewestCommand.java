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

package org.ejbca.ui.cli.ra;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Set status to key recovery for an end entity's newest certificate
 *
 * @version $Id$
 */
public class KeyRecoveryNewestCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(KeyRecoveryNewestCommand.class);

    private static final String USERNAME_KEY = "--username";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username for the end entity to perform key recovery upon."));
    }

    @Override
    public String getMainCommand() {
        return "keyrecovernewest";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String username = parameters.get(USERNAME_KEY);
        boolean usekeyrecovery = ((GlobalConfiguration) EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class)
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
        if (!usekeyrecovery) {
            getLogger().error("ERROR: Keyrecovery have to be enabled in the system configuration in order to use this command.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class).isUserMarked(username)) {
            getLogger().error("ERROR: End entity is already marked for recovery.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            EndEntityInformation userdata = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(
                    getAuthenticationToken(), username);
            if (userdata == null) {
                getLogger().error("The user doesn't exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).prepareForKeyRecovery(getAuthenticationToken(),
                    userdata.getUsername(), userdata.getEndEntityProfileId(), null)) {
                getLogger().info("Key corresponding to users newest certificate has been marked for recovery.");
                return CommandResult.SUCCESS;
            } else {
                getLogger().info("ERROR: Failed to mark key corresponding to users newest certificate for recovery.");
            }
        } catch (AuthorizationDeniedException e) {
            log.error("ERROR: CLI use not authorized to perform key recovery on user " + username);
        } catch (ApprovalException e) {
            log.error("ERROR: " + e.getMessage());
        } catch (WaitingForApprovalException e) {
            log.error("ERROR: " + e.getMessage());
        }
        return CommandResult.FUNCTIONAL_FAILURE;

    }

    @Override
    public String getCommandDescription() {
        return "Set status to key recovery for an end entity's newest certificate";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }
}
