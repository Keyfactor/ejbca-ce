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
package org.ejbca.ui.cli.config.oauth;

import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * 
 *
 */
public class ViewOAuthProviderCommand extends BaseOAuthConfigCommand {
    
    private static final Logger log = Logger.getLogger(ViewOAuthProviderCommand.class);
    
    private static final String KEY_IDENTIFIER = "--keyidentifier";
    
    {
        registerParameter(new Parameter(KEY_IDENTIFIER, "Key identifier", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Key identifier of the Trusted OAuth Provider which is going to be added."));
    }

    @Override
    public String getMainCommand() {
        return "viewoauthprovider";
    }

    @Override
    public String getCommandDescription() {
        return "Displays information about the specified OAuth provider available in EJBCA";
    }

    @Override 
    protected CommandResult execute(ParameterContainer parameters) {
        String kid = parameters.get(KEY_IDENTIFIER);
        
        OAuthKeyInfo key = getGlobalConfiguration().getOauthKeyByKeyIdentifier(kid);
        
        if (key != null) {
            log.info("Detailed information about Trusted OAuth Provider with key identifier " + kid);
            log.info("Label: " + key.getLabel());
            log.info("Skew limit: " + key.getSkewLimit());
            log.info("Public key fingerprint: " + key.getKeyFingerprint());
            log.info("Url: " + key.getUrl());
            log.info("Realm: " + key.getRealm());
            log.info("Client: " + key.getClient());
            // The line below has to be uncommented after ECA-9788 is merged to epic branch
            //log.info("Client secret: " + key.getClientSecret());
        }

        return CommandResult.SUCCESS;
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
