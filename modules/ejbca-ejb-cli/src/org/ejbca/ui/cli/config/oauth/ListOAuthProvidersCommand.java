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

import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * 
 *
 */
public class ListOAuthProvidersCommand extends BaseOAuthConfigCommand {
    
    private static final Logger log = Logger.getLogger(ListOAuthProvidersCommand.class);

    @Override
    public String getMainCommand() {
        return "listoauthproviders";
    }

    @Override
    public String getCommandDescription() {
        return "Lists the current oauth providers available in EJBCA";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        Collection<OAuthKeyInfo> oauthKeys = getGlobalConfiguration().getOauthKeys().values();
        OAuthKeyInfo defaultKey = getGlobalConfiguration().getDefaultOauthKey();
        
        for (OAuthKeyInfo keyInfo : oauthKeys) {
            log.info("Kid: "  + keyInfo.getKeyIdentifier() + " | skew limit: " + keyInfo.getSkewLimit() + " | publickey fingerprint: " + keyInfo.getKeyFingerprint());
        }
        if (defaultKey != null) {
            log.info("Default OAuth Provider kid: " + defaultKey.getKeyIdentifier());
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
