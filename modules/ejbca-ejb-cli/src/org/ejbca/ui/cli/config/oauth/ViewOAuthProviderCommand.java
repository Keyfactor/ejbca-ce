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
import org.cesecore.authentication.oauth.OAuthPublicKey;
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
    
    private static final String LABEL = "--label";
    
    {
        registerParameter(new Parameter(LABEL, "Provider name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Label of the Trusted OAuth Provider."));
    }

    @Override
    public String getMainCommand() {
        return "viewoauthprovider";
    }

    @Override
    public String getCommandDescription() {
        return "Displays information about the specified Trusted OAuth Provider available in EJBCA";
    }

    @Override 
    protected CommandResult execute(ParameterContainer parameters) {
        String label = parameters.get(LABEL);
        OAuthKeyInfo info = getOAuthConfiguration().getOauthKeyByLabel(label);
        
        if (info != null) {
            log.info("Label: " + info.getLabel());
            if (info.getType() != null) {
                log.info("Type: " + info.getType().getLabel());
            }
            log.info("Skew Limit: " + info.getSkewLimit());
            if (info.getKeyValues() != null) {
                for (OAuthPublicKey publicKey : info.getKeyValues()) {
                    log.info("Public Key Identifier: " + publicKey.getKeyIdentifier() + " | Public Key Fingerprint: " + publicKey.getKeyFingerprint());
                }
            }
            log.info("URL: " + info.getUrl());
            log.info("Audience: " + info.getAudience());
            if (info.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_KEYCLOAK)) {
                log.info("Realm: " + info.getRealm());
            }
            if (info.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_AZURE)) {
                log.info("Tenant: " + info.getRealm());
                log.info("Scope: " + info.getScope());
                Integer keyBindingId = info.getKeyBinding();
                if (keyBindingId != null) {
                    log.info("Key Binding: " + keyBindingIdToName(keyBindingId).orElse("not found"));
                }
            }
            if (info.getType().equals(OAuthKeyInfo.OAuthProviderType.TYPE_PINGID)) {
                log.info("Token URL: " + info.getTokenUrl());
                log.info("Logout URL: " + info.getLogoutUrl());
            }
            log.info("Client: " + info.getClient());
        } else {
            log.info("An OAuth Provider with the label " + label + " was not found.");
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
