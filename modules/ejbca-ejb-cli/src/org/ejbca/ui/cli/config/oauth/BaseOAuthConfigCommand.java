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

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateParsingException;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.ui.cli.config.ConfigBaseCommand;

/**
 * 
 *
 */
public abstract class BaseOAuthConfigCommand extends ConfigBaseCommand {
    
    private static final Logger log = Logger.getLogger(BaseOAuthConfigCommand.class);

    private GlobalConfiguration globalConfiguration = null;

    @Override
    public String[] getCommandPath() {
        return new String[] { super.getCommandPath()[0] , "oauth" };
    }
    
    protected GlobalConfiguration getGlobalConfiguration() {
        if (globalConfiguration == null) {
            globalConfiguration = (GlobalConfiguration) getGlobalConfigurationSession().getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        }
        return globalConfiguration;
    }
    
    protected boolean saveGlobalConfig() {
        try {
            getGlobalConfigurationSession().saveConfigurationWithRootAccessCheck(getAuthenticationToken(), getGlobalConfiguration());
            getGlobalConfigurationSession().flushConfigurationCache(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            return true;
        } catch (AuthorizationDeniedException e) {
            return false;
        }
    }
    
    protected byte[] getOauthKeyPublicKey(final String publicKey) {
        try {
            byte[] uploadedFileBytes = Files.readAllBytes(Paths.get(publicKey));
            return KeyTools.getBytesFromPublicKeyFile(uploadedFileBytes);
        } catch (final CertificateParsingException e) {
            log.info("Could not parse the public key file.", e);
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        } catch (final Exception e) {
            log.info("Failed to add OAuth Key.", e);
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
    }
    
    protected boolean canAdd(final OAuthKeyInfo oauthKey) {
        for (OAuthKeyInfo existingKeyInfo : getGlobalConfiguration().getOauthKeys().values()) {
            final boolean hasSameInternalId = existingKeyInfo.getInternalId() == oauthKey.getInternalId();
            final boolean hasSameKeyIdentifier = StringUtils.equals(existingKeyInfo.getKeyIdentifier(), oauthKey.getKeyIdentifier());
            if (hasSameInternalId || hasSameKeyIdentifier) {
                return false;
            }
        }
        return true;
    }
    
    protected boolean canEditKid(final String kid) {
        for (OAuthKeyInfo existingKeyInfo : getGlobalConfiguration().getOauthKeys().values()) {
            final boolean hasSameKeyIdentifier = StringUtils.equals(existingKeyInfo.getKeyIdentifier(), kid);
            if (hasSameKeyIdentifier) {
                return false;
            }
        }
        return true;
    }
    
    
    protected int validateSkewLimit(final String skewLimit) {
        int skewLimitInt = 0;
        try {
            skewLimitInt  = Integer.parseInt(skewLimit);
        } catch (NumberFormatException e) {
            return -1;
        }

        if(skewLimitInt < 0 || skewLimitInt > Integer.MAX_VALUE) {
            return -1;
        }
        
        return skewLimitInt;
    }
    
}
