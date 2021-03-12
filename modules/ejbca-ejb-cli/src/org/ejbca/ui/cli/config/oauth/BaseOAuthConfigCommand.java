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
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.ui.cli.config.ConfigBaseCommand;

/**
 * 
 *
 */
public abstract class BaseOAuthConfigCommand extends ConfigBaseCommand {
    
    private static final Logger log = Logger.getLogger(BaseOAuthConfigCommand.class);

    private OAuthConfiguration oAuthConfiguration = null;

    @Override
    public String[] getCommandPath() {
        return new String[] { super.getCommandPath()[0] , "oauth" };
    }
    
    protected OAuthConfiguration getOAuthConfiguration() {
        if (oAuthConfiguration == null) {
            oAuthConfiguration = (OAuthConfiguration) getGlobalConfigurationSession().getCachedConfiguration(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
        }
        return oAuthConfiguration;
    }
    
    protected boolean saveGlobalConfig() {
        try {
            getGlobalConfigurationSession().saveConfigurationWithRootAccessCheck(getAuthenticationToken(), getOAuthConfiguration());
            getGlobalConfigurationSession().flushConfigurationCache(OAuthConfiguration.OAUTH_CONFIGURATION_ID);
            return true;
        } catch (AuthorizationDeniedException e) {
            return false;
        }
    }
    
    protected byte[] getOauthKeyPublicKey(final String publicKey) {
        byte[] uploadedFileBytes = null;
        try {
            uploadedFileBytes = Files.readAllBytes(Paths.get(publicKey));
            return KeyTools.getBytesFromPublicKeyFile(uploadedFileBytes);
        } catch (final CertificateParsingException e) {
            try {
                final Certificate certificate = CertTools.getCertfromByteArray(uploadedFileBytes, Certificate.class);
                if (certificate == null || certificate.getPublicKey() == null) {
                    log.info("Could not parse the certificate file.");
                    return ArrayUtils.EMPTY_BYTE_ARRAY;
                }
                return certificate.getPublicKey().getEncoded();
            } catch (CertificateParsingException exception) {
                log.info("Could not parse the certificate file.", exception);
            }
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        } catch (final Exception e) {
            log.info("Failed to add Public Key.", e);
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
    }
    
    protected boolean canAdd(final OAuthKeyInfo oauthKey) {
        for (OAuthKeyInfo existingKeyInfo : getOAuthConfiguration().getOauthKeys().values()) {
            final boolean hasSameLabel = StringUtils.equals(existingKeyInfo.getLabel(), oauthKey.getLabel());
            if (hasSameLabel) {
                return false;
            }
        }
        return true;
    }
    
    protected boolean canEditLabel(final String label) {
        for (OAuthKeyInfo existingKeyInfo : getOAuthConfiguration().getOauthKeys().values()) {
            final boolean hasSameLabel = StringUtils.equals(existingKeyInfo.getLabel(), label);
            if (hasSameLabel) {
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
