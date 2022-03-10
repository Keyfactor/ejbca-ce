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
import java.util.List;
import java.util.Optional;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.oauth.OAuthKeyInfo;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
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
    
    protected byte[] getFileBytes(final String filename) {
        try {
            return Files.readAllBytes(Paths.get(filename));
        } catch (final Exception e) {
            log.info("Failed to read Public Key file.", e);
            return ArrayUtils.EMPTY_BYTE_ARRAY;
        }
    }
    
    protected boolean canAdd(final OAuthKeyInfo oauthKey) {
        for (OAuthKeyInfo existingKeyInfo : getOAuthConfiguration().getOauthKeys().values()) {
            final boolean hasSameInternalId = ObjectUtils.equals(existingKeyInfo.getInternalId(), oauthKey.getInternalId());
            final boolean hasSameLabel = StringUtils.equals(existingKeyInfo.getLabel(), oauthKey.getLabel());
            if (hasSameInternalId || hasSameLabel) {
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

    /**
     * Given a key binding name, return its ID if found.
     */
    protected Optional<Integer> keyBindingNameToId(String keyBindingName) {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final List<InternalKeyBindingInfo> internalKeyBindings = internalKeyBindingMgmtSession.getInternalKeyBindingInfos(getAuthenticationToken(),
                null);
        return internalKeyBindings.stream().filter(b -> b.getName().equals(keyBindingName)).map(InternalKeyBindingInfo::getId).findFirst();
    }

    /**
     * Given a key binding id, return its name if found.
     */
    protected Optional<String> keyBindingIdToName(Integer keyBindingId) {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final List<InternalKeyBindingInfo> internalKeyBindings = internalKeyBindingMgmtSession.getInternalKeyBindingInfos(getAuthenticationToken(),
                null);
        return internalKeyBindings.stream().filter(b -> b.getId() == keyBindingId).map(InternalKeyBindingInfo::getName).findFirst();
    }
    
}
