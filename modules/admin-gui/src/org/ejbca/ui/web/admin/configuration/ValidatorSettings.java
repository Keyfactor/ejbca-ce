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

package org.ejbca.ui.web.admin.configuration;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.validation.ExternalScriptsWhitelist;
import org.ejbca.config.GlobalConfiguration;

/**
 * This class is responsible for managing the configuration shown under the "Validators" tab
 * in System Configuration.
 */
public class ValidatorSettings {
    
    public interface ValidatorSettingsHelper {
        GlobalConfiguration getGlobalConfiguration();
        void addErrorMessage(final String languageKey, final Object... params);
        void addInfoMessage(final String languageKey);
        void persistConfiguration(final GlobalConfiguration globalConfiguration) throws AuthorizationDeniedException;
    }

    private final static Logger log = Logger.getLogger(ValidatorSettings.class);
    private final ValidatorSettingsHelper validatorSettingsHelper;
    private ArrayList<String> validationResult = new ArrayList<>();
    private String externalScriptsWhitelist;
    private boolean isExternalScriptsEnabled;
    private boolean isExternalScriptsWhitelistEnabled;

    public ValidatorSettings(final ValidatorSettingsHelper validatorSettingsHelper) {
        this.validatorSettingsHelper = validatorSettingsHelper;
        this.externalScriptsWhitelist = validatorSettingsHelper.getGlobalConfiguration().getExternalScriptsWhitelist();
        this.isExternalScriptsEnabled = validatorSettingsHelper.getGlobalConfiguration().getEnableExternalScripts();
        this.isExternalScriptsWhitelistEnabled = validatorSettingsHelper.getGlobalConfiguration().getIsExternalScriptsWhitelistEnabled();
    }

    public boolean getIsExternalScriptsEnabled() {
        return isExternalScriptsEnabled;
    }

    public void setIsExternalScriptsEnabled(final boolean isExternalScriptsEnabled) {
        this.isExternalScriptsEnabled = isExternalScriptsEnabled;
    }

    public String getExternalScriptsWhitelist() {
        return externalScriptsWhitelist;
    }

    public void setExternalScriptsWhitelist(final String value) {
        this.externalScriptsWhitelist = value;
    }

    public boolean getIsExternalScriptsWhitelistEnabled() {
        return isExternalScriptsWhitelistEnabled;
    }

    public void setIsExternalScriptsWhitelistEnabled(final boolean value) {
        this.isExternalScriptsWhitelistEnabled = value;
    }

    public void save() {
        try {
            final ExternalScriptsWhitelist whitelist = ExternalScriptsWhitelist.fromText(externalScriptsWhitelist, isExternalScriptsWhitelistEnabled);
            if (log.isDebugEnabled()) {
                log.debug("Saving whitelist of permitted scripts: " + whitelist.getScriptsPaths());
            }
            if (isExternalScriptsWhitelistEnabled && whitelist.hasInvalidPaths()) {
                log.info(
                        "Unable to save (enabled) whitelist containing external scripts permitted to be used in External Command Validators. One or file paths are invalid.");
                validatorSettingsHelper.addErrorMessage("EXTERNAL_SCRIPTS_SAVE_FAILED");
                return;
            }
            final GlobalConfiguration globalConfiguration = validatorSettingsHelper.getGlobalConfiguration();
            globalConfiguration.setEnableExternalScripts(isExternalScriptsEnabled);
            globalConfiguration.setExternalScriptsWhitelist(externalScriptsWhitelist);
            globalConfiguration.setIsExternalScriptsWhitelistEnabled(isExternalScriptsWhitelistEnabled);
            validatorSettingsHelper.persistConfiguration(globalConfiguration);
            validatorSettingsHelper.addInfoMessage("EXTERNAL_SCRIPTS_SAVED");
        } catch (final AuthorizationDeniedException e) {
            log.warn("Unable to save configuration, because authorization was denied.", e);
            validatorSettingsHelper.addErrorMessage("EXTERNAL_SCRIPTS_SAVE_FAILED", e.getMessage());
        }
    }

    public void validateScripts() {
        final ExternalScriptsWhitelist whitelist = ExternalScriptsWhitelist.fromText(externalScriptsWhitelist);
        final List<String> validationMessages = new ArrayList<>();
        for (final Entry<File, String> validationEntry : whitelist.validateScripts().entrySet()) {
            if (validationEntry.getValue() == null) {
                // No problem detected
                continue;
            }
            validationMessages
                    .add(String.format("Script %s has the following problem: %s", validationEntry.getKey().getPath(), validationEntry.getValue()));
        }
        validationResult.clear();
        validationResult.add(whitelist.size() + " scripts have been checked. " + validationMessages.size() + " problems were detected.");
        validationResult.addAll(validationMessages);
    }

    /**
     * Returns a list of strings containing the output of the latest invocation to {@link #validateScripts()}.
     * @return a list of validation messages
     */
    public List<String> getValidationResult() {
        return validationResult;
    }
}
