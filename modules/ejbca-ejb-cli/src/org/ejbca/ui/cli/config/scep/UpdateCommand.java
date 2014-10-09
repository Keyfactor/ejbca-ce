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
package org.ejbca.ui.cli.config.scep;

import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * @version $Id$
 *
 */
public class UpdateCommand extends BaseScepConfigCommand {

    private static final String ALIAS_KEY = "--alias";
    private static final String KEY_KEY = "--key"; //Hue hue hue
    private static final String VALUE_KEY = "--value";

    private static final Logger log = Logger.getLogger(UpdateCommand.class);

    {
        registerParameter(new Parameter(ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The alias of the configuration to update."));
        registerParameter(new Parameter(KEY_KEY, "Key", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The alias of the configuration to update."));
        registerParameter(new Parameter(VALUE_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The alias of the configuration to update."));
    }

    @Override
    public String getMainCommand() {
        return "updatealias";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String alias = parameters.get(ALIAS_KEY);
        String key = parameters.get(KEY_KEY);
        String value = parameters.get(VALUE_KEY);
        ScepConfiguration scepConfig = getScepConfiguration();
        List<String> bkeys = ScepConfiguration.SCEP_BOOLEAN_KEYS;
        
        if(StringUtils.equals(key, ScepConfiguration.SCEP_RAMODE_OLD) || StringUtils.equals(key, ScepConfiguration.SCEP_OPERATIONMODE)) {
            key = alias + "." + ScepConfiguration.SCEP_OPERATIONMODE;
            value = !StringUtils.equalsIgnoreCase(value, "ra") ? "ca" : "ra";
        } else {
            if (bkeys.contains(key)) {
                value = Boolean.toString(StringUtils.equalsIgnoreCase(value, "true"));
            }
            key = alias + "." + key;
        }
        
        log.info("Configuration was: " + key + "=" + scepConfig.getValue(key, alias));
        scepConfig.setValue(key, value, alias);
        try {
            getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(), scepConfig);
            log.info("Configuration updated: " + key + "=" + getScepConfiguration().getValue(key, alias));
            getGlobalConfigurationSession().flushConfigurationCache(ScepConfiguration.SCEP_CONFIGURATION_ID);
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.info("Failed to update configuration: " + e.getLocalizedMessage());
            return CommandResult.AUTHORIZATION_FAILURE;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Updates one configuration value.";
    }

    @Override
    public String getFullHelpText() {
        final String divider = " | ";
        
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\n");
        sb.append("The key could be any of the following:\n");
        
        sb.append("    " + ScepConfiguration.SCEP_OPERATIONMODE + " - possible values: ca " + divider + " ra" + "\n");
        sb.append("    " + ScepConfiguration.SCEP_INCLUDE_CA + " - possible values: true " + divider + " false" + "\n");
        

        Map<Integer, String> endentityprofileidtonamemap = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class)
                .getEndEntityProfileIdToNameMap();
        StringBuilder existingEeps = new StringBuilder();
        for (Integer profileId : EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(
                getAuthenticationToken())) {
            existingEeps.append((existingEeps.length() == 0 ? "" : divider) + endentityprofileidtonamemap.get(profileId));
        }
        sb.append("    " + ScepConfiguration.SCEP_RA_ENTITYPROFILE + " - possible values: " + existingEeps + "\n");
        
        Map<Integer, String> certificateprofileidtonamemap = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                .getCertificateProfileIdToNameMap();
        StringBuilder existingCps = new StringBuilder();
        for (Integer profileId : EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getAuthorizedCertificateProfileIds(
                getAuthenticationToken(), CertificateConstants.CERTTYPE_ENDENTITY)) {
            existingCps.append((existingCps.length() == 0 ? "" : divider) + certificateprofileidtonamemap.get(profileId));
        }
        sb.append("    " + ScepConfiguration.SCEP_RA_CERTPROFILE + " - possible values: ProfileDefault" + divider + existingCps + "\n");
        
        StringBuilder existingCas = new StringBuilder();
        for (String ca : EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getActiveCANames(getAuthenticationToken())) {
            existingCas.append((existingCas.length() == 0 ? "" : divider) + ca);
        }
        sb.append("    " + ScepConfiguration.SCEP_RA_DEFAULTCA + " - possible values: ProfileDefault" + divider + existingCas + "\n");
        
        sb.append("    " + ScepConfiguration.SCEP_RA_AUTHPWD + " - possible values: none " + divider + " any alphanumeric string" + "\n");
        sb.append("    " + ScepConfiguration.SCEP_RA_NAME_GENERATION_SCHEME + " - possible values: DN " + divider + " RANDOM " + divider + " USERNAME " + divider + " FIXED" + "\n");
        sb.append("    " + ScepConfiguration.SCEP_RA_NAME_GENERATION_PARAMETERS + " - possible values: See CMP Configurations in the Admin GUI" + "\n");
        sb.append("    " + ScepConfiguration.SCEP_RA_NAME_GENERATION_PREFIX + " - possible values: ${RANDOM} " + divider + " any alphanumeric string" + "\n");
        sb.append("    " + ScepConfiguration.SCEP_RA_NAME_GENERATION_POSTFIX + " - possible values: ${RANDOM} " + divider + " any alphanumeric string" + "\n");
        
        return sb.toString();

    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
