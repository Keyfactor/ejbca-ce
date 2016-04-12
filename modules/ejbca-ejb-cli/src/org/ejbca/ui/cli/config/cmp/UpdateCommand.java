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
package org.ejbca.ui.cli.config.cmp;

import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.authorization.AccessRulesConstants;
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
public class UpdateCommand extends BaseCmpConfigCommand {

    private static final String ALIAS_KEY = "--alias";
    private static final String KEY_KEY = "--key"; //Hue hue hue
    private static final String VALUE_KEY = "--value";

    private static final Logger log = Logger.getLogger(UpdateCommand.class);

    {
        registerParameter(new Parameter(ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The alias of the configuration to update."));
        registerParameter(new Parameter(KEY_KEY, "Key", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The key of the configuration to update (alias not included)."));
        registerParameter(new Parameter(VALUE_KEY, "Value", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The new value of the configuration to update."));
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
        List<String> bkeys = CmpConfiguration.CMP_BOOLEAN_KEYS;

        if (StringUtils.equals(key, CmpConfiguration.CONFIG_OPERATIONMODE)) {
            if (!StringUtils.equalsIgnoreCase(value, "ra")) {
                value = "client";
            }
        } else if (bkeys.contains(key)) {
            value = Boolean.toString(StringUtils.equalsIgnoreCase(value, "true"));
        }

        key = alias + "." + key;
        log.info("Configuration was: " + key + "=" + getCmpConfiguration().getValue(key, alias));
        getCmpConfiguration().setValue(key, value, alias);
        try {
            getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(), getCmpConfiguration());
            log.info("Configuration updated: " + key + "=" + getCmpConfiguration().getValue(key, alias));
            getGlobalConfigurationSession().flushConfigurationCache(CmpConfiguration.CMP_CONFIGURATION_ID);
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
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\n");
        sb.append("The key could be any of the following:\n");
        StringBuilder existingCas = new StringBuilder();
        final String divider = " | ";
        for (String ca : EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getActiveCANames(getAuthenticationToken())) {
            existingCas.append((existingCas.length() == 0 ? "" : divider) + ca);
        }
        sb.append("    " + CmpConfiguration.CONFIG_DEFAULTCA + " - possible values: " + existingCas + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO + " - possible values: true | false" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_OPERATIONMODE + " - possible values: client | ra" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_AUTHENTICATIONMODULE
                + " - possible values: RegTokenPwd | DnPartPwd | HMAC | EndEntityCertificate | a combination of those methods separated by ';'" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS + " - possible values: See documentation in Admin Guid" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_EXTRACTUSERNAMECOMPONENT
                + " - possible values: DN | any SubjectDN attribut tex. CN, OU, UID...etc" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RA_ALLOWCUSTOMCERTSERNO + " - possible values: true | false" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME + " - possible values: DN | RANDOM | USERNAME | FIXED" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS + " - possible values: See documentation in Admin Guid" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONPREFIX + " - possible values: ${RANDOM} | any alphanumeric string" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONPOSTFIX + " - possible values: ${RANDOM} | any alphanumeric string" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RA_PASSWORDGENPARAMS + " - possible values: random | any alphanumeric string" + "\n");
        Map<Integer, String> endentityprofileidtonamemap = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class)
                .getEndEntityProfileIdToNameMap();
        StringBuilder existingEeps = new StringBuilder();
        for (Integer profileId : EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(
                getAuthenticationToken(), AccessRulesConstants.CREATE_END_ENTITY)) {
            existingEeps.append((existingEeps.length() == 0 ? "" : divider) + profileId + " (" + endentityprofileidtonamemap.get(profileId) + ")");
        }
        sb.append("    " + CmpConfiguration.CONFIG_RA_ENDENTITYPROFILEID + " - available IDs: " + existingEeps + "\n");
        Map<Integer, String> certificateprofileidtonamemap = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                .getCertificateProfileIdToNameMap();
        StringBuilder existingCps = new StringBuilder();
        for (Integer profileId : EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getAuthorizedCertificateProfileIds(
                getAuthenticationToken(), CertificateConstants.CERTTYPE_ENDENTITY)) {
            existingCps.append((existingCps.length() == 0 ? "" : " | ") + certificateprofileidtonamemap.get(profileId));
        }
        sb.append("    " + CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE + " - possible values: ProfileDefault | " + existingCps + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RACANAME + " - possible values: ProfileDefault | " + existingCas + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_RESPONSEPROTECTION + " - possible values: signature | pbe" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_VENDORCERTIFICATEMODE + " - possible values: true | false" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_VENDORCA + " - possible values: the name of the external CA. Several CAs can be specified by separating them with ';'" + "\n");
        sb.append("    "
                + CmpConfiguration.CONFIG_RACERT_PATH
                + " - possible values: the path to the catalogue where the certificate that will be used to authenticate NestedMessageContent are stored."
                + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE + " - possible values: true | false" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY + " - possible values: true | false" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_CERTREQHANDLER_CLASS
                + " - possible values: org.ejbca.core.protocol.unid.UnidFnrHandler | your own implementation of this class" + "\n");
        sb.append("    " + CmpConfiguration.CONFIG_UNIDDATASOURCE + " - possible values: java:/UnidDS | your own unid data source" + "\n");
        return sb.toString();

    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
