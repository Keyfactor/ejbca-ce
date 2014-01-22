/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli.config;

import java.io.File;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Shows the current server configuration
 * 
 * @version $Id$
 */
public class CmpConfigCommand extends ConfigBaseCommand {

    private CmpConfiguration cmpConfiguration = null;

    private static final String DUMPALLCONFIG = "dumpall";
    private static final String DUMPALIASCONFIG = "dumpalias";
    private static final String LISTALIAS = "listalias";
    private static final String ADDALIAS = "addalias";
    private static final String REMOVEALIAS = "removealias";
    private static final String RENAMEALIAS = "renamealias";
    private static final String UPDATEONECONFIG = "updateconfig";
    private static final String UPLOADFILE = "uploadfile";

    @Override
    public String getSubCommand() {
        return "cmp";
    }

    @Override
    public String getDescription() {
        return "Edit CMP configuration";
    }

    private CmpConfiguration getCmpConfiguration() {
        if (cmpConfiguration == null) {
            cmpConfiguration = (CmpConfiguration) getGlobalConfigurationSession().getCachedConfiguration(Configuration.CMPConfigID);
        }
        return cmpConfiguration;
    }

    /**
     * Tries to fetch the server properties and dumps them to standard out
     */
    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {

        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }

        if (args.length < 2) {
            getLogger().info("Available subcommands for '" + getSubCommand() + "':");
            printAvailableCommands();
            return;
        }

        String subsubcommand = args[1];
        if (StringUtils.equalsIgnoreCase(subsubcommand, DUMPALLCONFIG)) {
            try {
                Properties properties = getGlobalConfigurationSession().getAllProperties(getAuthenticationToken(cliUserName, cliPassword),
                        Configuration.CMPConfigID);
                Enumeration<Object> enumeration = properties.keys();
                while (enumeration.hasMoreElements()) {
                    String key = (String) enumeration.nextElement();
                    getLogger().info(" " + key + " = " + properties.getProperty(key));
                }
            } catch (Exception e) {
                throw new ErrorAdminCommandException(e);
            }
        } else if (StringUtils.equalsIgnoreCase(subsubcommand, DUMPALIASCONFIG)) {
            if (args.length < 3) {
                getLogger().info("Description: shows the current CMP configuration for one alias");
                getLogger().info("Usage: config cmp " + DUMPALIASCONFIG + " <alias>");
                return;
            }
            String alias = args[2];
            try {
                Properties properties = getCmpConfiguration().getAsProperties(alias);
                if (properties != null) {
                    Enumeration<Object> enumeration = properties.keys();
                    while (enumeration.hasMoreElements()) {
                        String key = (String) enumeration.nextElement();
                        getLogger().info(" " + key + " = " + properties.getProperty(key));
                    }
                } else {
                    getLogger().info("Could not find alias: " + alias);
                }
            } catch (Exception e) {
                throw new ErrorAdminCommandException(e);
            }
        } else if (StringUtils.equals(subsubcommand, LISTALIAS)) {
            Set<String> aliaslist = getCmpConfiguration().getAliasList();
            Iterator<String> itr = aliaslist.iterator();
            while (itr.hasNext()) {
                getLogger().info(itr.next());
            }

        } else if (StringUtils.equals(subsubcommand, ADDALIAS)) {
            if (args.length < 3) {
                getLogger().info("Description: Adds a CMP configuration alias");
                getLogger().info("Usage: config cmp " + ADDALIAS + " <alias>");
                return;
            }

            String alias = args[2];
            // We check first because it is unnecessary to call saveConfiguration when it is not needed
            if (getCmpConfiguration().aliasExists(alias)) {
                getLogger().info("Alias '" + alias + "' already exists.");
                return;
            }

            getCmpConfiguration().addAlias(alias);
            try {
                getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(cliUserName, cliPassword), getCmpConfiguration(),
                        Configuration.CMPConfigID);
                getLogger().info("Added CMP alias: " + alias);
                getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            } catch (AuthorizationDeniedException e) {
                getLogger().info("Failed to add alias '" + alias + "': " + e.getLocalizedMessage());
                return;
            }

        } else if (StringUtils.equalsIgnoreCase(subsubcommand, REMOVEALIAS)) {
            if (args.length < 3) {
                getLogger().info("Description: Removes a CMP configuration alias");
                getLogger().info("Usage: config cmp " + REMOVEALIAS + " <alias>");
                return;
            }

            String alias = args[2];
            // We check first because it is unnecessary to call saveConfiguration when it is not needed
            if (!getCmpConfiguration().aliasExists(alias)) {
                getLogger().info("Alias '" + alias + "' does not exist");
                return;
            }

            getCmpConfiguration().removeAlias(alias);
            try {
                getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(cliUserName, cliPassword), getCmpConfiguration(),
                        Configuration.CMPConfigID);
                getLogger().info("Removed CMP alias: " + alias);
                getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            } catch (AuthorizationDeniedException e) {
                getLogger().info("Failed to remove alias '" + alias + "': " + e.getLocalizedMessage());
                return;
            }

        } else if (StringUtils.equalsIgnoreCase(subsubcommand, RENAMEALIAS)) {
            if (args.length < 4) {
                getLogger().info("Description: Renames a CMP configuration alias");
                getLogger().info("Usage: config cmp " + RENAMEALIAS + " <oldalias> <newalias>");
                return;
            }

            String oldalias = args[2];
            String newalias = args[3];
            // We check first because it is unnecessary to call saveConfiguration when it is not needed
            if (!getCmpConfiguration().aliasExists(oldalias)) {
                getLogger().info("Alias '" + oldalias + "' does not exist");
                return;
            }

            getCmpConfiguration().renameAlias(oldalias, newalias);
            try {
                getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(cliUserName, cliPassword), getCmpConfiguration(),
                        Configuration.CMPConfigID);
                getLogger().info("Renamed CMP alias '" + oldalias + "' to '" + newalias + "'");
                getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            } catch (AuthorizationDeniedException e) {
                getLogger().info("Failed to rename alias '" + oldalias + "' to '" + newalias + "': " + e.getLocalizedMessage());
                return;
            }
        } else if (StringUtils.equals(subsubcommand, UPDATEONECONFIG)) {
            if (args.length < 5) {
                printUpdateUsage();
                return;
            }
            String alias = args[2];
            String key = args[3];
            String value = args[4];
            List<String> bkeys = CmpConfiguration.CMP_BOOLEAN_KEYS;

            if (StringUtils.equals(key, CmpConfiguration.CONFIG_OPERATIONMODE)) {
                if (!StringUtils.equalsIgnoreCase(value, "ra")) {
                    value = "client";
                }
            } else if (bkeys.contains(key)) {
                value = Boolean.toString(StringUtils.equalsIgnoreCase(value, "true"));
            }

            key = alias + "." + key;
            getLogger().info("Configuration was: " + key + "=" + getCmpConfiguration().getValue(key, alias));
            getCmpConfiguration().setValue(key, value, alias);
            try {
                getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(cliUserName, cliPassword), getCmpConfiguration(),
                        Configuration.CMPConfigID);
                getLogger().info("Configuration updated: " + key + "=" + getCmpConfiguration().getValue(key, alias));
                getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            } catch (AuthorizationDeniedException e) {
                getLogger().info("Failed to update configuration: " + e.getLocalizedMessage());
                return;
            }

        } else if (StringUtils.equals(subsubcommand, UPLOADFILE)) {

            if (args.length < 4) {
                printUploadUsage();
                return;
            }

            String filename = args[2];
            String alias = args[3];

            CompositeConfiguration config = null;
            File f = null;
            try {
                f = new File(filename);
                final PropertiesConfiguration pc = new PropertiesConfiguration(f);
                pc.setReloadingStrategy(new FileChangedReloadingStrategy());
                config = new CompositeConfiguration();
                config.addConfiguration(pc);
                getLogger().info("Reading CMP configuration from file: " + f.getAbsolutePath());
            } catch (ConfigurationException e) {
                getLogger().error("Failed to load configuration from file " + f.getAbsolutePath());
                return;
            }

            readConfigurations(config, alias);

        } else {
            getLogger().error("Unknow command");
            printAvailableCommands();
            return;
        }

    }

    private void readConfigurations(CompositeConfiguration config, String alias) {

        // if the alias does not already exist, create it.
        getCmpConfiguration().addAlias(alias);

        // Reading all relevant configurations from file.
        boolean populated = false;
        Set<String> keys = CmpConfiguration.getAllAliasKeys(alias);
        Iterator<String> itr = keys.iterator();
        while (itr.hasNext()) {
            String key = itr.next();
            if (config.containsKey(key)) {
                populated = true;
                String value = config.getString(key);
                getCmpConfiguration().setValue(key, value, alias);
                getLogger().info("Setting value: " + key + "=" + value);
            }
        }

        // Save the new configurations.
        if (populated) {
            try {
                getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(cliUserName, cliPassword), getCmpConfiguration(),
                        Configuration.CMPConfigID);
                getLogger().info("\nNew configurations saved successfully.");
                getLogger().info("If there are any issues with the configurations, check them in the AdminGUI and click 'Save'");
                getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            } catch (AuthorizationDeniedException e) {
                getLogger().error("Failed to save configuration from file: " + e.getLocalizedMessage());
            }
        } else {
            getCmpConfiguration().removeAlias(alias);
            getLogger().info("No relevent CMP configurations found with alias '" + alias + "' in the file.");
        }
    }

    private void printAvailableCommands() {
        getLogger().info(String.format("  %-20s %s", DUMPALLCONFIG, "Shows all current CMP configuration"));
        getLogger().info(String.format("  %-20s %s", DUMPALIASCONFIG, "Shows the current CMP configuration for one alias"));
        getLogger().info(String.format("  %-20s %s", LISTALIAS, "Lists all existing CMP configuration aliases"));
        getLogger().info(String.format("  %-20s %s", ADDALIAS, "Adds a CMP configuration alias with default values"));
        getLogger().info(String.format("  %-20s %s", REMOVEALIAS, "Removes a CMP configuration alias"));
        getLogger().info(String.format("  %-20s %s", RENAMEALIAS, "Renames a CMP configuration alias"));
        getLogger().info(String.format("  %-20s %s", UPDATEONECONFIG, "Updates one configuration value"));
        getLogger().info(String.format("  %-20s %s", UPLOADFILE, "Reads CMP configuration from a file"));
    }

    private void printUpdateUsage() {
        getLogger().info("Description: Updates one configuration value");
        getLogger().info("Usage: cmp updateconfig <alias> <key> <value>");
        getLogger().info("The alias should be an existing CMP configration alias");
        getLogger().info("The key could be any of the following:");

        Collection<String> canames = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAvailableCANames(
                getAuthenticationToken(cliUserName, cliPassword));
        String existingCas = "";
        Iterator<String> itrname = canames.iterator();
        while (itrname.hasNext()) {
            existingCas += (existingCas.length() == 0 ? "" : " | ") + itrname.next();
        }
        getLogger().info("    " + CmpConfiguration.CONFIG_DEFAULTCA + " - possible values: " + existingCas);
        getLogger().info("    " + CmpConfiguration.CONFIG_ALLOWRAVERIFYPOPO + " - possible values: true | false");
        getLogger().info("    " + CmpConfiguration.CONFIG_OPERATIONMODE + " - possible values: client | ra");
        getLogger().info(
                "    " + CmpConfiguration.CONFIG_AUTHENTICATIONMODULE
                        + " - possible values: RegTokenPwd | DnPartPwd | HMAC | EndEntityCertificate | a combination of those methods");
        getLogger().info("    " + CmpConfiguration.CONFIG_AUTHENTICATIONPARAMETERS + " - possible values: See documentation in Admin Guid");
        getLogger().info(
                "    " + CmpConfiguration.CONFIG_EXTRACTUSERNAMECOMPONENT + " - possible values: DN | any SubjectDN attribut tex. CN, OU, UID...etc");
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_ALLOWCUSTOMCERTSERNO + " - possible values: true | false");
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONSCHEME + " - possible values: DN | RANDOM | USERNAME | FIXED");
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONPARAMS + " - possible values: See documentation in Admin Guid");
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONPREFIX + " - possible values: ${RANDOM} | any alphanumeric string");
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_NAMEGENERATIONPOSTFIX + " - possible values: ${RANDOM} | any alphanumeric string");
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_PASSWORDGENPARAMS + " - possible values: random | any alphanumeric string");

        Collection<Integer> endentityprofileids = ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(
                getAuthenticationToken(cliUserName, cliPassword));
        Map<Integer, String> endentityprofileidtonamemap = ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileIdToNameMap();
        String existingEeps = "";
        Iterator<Integer> itr = endentityprofileids.iterator();
        while (itr.hasNext()) {
            existingEeps += (existingEeps.length() == 0 ? "" : " | ") + endentityprofileidtonamemap.get(itr.next());
        }
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_ENDENTITYPROFILE + " - possible values: " + existingEeps);

        Collection<Integer> caids = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCAs(
                getAuthenticationToken(cliUserName, cliPassword));
        Collection<Integer> certprofileids = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getAuthorizedCertificateProfileIds(
                CertificateConstants.CERTTYPE_ENDENTITY, caids);
        Map<Integer, String> certificateprofileidtonamemap = ejb.getRemoteSession(CertificateProfileSessionRemote.class)
                .getCertificateProfileIdToNameMap();
        String existingCps = "";
        itr = certprofileids.iterator();
        while (itr.hasNext()) {
            existingCps += (existingCps.length() == 0 ? "" : " | ") + certificateprofileidtonamemap.get(itr.next());
        }
        getLogger().info("    " + CmpConfiguration.CONFIG_RA_CERTIFICATEPROFILE + " - possible values: ProfileDefault | " + existingCps);
        getLogger().info("    " + CmpConfiguration.CONFIG_RACANAME + " - possible values: ProfileDefault | " + canames);
        getLogger().info("    " + CmpConfiguration.CONFIG_RESPONSEPROTECTION + " - possible values: signature | pbe");
        getLogger().info("    " + CmpConfiguration.CONFIG_VENDORCERTIFICATEMODE + " - possible values: true | false");
        getLogger().info("    " + CmpConfiguration.CONFIG_VENDORCA + " - possible values: the name of the external CA");
        getLogger()
                .info("    "
                        + CmpConfiguration.CONFIG_RACERT_PATH
                        + " - possible values: the path to the catalogue where the certificate that will be used to authenticate NestedMessageContent are stored");
        getLogger().info("    " + CmpConfiguration.CONFIG_ALLOWAUTOMATICKEYUPDATE + " - possible values: true | false");
        getLogger().info("    " + CmpConfiguration.CONFIG_ALLOWUPDATEWITHSAMEKEY + " - possible values: true | false");
        getLogger().info(
                "    " + CmpConfiguration.CONFIG_CERTREQHANDLER_CLASS
                        + " - possible values: org.ejbca.core.protocol.unid.UnidFnrHandler | your own implementation of this class");
        getLogger().info("    " + CmpConfiguration.CONFIG_UNIDDATASOURCE + " - possible values: java:/UnidDS | your own unid data source");

    }

    private void printUploadUsage() {
        getLogger().info("Description: Reads CMP configurations from a file.");
        getLogger().info("Usage: cmp uploadfile <filename> <alias>");
        getLogger().info("");
        getLogger().info("Each line that has the format 'ALIAS.key=VALUE' will be read");
        getLogger().info(
                "Only one alias will be read. If one file contains configurations of several aliases, you have to repeat the command with a "
                        + "different alias each time to have all configurations of all aliases read");
        getLogger().info(
                "Note that the alias 'cmp' is the default alias used when sending the CMP request through the URL 'http://HOST:PORT/ejbca/publicweb/cmp'. "
                        + "Note also that the alias 'cmp' does not exist per default and should be created before using this URL");
        getLogger().info("The following keys (if present) will be read from the file:");
        Set<String> keys = CmpConfiguration.getAllAliasKeys("<ALIAS>");
        Iterator<String> itr = keys.iterator();
        while (itr.hasNext()) {
            getLogger().info("     " + itr.next());
        }
    }

}
