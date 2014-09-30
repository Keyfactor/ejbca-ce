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

import java.io.File;
import java.util.Iterator;
import java.util.Set;

import org.apache.commons.configuration.CompositeConfiguration;
import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;
import org.apache.commons.configuration.reloading.FileChangedReloadingStrategy;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.Configuration;
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
public class UploadFileCommand extends BaseCmpConfigCommand {

    private static final String ALIAS_KEY = "--alias";
    private static final String FILE_KEY = "--file";

    private static final Logger log = Logger.getLogger(UploadFileCommand.class);

    {
        registerParameter(new Parameter(ALIAS_KEY, "Alias", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The alias to read to."));
        registerParameter(new Parameter(FILE_KEY, "File", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The file to upload."));
    }

    @Override
    public String getMainCommand() {
        return "uploadfile";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String filename = parameters.get(FILE_KEY);
        String alias = parameters.get(ALIAS_KEY);

        CompositeConfiguration config = null;
        File f = null;
        try {
            f = new File(filename);
            final PropertiesConfiguration pc = new PropertiesConfiguration(f);
            pc.setReloadingStrategy(new FileChangedReloadingStrategy());
            config = new CompositeConfiguration();
            config.addConfiguration(pc);
            log.info("Reading CMP configuration from file: " + f.getAbsolutePath());
        } catch (ConfigurationException e) {
            log.error("Failed to load configuration from file " + f.getAbsolutePath());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        readConfigurations(config, alias);
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Reads CMP configuration from a file.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n");
        sb.append("\n");
        sb.append("Each line that has the format 'ALIAS.key=VALUE' will be read" + "\n");
        sb.append(
                "Only one alias will be read. If one file contains configurations of several aliases, you have to repeat the command with a "
                        + "different alias each time to have all configurations of all aliases read"+ "\n");
        sb.append(
                "Note that the alias 'cmp' is the default alias used when sending the CMP request through the URL 'http://HOST:PORT/ejbca/publicweb/cmp'. "
                        + "Note also that the alias 'cmp' does not exist per default and should be created before using this URL"+ "\n");
        sb.append("The following keys (if present) will be read from the file:" + "\n");
        Set<String> keys = CmpConfiguration.getAllAliasKeys("<ALIAS>");
        Iterator<String> itr = keys.iterator();
        while (itr.hasNext()) {
            sb.append("     " + itr.next() + "\n");
        }
        return sb.toString();
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
                log.info("Setting value: " + key + "=" + value);
            }
        }

        // Save the new configurations.
        if (populated) {
            try {
                getGlobalConfigurationSession().saveConfiguration(getAuthenticationToken(), getCmpConfiguration(),
                        Configuration.CMPConfigID);
                log.info("\nNew configurations saved successfully.");
                log.info("If there are any issues with the configurations, check them in the AdminGUI and click 'Save'");
                getGlobalConfigurationSession().flushConfigurationCache(Configuration.CMPConfigID);
            } catch (AuthorizationDeniedException e) {
                log.error("Failed to save configuration from file: " + e.getLocalizedMessage());
            }
        } else {
            getCmpConfiguration().removeAlias(alias);
            log.info("No relevent CMP configurations found with alias '" + alias + "' in the file.");
        }
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
