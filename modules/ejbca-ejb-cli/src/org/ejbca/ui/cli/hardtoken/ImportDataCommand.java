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

package org.ejbca.ui.cli.hardtoken;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.ui.cli.hardtoken.importer.IHardTokenImporter;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Command used to import hard token data from a source.
 * 
 * It reads its properties from a file specified and there are two required
 * properties by default.
 * importer.classpath pointing to an implementation of a org.ejbca.ui.cli.hardtoken.IHardTokenImporter 
 * significantissuerdn should contain the DN of the CA that the tokens should be connected to, used 
 * for authorization purposes. 
 * 
 * The -force flag indicates that rows that already exists in the data will be overwritten.
 * @version $Id$
 */
public class ImportDataCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(ImportDataCommand.class);

    private static final String FORCE_KEY = "-force";
    private static final String FILE_KEY = "-f";

    {
        registerParameter(new Parameter(FILE_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Properties file to import from."));
        registerParameter(Parameter.createFlag(FORCE_KEY, "Indicates that existing hard token info will be overwritten."));
    }

    @Override
    public String[] getCommandPath() {
        return new String[] { "hardtoken" };
    }

    @Override
    public String getMainCommand() {
        return "importdata";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        Properties props = new Properties();
        String filename = parameters.get(FILE_KEY);
        boolean force = parameters.containsKey(FORCE_KEY);
        try {
            try {
                props.load(new FileInputStream(filename));
            } catch (FileNotFoundException e) {
                log.error("ERROR: File " + filename + " not found.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            // Read the significant issuer dn and check that it exists
            if (props.getProperty("significantissuerdn") == null) {
                log.error("ERROR: The property significantissuerdn isn't set in the propertyfile " + filename);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            String significantIssuerDN = props.getProperty("significantissuerdn");
            int cAId = significantIssuerDN.hashCode();
            try {
                EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), cAId);
            } catch (CADoesntExistsException e) {
                log.error("ERROR: the property significantissuerdn '" + significantIssuerDN + "' does not exist as CA in the system.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            // Create the importer
            if (props.getProperty("importer.classpath") == null) {
                log.error("ERROR: the property importer.classpath isn't set in the propertyfile " + filename);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            IHardTokenImporter importer;
            try {
                importer = (IHardTokenImporter) Thread.currentThread().getContextClassLoader().loadClass(props.getProperty("importer.classpath"))
                        .newInstance();
            } catch (InstantiationException e) {
                log.error("ERROR: Class " + props.getProperty("importer.classpath") + " defined by 'importer.classpath' could not be instantiated.");
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (IllegalAccessException e) {
                log.error("ERROR: Class " + props.getProperty("importer.classpath")
                        + " defined by 'importer.classpath' could not be instantiated legally.", e);
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (ClassNotFoundException e) {
                log.error("ERROR: Class " + props.getProperty("importer.classpath") + " defined by 'importer.classpath' could not be found.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            importer.startImport(props);
            HardTokenInformation htd;
            try {
                while ((htd = importer.readHardTokenData()) != null) {
                    try {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class).addHardToken(getAuthenticationToken(),
                                htd.getTokenSN(), htd.getUsername(), significantIssuerDN, htd.getTokenType(), htd.getHardToken(), null,
                                htd.getCopyOf());
                        getLogger().info("Token with SN " + htd.getTokenSN() + " were added to the database.");
                    } catch (HardTokenExistsException e) {
                        if (force) {
                            try {
                                EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class).removeHardToken(getAuthenticationToken(),
                                        htd.getTokenSN());
                            } catch (HardTokenDoesntExistsException e1) {
                                throw new IllegalStateException("Hard token that should exist apparently doesn't.", e);
                            }
                            try {
                                EjbRemoteHelper.INSTANCE.getRemoteSession(HardTokenSessionRemote.class).addHardToken(getAuthenticationToken(),
                                        htd.getTokenSN(), htd.getUsername(), significantIssuerDN, htd.getTokenType(), htd.getHardToken(), null,
                                        htd.getCopyOf());
                            } catch (HardTokenExistsException e1) {
                                throw new IllegalStateException("Hard token that shouldn't exist apparently does.", e);
                            }
                            getLogger().info("Token with SN " + htd.getTokenSN() + " already existed in the database but was OVERWRITTEN.");
                        } else {
                            getLogger().error("Token with SN " + htd.getTokenSN() + " already exists in the database and is NOT imported.");
                        }
                    }
                }
            } finally {
                importer.endImport();
            }
        } catch (IOException e) {
            throw new IllegalStateException("Unknown IOException was caught.", e);
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user not authorized to import data.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Used to import hard token data from a source";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }
}
