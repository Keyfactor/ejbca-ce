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

package org.ejbca.ui.cli.ca;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Retrieves the latest CRL from a CA.
 *
 * @version $Id$
 */
public class CaGetCrlCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaGetCrlCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String DELTA_KEY = "-delta";
    private static final String PEM_KEY = "-pem";
    private static final String FILE_KEY = "-f";
    private static final String CRLNUMBER_KEY = "-crlnumber";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The CA to get the CRL for."));
        registerParameter(new Parameter(FILE_KEY, "File Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The file to export to."));
        registerParameter(new Parameter(DELTA_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Fetch the latest delta CRL. Default is regular CRL."));
        registerParameter(new Parameter(PEM_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Use PEM encoding. Default is DER encoding."));
        registerParameter(new Parameter(CRLNUMBER_KEY, "CRL Number", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Get CRL with the specified CRL number, instead of the latest. Used to read historical CRLs."));
    }

    @Override
    public String getMainCommand() {
        return "getcrl";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        boolean deltaSelector = parameters.get(DELTA_KEY) != null;
        boolean pem = parameters.get(PEM_KEY) != null;
        CryptoProviderTools.installBCProvider();
        // Perform CRL fetch
        String caname = parameters.get(CA_NAME_KEY);
        String outfile = parameters.get(FILE_KEY);
        String crlnumber = parameters.get(CRLNUMBER_KEY);
        if (crlnumber != null) {
            if (!StringUtils.isNumeric(crlnumber)) {
                log.error("CRL Number must be numerical");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        try {
            String issuerdn = getIssuerDN(getAuthenticationToken(), caname);
            final byte[] crl;
            if (crlnumber != null) {
                crl = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getCRL(issuerdn, Integer.valueOf(crlnumber));                
            } else {
                crl = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRL(issuerdn, deltaSelector);
            }
            if (crl != null) {
                FileOutputStream fos = new FileOutputStream(outfile);
                if (pem) {
                    fos.write(CertTools.getPEMFromCrl(crl));
                } else {
                    fos.write(crl);
                }
                fos.close();
                log.info("Wrote latest " + (deltaSelector ? "delta " : "") + "CRL to " + outfile + " using " + (pem ? "PEM" : "DER") + " format");
            } else {
                log.info("No " + (deltaSelector ? "delta " : "") + "CRL exists for CA " + caname + ".");
            }
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI User was not authorized to CA " + caname);
        } catch (CADoesntExistsException e) {
            log.info("CA '" + caname + "' does not exist.");
        } catch (FileNotFoundException e) {
            log.error("Could not create export file", e);
        } catch (IOException e) {
            throw new IllegalStateException("Could not write to file for unknown reason", e);
        }
        return CommandResult.FUNCTIONAL_FAILURE;

    }

    @Override
    public String getCommandDescription() {
        return "Retrieves a CRL from a CA. Either the latest CRL or a CRL with a specified CRL number.";

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
