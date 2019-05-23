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
import org.apache.commons.lang.math.IntRange;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
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
    private static final String CRLPARTITION_KEY = "-crlpartition";

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
        registerParameter(new Parameter(CRLPARTITION_KEY, "CRL Partition Number", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Get CRL with the specified CRL partition numbers. Default is 0."));
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
        final String caName = parameters.get(CA_NAME_KEY);
        final String outFile = parameters.get(FILE_KEY);
        final String crlNumber = parameters.get(CRLNUMBER_KEY);
        final String crlPartitionNumber = parameters.get(CRLPARTITION_KEY);

        if (crlNumber != null) {
            if ( !StringUtils.isNumeric(crlNumber) || (Integer.valueOf(crlNumber) < 0) ) {
                log.error("CRL Number must be a positive number");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        if(crlPartitionNumber != null) {
            if ( !StringUtils.isNumeric(crlPartitionNumber) || (Integer.valueOf(crlPartitionNumber) < 0) ) {
                log.error("CRL Partition Number must be a positive number");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        try {
            final CAInfo caInfo = getCAInfo(getAuthenticationToken(), caName);
            if(caInfo == null) {
                throw new CADoesntExistsException();
            }
            final String issuerDN = caInfo.getSubjectDN();
            final IntRange allCrlPartitionIndexes = caInfo.getAllCrlPartitionIndexes();
            int crlPartitionIndex = CertificateConstants.NO_CRL_PARTITION;
            String crlPartitionOutputString = "";
            if(allCrlPartitionIndexes == null) {
                if (crlPartitionNumber != null) {
                    log.error("This CA '" + caName + "' does not support CRL Partitions.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }
            else {
                crlPartitionIndex = ( crlPartitionNumber == null ? CertificateConstants.NO_CRL_PARTITION : Integer.valueOf(crlPartitionNumber));
                crlPartitionOutputString = " with crl partition " + crlPartitionIndex;
            }
            final byte[] crl = getCrlBytes(issuerDN, crlNumber, crlPartitionIndex, deltaSelector);
            final String deltaOutputString = (deltaSelector ? " delta" : "");
            if (crl != null) {
                writeCrlBytesToFile(outFile, crl, pem);
                log.info("Wrote " + (crlNumber == null ? "latest" : ("crlNumber " + crlNumber)) + deltaOutputString + crlPartitionOutputString + " CRL to " + outFile + " using " + (pem ? "PEM" : "DER") + " format");
            } else {
                final String crlNumberOutputString = " CRL " + (crlNumber == null ? "" : ("with crlNumber " + crlNumber));
                log.info("No" + deltaOutputString + crlNumberOutputString + crlPartitionOutputString + " exists for CA " + caName + ".");
            }
            return CommandResult.SUCCESS;
        } catch (CADoesntExistsException e) {
            log.info("CA '" + caName + "' does not exist.");
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

    private byte[] getCrlBytes(final String issuerDN, final String crlNumber, final int crlPartitionIndex, final boolean isDeltaCrl) {
        final CrlStoreSessionRemote crlStoreSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
        if(crlNumber != null) {
            return crlStoreSessionRemote.getCRL(issuerDN, crlPartitionIndex, Integer.valueOf(crlNumber));
        }
        return crlStoreSessionRemote.getLastCRL(issuerDN, crlPartitionIndex, isDeltaCrl);
    }

    private void writeCrlBytesToFile(final String outFile, final byte[] crlBytes, final boolean isPemFormat) throws IOException {
        final FileOutputStream fos = new FileOutputStream(outFile);
        if (isPemFormat) {
            fos.write(CertTools.getPEMFromCrl(crlBytes));
        } else {
            fos.write(crlBytes);
        }
        fos.close();
    }
}
