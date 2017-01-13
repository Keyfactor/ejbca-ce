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

package org.ejbca.ui.cli.ra;

import java.math.BigInteger;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Revokes a certificate in the database.
 *
 * @version $Id$
 */
public class RevokeCertificateCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(RevokeCertificateCommand.class);

    private static final String SERIAL_NUMBER_KEY = "-s";
    private static final String DN_KEY = "--dn";
    private static final String REASON_KEY = "-r";

    {
        registerParameter(new Parameter(DN_KEY, "Issuer DN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Issuer DN"));
        registerParameter(new Parameter(SERIAL_NUMBER_KEY, "Serial Number", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate serial number in HEX."));
        registerParameter(new Parameter(
                REASON_KEY,
                "Reason",
                MandatoryMode.MANDATORY,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "Reason integer value: unused(0), keyCompromise(1), cACompromise(2), affiliationChanged(3),"
                        + " superseded(4), cessationOfOperation(5), certficateHold(6), removeFromCRL(8), privilegeWithdrawn(9), aACompromise(10). Normal reason is 0"));
    }

    @Override
    public String getMainCommand() {
        return "revokecert";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        final String issuerDNStr = parameters.get(DN_KEY);
        final String issuerDN = CertTools.stringToBCDNString(issuerDNStr);
        final String certserno = parameters.get(SERIAL_NUMBER_KEY);
        final BigInteger serno;
        try {
            serno = new BigInteger(certserno, 16);
        } catch (NumberFormatException e) {
            log.error("ERROR: Invalid hexadecimal certificate serial number string: " + certserno);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        int reason;
        try {
            reason = Integer.parseInt(parameters.get(REASON_KEY));
        } catch (NumberFormatException e) {
            log.error("ERROR: " + parameters.get(REASON_KEY) + " was not a number.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if ((reason == 7) || (reason < 0) || (reason > 10)) {
            getLogger().error("ERROR: Reason must be an integer between 0 and 10 except 7.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } else {
            CertificateDataWrapper certWrapper = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getCertificateDataByIssuerAndSerno(
                    issuerDN, serno);
            if (certWrapper != null) {
                getLogger().info("Found certificate:");
                getLogger().info("Subject DN=" + certWrapper.getCertificateData().getSubjectDnNeverNull());
                // We need the user this cert is connected with
                // Revoke or unrevoke, will throw appropriate exceptions if parameters are wrong, such as trying to unrevoke a certificate
                // that was permanently revoked
                try {
                    try {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).revokeCert(getAuthenticationToken(), serno,
                                issuerDN, reason);
                    } catch (ApprovalException e) {
                        log.error(e.getMessage(), e);
                        return CommandResult.FUNCTIONAL_FAILURE;
                    } catch (AuthorizationDeniedException e) {
                       log.error("ERROR: CLI user not authorized to revoke certificate.");
                       return CommandResult.FUNCTIONAL_FAILURE;
                    } catch (NoSuchEndEntityException e) {
                        log.error("ERROR: " + e.getMessage());
                        return CommandResult.FUNCTIONAL_FAILURE;
                    } catch (WaitingForApprovalException e) {
                        log.error("ERROR: " + e.getMessage());
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                    getLogger().info(
                            (reason == 8 ? "Unrevoked" : "Revoked") + " certificate with issuerDN '" + issuerDN + "' and serialNumber " + certserno
                                    + ". Revocation reason=" + reason);
                } catch (AlreadyRevokedException e) {
                    if (reason == 8) {
                        getLogger().info(
                                "Certificate with issuerDN '" + issuerDN + "' and serialNumber " + certserno + " is not revoked, nothing was done.");
                    } else {
                        getLogger().info(
                                "Certificate with issuerDN '" + issuerDN + "' and serialNumber " + certserno
                                        + " is already revoked, nothing was done.");
                    }
                    getLogger().info(e.getMessage());
                }
            } else {
                getLogger().info("No certificate found with issuerDN '" + issuerDN + "' and serialNumber " + certserno);
            }
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Command used to revoke or unrevoke a certificate.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()+"\nUnrevocation is done using the reason removeFromCRL(8), and can only be done if the certificate is revoked with reason removeFromCRL(6).";
    }

    protected Logger getLogger() {
        return log;
    }

}
