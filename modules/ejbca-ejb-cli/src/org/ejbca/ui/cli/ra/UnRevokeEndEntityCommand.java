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
import java.security.cert.Certificate;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
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
 * Reactivates end entity's certificates if the revocation reason of user certificates is 'on hold'.
 * Does not change status of the end entity itself.
 *
 * @version $Id$
 */
public class UnRevokeEndEntityCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(UnRevokeEndEntityCommand.class);

    private static final String COMMAND = "unrevokeendentity";
    private static final String OLD_COMMAND = "unrevokeuser";

    private static final Set<String> ALIASES = new HashSet<String>();
    static {
        ALIASES.add(OLD_COMMAND);
    }

    private static final String USERNAME_KEY = "--username";

    {
        registerParameter(new Parameter(USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Username for the end entity."));
    }

    @Override
    public Set<String> getMainCommandAliases() {
        return ALIASES;
    }

    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String username = parameters.get(USERNAME_KEY);
        EndEntityInformation data;
        EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(EndEntityManagementSessionRemote.class);
        try {
            data = endEntityAccessSession.findUser(getAuthenticationToken(), username);
        } catch (AuthorizationDeniedException e1) {
            log.error("ERROR: Not authorized to revoke end entity.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        if (data == null) {
            log.error("ERROR: No such end entity: " + username);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (data.getStatus() != EndEntityConstants.STATUS_REVOKED) {
            log.error("ERROR: End entity '" + username + "' is not revoked.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        // Unrevoke user's certificates
        try {
            boolean foundCertificateOnHold = false;
            // Find all user certs
            List<Certificate> certificates = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificatesByUsername(username);
           
                for (Certificate cert : certificates) {
                    BigInteger serialNumber = CertTools.getSerialNumber(cert);
                    String issuerDN = CertTools.getIssuerDN(cert);
                    if (EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getStatus(issuerDN, serialNumber).revocationReason == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
                        foundCertificateOnHold = true;
                        try {
                            endEntityManagementSession.revokeCert(getAuthenticationToken(), serialNumber, issuerDN.toString(),
                                    RevokedCertInfo.NOT_REVOKED);
                        } catch (AlreadyRevokedException e) {
                            getLogger().error("ERROR: The end entity was already reactivated while the request executed.");
                        } catch (ApprovalException e) {
                            getLogger().error("ERROR: Reactivation already requested.");
                        } catch (WaitingForApprovalException e) {
                            getLogger().info("ERROR: Reactivation request has been sent for approval.");
                        }
                    }
                }
                if (!foundCertificateOnHold) {
                    getLogger().error("No certificates with status 'On hold' were found for this end entity. Status is unchanged.");
                } else {
                    try {
                        //Certificates were found and unrevoked. Set status to generates
                        endEntityManagementSession.setUserStatus(getAuthenticationToken(), username, EndEntityConstants.STATUS_GENERATED);
                        getLogger().info("Setting status of end entity '" + username + "' to GENERATED (40).");

                    } catch (ApprovalException e) {
                        getLogger().error("ERROR: End entity reactivation already requested.");
                    } catch (WaitingForApprovalException e) {
                        getLogger().info("End entity reactivation request has been sent for approval.");
                    }
                }
         
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to reactivate end entity.");
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (FinderException e) {
            getLogger().error("ERROR: " + e.getMessage());
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Reactivates an end entity's certificates if the revocation reason of certificates is 'on hold', and unrevokes the end entity. ";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription()
                + "A user's certificate can unly be unrevoked if the revocation reason is certificate_hold. If any such certificates were found, status will automatically be set to 40 (generated) after this command is run.");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }

}
