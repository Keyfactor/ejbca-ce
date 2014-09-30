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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
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
        try {
            data = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAuthenticationToken(), username);
        } catch (AuthorizationDeniedException e1) {
            log.error("ERROR: Not authorized to revoke end entity.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        getLogger().info("Found user:");
        getLogger().info("username=" + data.getUsername());
        getLogger().info("dn=\"" + data.getDN() + "\"");
        getLogger().info("Old status=" + data.getStatus());
        // Revoke users certificates
        try {
            boolean foundCertificateOnHold = false;
            // Find all user certs
            Iterator<Certificate> i = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                    .findCertificatesByUsername(username).iterator();
            while (i.hasNext()) {
                X509Certificate cert = (X509Certificate) i.next();
                if (EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).getStatus(cert.getIssuerDN().toString(),
                        cert.getSerialNumber()).revocationReason == RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD) {
                    foundCertificateOnHold = true;
                    try {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).revokeCert(getAuthenticationToken(),
                                cert.getSerialNumber(), cert.getIssuerDN().toString(), RevokedCertInfo.NOT_REVOKED);
                    } catch (AlreadyRevokedException e) {
                        getLogger().error("ERROR: The end entity was already reactivated while the request executed.");
                    } catch (ApprovalException e) {
                        getLogger().error("ERROR: Reactivation already requested.");
                    } catch (WaitingForApprovalException e) {
                        getLogger().info("ERROR: Reactivation request has been sent for approval.");
                    } catch (FinderException e) {
                        getLogger().error("ERROR: " + e.getMessage());
                    }
                }
            }
            if (!foundCertificateOnHold) {
                getLogger().error("No certificates with status 'On hold' were found for this end entity.");
            } else {
                data = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAuthenticationToken(), username);
                getLogger().info("New status=" + data.getStatus());
                return CommandResult.SUCCESS;
            }
        } catch (AuthorizationDeniedException e) {
            getLogger().error("Not authorized to reactivate end entity.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.FUNCTIONAL_FAILURE;

    }

    @Override
    public String getCommandDescription() {
        return "Reactivates an end entity's certificates if the revocation reason of certificates is 'on hold'. ";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription()
                + "Does not change status of the end entity itself. "
                + "A user's certificate can unly be unrevoked if the revocation reason is certificate_hold. "
                + " The user status on the user itself is not changed, it is still revoked. Use setendentitystatus command to change status of a user.");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }

}
