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
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Set status to key recovery for an end entity's certificate.
 *
 * @version $Id$
 */
public class KeyRecoveryCommand extends BaseRaCommand {

    private static final Logger log = Logger.getLogger(KeyRecoveryCommand.class);

    private static final String SERIAL_NUMBER_KEY = "-s";
    private static final String DN_KEY = "--dn";

    {
        registerParameter(new Parameter(SERIAL_NUMBER_KEY, "Serial Number", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The certificate serial number in HEX."));
        registerParameter(new Parameter(DN_KEY, "Issuer DN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT, "Issuer DN"));
    }

    @Override
    public String getMainCommand() {
        return "keyrecover";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        BigInteger certificatesn = new BigInteger(parameters.get(SERIAL_NUMBER_KEY), 16);
        String issuerdn = parameters.get(DN_KEY);
        boolean usekeyrecovery = ((GlobalConfiguration) EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class)
                .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
        if (!usekeyrecovery) {
            getLogger().error("Keyrecovery have to be enabled in the system configuration in order to use this command.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        X509Certificate cert = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                .findCertificateByIssuerAndSerno(issuerdn, certificatesn);
        if (cert == null) {
            getLogger().error("Certificate couldn't be found in database.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        String username = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).findUsernameByCertSerno(certificatesn,
                issuerdn);
        if (!EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class).existsKeys(EJBTools.wrap(cert))) {
            getLogger().error("Specified keys don't exist in database.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class).isUserMarked(username)) {
            getLogger().error("User is already marked for recovery.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            EndEntityInformation userdata = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(
                    getAuthenticationToken(), username);
            if (userdata == null) {
                getLogger().error("ERROR: The user " + username + " defined by certificate serial number doesn't exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).prepareForKeyRecovery(getAuthenticationToken(),
                    userdata.getUsername(), userdata.getEndEntityProfileId(), cert)) {
                getLogger().info("Key pair corresponding to the specified certificate has been marked for recovery.");
                return CommandResult.SUCCESS;
            } else {
                getLogger().error("Failed to mark keys corresponding to given certificate for recovery.");
            }
        } catch (AuthorizationDeniedException e) {
            log.error("ERROR: CLI use not authorized to perform key recovery on user " + username);
        } catch (ApprovalException e) {
            log.error("ERROR: " + e.getMessage());
        } catch (WaitingForApprovalException e) {
            log.error("ERROR: " + e.getMessage());
        } catch (CADoesntExistsException e) {
            log.error("ERROR: " + e.getMessage());
        }
        return CommandResult.FUNCTIONAL_FAILURE;

    }

    @Override
    public String getCommandDescription() {
        return "Set status to key recovery for an end entity's certificate";
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
