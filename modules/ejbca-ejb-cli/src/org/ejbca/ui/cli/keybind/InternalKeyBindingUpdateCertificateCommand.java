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
package org.ejbca.ui.cli.keybind;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingUpdateCertificateCommand extends RudInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingUpdateCertificateCommand.class);

    @Override
    public String getMainCommand() {
        return "update";
    }

    @Override
    public CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException,
            CryptoTokenOfflineException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

        String certificateId;
        try {
            certificateId = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(getAdmin(), internalKeyBindingId);
            if (certificateId == null) {
                getLogger().info("Operation completed successfully. No change was made.");
            } else {
                final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE
                        .getRemoteSession(CertificateStoreSessionRemote.class);
                final CertificateInfo certificateInfo = certificateStoreSession.getCertificateInfo(certificateId);
                getLogger().info("Operation completed successfully.");
                getLogger().info(" InternalKeyBinding:       " + parameters.get(KEYBINDING_NAME_KEY));
                getLogger().info(" Issuer DN:                " + certificateInfo.getIssuerDN());
                getLogger().info(" Certificate Serialnumber: " + certificateInfo.getSerialNumber().toString(16).toUpperCase());
                getLogger().info(" Subject DN:               " + certificateInfo.getSubjectDN());
            }
            return CommandResult.SUCCESS;
        } catch (CertificateImportException e) {
            log.error("Could not update certificate: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
       
    }

    @Override
    public String getCommandDescription() {
        return "Search the database for a newer valid certificate matching the next or current key and sets it as current the certificate.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n");
        return sb.toString();
    }

    protected Logger getLogger() {
        return log;
    }
}
