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
package org.ejbca.ui.cli.keybind;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingUpdateCertificateCommand extends BaseInternalKeyBindingCommand {

    @Override
    public String getSubCommand() {
        return "update";
    }

    @Override
    public String getDescription() {
        return "Search the database for a newer valid certificate matching the next or current key and sets it as current the certificate.";
    }

    @Override
    public void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, CryptoTokenOfflineException, CertificateImportException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        if (args.length < 2) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name>");
            return;
        }
        final String certificateId = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(getAdmin(), internalKeyBindingId);
        if (certificateId == null) {
            getLogger().info("Operation complete successfully. No change was made.");
        } else {
            final CertificateStoreSessionRemote certificateStoreSession = ejb.getRemoteSession(CertificateStoreSessionRemote.class);
            final CertificateInfo certificateInfo = certificateStoreSession.getCertificateInfo(certificateId);
            getLogger().info("Operation complete successfully.");
            getLogger().info(" InternalKeyBinding:       " + args[1]);
            getLogger().info(" Issuer DN:                " + certificateInfo.getIssuerDN());
            getLogger().info(" Certificate Serialnumber: " + certificateInfo.getSerialNumber().toString(16).toUpperCase());
            getLogger().info(" Subject DN:               " + certificateInfo.getSubjectDN());
        }
    }
}
