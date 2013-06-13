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

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.util.List;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.keybind.InternalKeyBinding;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.util.CliTools;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingGenerateCsrCommand extends BaseInternalKeyBindingCommand {

    @Override
    public String getSubCommand() {
        return "gencsr";
    }

    @Override
    public String getDescription() {
        return "Generate a PKCS#10 CSR for the next key pair to be used. Optionally generates a new \"next\" key pair and otherwise returns the current public key.";
    }

    @Override
    public void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, IOException, InvalidKeyException, Exception {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name> [--genkeypair] <output filename>");
            return;
        }
        final List<String> argsList = CliTools.getAsModifyableList(args);
        final boolean switchGenKeyPair = CliTools.getAndRemoveSwitch("--genkeypair", argsList);
        args = CliTools.getAsArgs(argsList);
        String nextKeyAlias;
        if (switchGenKeyPair) {
            nextKeyAlias = internalKeyBindingMgmtSession.generateNextKeyPair(getAdmin(), internalKeyBindingId);
            getLogger().info("A new key pair has been generated with alias " + nextKeyAlias);
        } else {
            final InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(getAdmin(), internalKeyBindingId);
            nextKeyAlias = internalKeyBinding.getNextKeyPairAlias();
            if (nextKeyAlias == null) {
                nextKeyAlias = internalKeyBinding.getKeyPairAlias();
            }
            getLogger().info("Next key pair alias is " + nextKeyAlias);
        }
        final byte[] certificateRequestBytes = internalKeyBindingMgmtSession.generateCsrForNextKey(getAdmin(), internalKeyBindingId);
        if (certificateRequestBytes == null) {
            getLogger().info("Unable to generate CSR for " + nextKeyAlias);
        } else {
            final byte[] pemEncodedPublicKey = CertTools.getPEMFromCertificateRequest(certificateRequestBytes);
            final OutputStream fos = new FileOutputStream(args[2]);
            fos.write(pemEncodedPublicKey);
            fos.close();
            getLogger().info("Stored PEM encoded PKCS#10 request for \"" + args[1] + "\" as " + args[2]);
        }
    }
}
