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

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.keybind.CertificateImportException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingImportCertificateCommand extends BaseInternalKeyBindingCommand {

    @Override
    public String getSubCommand() {
        return "import";
    }

    @Override
    public String getDescription() {
        return "Validate and import a certificate in PEM format to the database and update the key binding.";
    }

    @Override
    public void executeCommand(Integer internalKeyBindingId, String[] args) throws AuthorizationDeniedException, CertificateImportException {
        if (args.length < 3) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <name> <PEM input file name>");
            return;
        }
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = ejb.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        try {
            final InputStream is = new FileInputStream(args[2]);
            final List<Certificate> certificates = CertTools.getCertsFromPEM(is);
            is.close();
            // Import first non-CA cert
            boolean imported = false;
            for (final Certificate certificate : certificates) {
                if (!CertTools.isCA(certificate)) {
                    final byte[] certificateBytes = certificate.getEncoded();
                    internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(getAdmin(), internalKeyBindingId, certificateBytes);
                    getLogger().info("Operation complete successfully.");
                    imported = true;
                    break;
                } else {
                    getLogger().info("Ignoring CA certificate with subjectDN " + CertTools.getSubjectDN(certificate));
                }
            }
            if (!imported) {
                getLogger().info("Unable to import any certificate from the specified file.");
            }
        } catch (IOException e) {
            getLogger().info("Filed to read PEM format certificate from \"" + args[2] + "\". " + e.getMessage());
        } catch (CertificateException e) {
            getLogger().info("Filed to read PEM format certificate from \"" + args[2] + "\". " + e.getMessage());
        }
    }
}
