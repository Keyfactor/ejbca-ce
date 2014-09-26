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

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class InternalKeyBindingImportCertificateCommand extends RudInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingImportCertificateCommand.class);

    private static final String PEM_FILE_KEY = "-f";

    {
        registerParameter(new Parameter(PEM_FILE_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "PEM to import from."));
    }

    @Override
    public String getMainCommand() {
        return "import";
    }

    @Override
    public CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException,
            CertificateImportException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final String filename = parameters.get(PEM_FILE_KEY);
        try {
            final InputStream is = new FileInputStream(filename);
            final List<Certificate> certificates = CertTools.getCertsFromPEM(is);
            is.close();
            // Import first non-CA cert
            boolean imported = false;
            for (final Certificate certificate : certificates) {
                if (!CertTools.isCA(certificate)) {
                    final byte[] certificateBytes = certificate.getEncoded();
                    internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(getAdmin(), internalKeyBindingId, certificateBytes);
                    getLogger().info("Operation completed successfully.");
                    imported = true;
                    break;
                } else {
                    getLogger().info("Ignoring CA certificate with subjectDN " + CertTools.getSubjectDN(certificate));
                }
            }
            if (!imported) {
                getLogger().error("Unable to import any certificate from the specified file.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            return CommandResult.SUCCESS;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read PEM format certificate from \"" + filename + "\". " + e.getMessage());
        } catch (CertificateException e) {
            log.error("Failed to read PEM format certificate from \"" + filename + "\". " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Validate and import a certificate in PEM format to the database and update the key binding.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }

}
