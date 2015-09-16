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

import java.io.FileWriter;
import java.io.IOException;
import java.security.cert.Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.util.EJBTools;
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
 * @version $Id: InternalKeyBindingImportCertificateCommand.java 18666 2014-03-24 13:37:16Z mikekushner $
 */
public class InternalKeyBindingExportCertificateCommand extends RudInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingExportCertificateCommand.class);

    private static final String PEM_FILE_KEY = "-f";

    {
        registerParameter(new Parameter(PEM_FILE_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "PEM to export to."));
    }

    @Override
    public String getMainCommand() {
        return "exportcert";
    }

    @Override
    public CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException,
            CertificateImportException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final CertificateStoreSessionRemote certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        final String filename = parameters.get(PEM_FILE_KEY);
        try {
            final InternalKeyBindingInfo info = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(getAdmin(), internalKeyBindingId);
            if (info == null) {
                getLogger().error("Internal key binding with id "+internalKeyBindingId+" does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            final String fp = info.getCertificateId();
            if (fp == null) {
                getLogger().error("There is no certificate bound to Internal key binding with id "+internalKeyBindingId+".");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            final Certificate cert = EJBTools.unwrap(certStoreSession.findCertificateByFingerprintRemote(fp));
            if (cert == null) {
                getLogger().error("Certificate with fingerprint "+fp+" does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            JcaPEMWriter pw = new JcaPEMWriter(new FileWriter(filename));            
            pw.writeObject(cert);
            pw.close();
            getLogger().info("Operation completed successfully.");
            return CommandResult.SUCCESS;
        } catch (IOException e) {
            throw new IllegalStateException("Failed to write PEM format certificate to \"" + filename + "\". " + e.getMessage());
        }
    }

    @Override
    public String getCommandDescription() {
        return "Export a certificate in PEM format from the key binding database.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    protected Logger getLogger() {
        return log;
    }

}
