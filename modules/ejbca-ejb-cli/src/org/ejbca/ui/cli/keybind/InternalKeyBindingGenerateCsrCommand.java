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

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
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
public class InternalKeyBindingGenerateCsrCommand extends RudInternalKeyBindingCommand {

    private static final Logger log = Logger.getLogger(InternalKeyBindingGenerateCsrCommand.class);

    private static final String GENKEYPAIR_KEY = "--genkeypair";
    private static final String SUBJECTDN_KEY = "--subjectdn";
    private static final String CSR_FILE_KEY = "-f";

    {
        registerParameter(Parameter.createFlag(GENKEYPAIR_KEY, "Set to generate a \"next\" key pair"));
        registerParameter(new Parameter(CSR_FILE_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Destination file for the CSR."));
        registerParameter(new Parameter(SUBJECTDN_KEY, "CSR Subject DN", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The Subject Distinguiser Name to put in the CSR."));
    }

    @Override
    public String getMainCommand() {
        return "gencsr";
    }

    @Override
    public CommandResult executeCommand(Integer internalKeyBindingId, ParameterContainer parameters) throws AuthorizationDeniedException, IOException,
            InvalidKeyException, CryptoTokenOfflineException, InvalidAlgorithmParameterException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

        final boolean switchGenKeyPair = parameters.containsKey(GENKEYPAIR_KEY);

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
        final String optionalSubjectDN = parameters.get(SUBJECTDN_KEY);
        final byte[] certificateRequestBytes = internalKeyBindingMgmtSession.generateCsrForNextKey(getAdmin(), internalKeyBindingId, optionalSubjectDN);
        if (certificateRequestBytes == null) {
            getLogger().error("Unable to generate CSR for " + nextKeyAlias);
            return CommandResult.FUNCTIONAL_FAILURE;
        } else {
            final byte[] pemEncodedPublicKey = CertTools.getPEMFromCertificateRequest(certificateRequestBytes);
            final OutputStream fos = new FileOutputStream(parameters.get(CSR_FILE_KEY));
            fos.write(pemEncodedPublicKey);
            fos.close();
            getLogger().info(
                    "Stored PEM encoded PKCS#10 request for \"" + parameters.get(KEYBINDING_NAME_KEY) + "\" as " + parameters.get(CSR_FILE_KEY));
            return CommandResult.SUCCESS;
        }
    }

    @Override
    public String getCommandDescription() {
        return "Generate a PKCS#10 CSR for the next key pair to be used.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription()+ " Optionally generates a new \"next\" key pair and otherwise returns the current public key.";
    }

    protected Logger getLogger() {
        return log;
    }

}
