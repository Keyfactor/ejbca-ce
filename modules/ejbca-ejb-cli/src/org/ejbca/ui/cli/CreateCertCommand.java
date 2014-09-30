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

package org.ejbca.ui.cli;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Issue a certificate for a user based on a CSR
 *
 * @version $Id$
 */
public class CreateCertCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(CreateCertCommand.class);

    private static final String ENTITY_NAME = "--username";
    private static final String ENTITY_PASSWORD = "--password";
    private static final String CSR = "-c";
    private static final String DESTINATION_FILE = "-f";

    //Register parameters 
    {
        registerParameter(new Parameter(ENTITY_NAME, "End entity username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The username of an end entity"));
        registerParameter(new Parameter(ENTITY_PASSWORD, "End entity password", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The password of the specified end entity."));
        registerParameter(new Parameter(CSR, "Certificate Request", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Must be a PKCS#10 request in PEM format."));
        registerParameter(new Parameter(DESTINATION_FILE, "Destination file", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The issued certificate will be written to this file."));
    }

    @Override
    public String getMainCommand() {
        return "createcert";
    }

    @Override
    public String getCommandDescription() {
        return "Issue a certificate for a user based on a CSR";
    }

    @Override
    public String getFullHelpText() {
        return "Issue a certificate for a user based on a CSR";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String username = parameters.get(ENTITY_NAME);
        String password = parameters.get(ENTITY_PASSWORD);
        String csr = parameters.get(CSR);
        String certf = parameters.get(DESTINATION_FILE);

        byte[] bytes;
        try {
            bytes = FileTools.readFiletoBuffer(csr);
        } catch (FileNotFoundException e) {
            log.error("File " + csr + " not found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        RequestMessage req = RequestMessageUtils.parseRequestMessage(bytes);
        if (req instanceof PKCS10RequestMessage) {
            PKCS10RequestMessage p10req = (PKCS10RequestMessage) req;
            p10req.setUsername(username);
            p10req.setPassword(password);
        } else {
            log.error("Input file '" + csr + "' is not a PKCS#10 request.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        // Call signsession to create a certificate
        ResponseMessage resp;
        try {
            resp = signSession.createCertificate(getAuthenticationToken(), req, X509ResponseMessage.class, null);
        } catch (EjbcaException e) {
            log.error("Could not create certificate: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CesecoreException e) {
            log.error("Could not create certificate: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException ee) {
            log.error("CLI user with username " + parameters.get(USERNAME_KEY) + " was not authorized to create a certificate.");
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (CertificateExtensionException e) {
            log.error("CSR specified extensions which were invalid: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        byte[] pembytes;
        try {
            pembytes = CertTools.getPemFromCertificateChain(Arrays.asList(((X509ResponseMessage) resp).getCertificate()));
        } catch (CertificateException e) {
            throw new IllegalStateException("Newly created certificate could not be parsed. This should not happen.", e);
        }
        // Write the resulting cert to file
        try {
            FileOutputStream fos = new FileOutputStream(certf);
            fos.write(pembytes);
            fos.close();
        } catch (IOException e) {
            log.error("Could not write to certificate file " + certf + ". " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        log.info("PEM certificate written to file '" + certf + "'");
        return CommandResult.SUCCESS;
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }

}
