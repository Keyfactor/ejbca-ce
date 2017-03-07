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

package org.ejbca.ui.cli.ca;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.util.Arrays;
import java.util.Collection;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleNotFoundException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.roles.RoleExistsException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Imports a PEM file and creates a new external CA representation from it.
 */
public class CaImportCACertCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaImportCACertCommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String FILE_KEY = "-f";
    private static final String INIT_AUTH_KEY = "-initauthorization";
    private static final String SUPERADMIN_CN_KEY = "-superadmincn";

    {
        registerParameter(new Parameter(
                CA_NAME_KEY,
                "CA Name",
                MandatoryMode.MANDATORY,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "Name of the affected CA. If the CA is present, it must either be waiting for a certificate response from an external CA or itself be "
                        + "an external CA, in which case its certificate will be updated. If the CA is not present, a new CA will be added using the imported certificate chain."));
        registerParameter(new Parameter(FILE_KEY, "File Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "A file containing a certificate, in either PEM or DER format. If the CA is waiting for a CSR, this certificate should be the response. "
                        + "If the CA is an externally imported CA, then it will be updated using this certificate. "
                        + "If the CA doesn't exist it will be imported using this certificate. "));
        registerParameter(Parameter.createFlag(INIT_AUTH_KEY,
                "This flag may be used when importing an external CA and will create a super administrator (full access) issued by that CA."));
        registerParameter(new Parameter(SUPERADMIN_CN_KEY, "CN", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Required when using " + INIT_AUTH_KEY + ". The Common Name (CN) for the created super administrator."));
    }

    @Override
    public String getMainCommand() {
        return "importcacert";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String caName = parameters.get(CA_NAME_KEY);
        String certificateFile = parameters.get(FILE_KEY);

        boolean initAuth = parameters.containsKey(INIT_AUTH_KEY);
        String superAdminCN = parameters.get(SUPERADMIN_CN_KEY);
        if (initAuth && StringUtils.isEmpty(superAdminCN)) {
            log.error("Error: " + INIT_AUTH_KEY + " flag was used, but super administrator Common Name was not defined with the " + SUPERADMIN_CN_KEY
                    + " switch.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        try {
            CryptoProviderTools.installBCProviderIfNotAvailable();
            Certificate certificate;
            Collection<Certificate> certs;
            try {
                try {
                    //Try to parse as PEM
                    certs = CertTools.getCertsFromPEM(certificateFile, Certificate.class);
                    if (certs.size() != 1) {
                        log.error("PEM file must only contain one CA certificate, this PEM file contains " + certs.size() + ".");
                        return CommandResult.FUNCTIONAL_FAILURE;
                    } else {
                        certificate = certs.iterator().next();
                    }
                } catch (CertificateParsingException e) {
                    //Try parsing as binary instead.
                    try {
                        certificate = CertTools.getCertfromByteArray(IOUtils.toByteArray(new FileInputStream(certificateFile)), Certificate.class);
                        certs = Arrays.asList(certificate);
                    } catch (CertificateParsingException e2) {
                        log.error("Error: " + certificateFile + " does not contain a certificate, either in PEM or in binary format.");
                        return CommandResult.CLI_FAILURE;
                    }
                }
            } catch (FileNotFoundException e) {
                log.error("Error: " + certificateFile + " was not a file, not found or could otherwise not be opened.");
                return CommandResult.CLI_FAILURE;
            } catch(IOException e) {
                log.error("Unknown IOException was caught", e);
                return CommandResult.FUNCTIONAL_FAILURE;
            }

            /* 
             * We need to check if the CA already exists to determine what to do:
             *  - If CA already exist, it might be a sub CA that is waiting for certificate from an external CA
             *  - If the CA does not already exist, we import the CA certificate as an "External CA" certificate in EJBCA, so we have the CA cert in EJBCA as a trust point
             *    getCAInfo throws an exception (CADoesntExistsException) if the CA does not exists, that is how we check if the CA exists 
             */
            CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
            try {
                CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
                if (cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
                    if (initAuth) {
                        log.warn("Warning: " + INIT_AUTH_KEY + " was defined but was ignored when receiving a CSR.");
                    }

                    log.info("CA '" + caName
                            + "' is waiting for certificate response from external CA, importing certificate as certificate response to this CA.");
                    X509ResponseMessage resp = new X509ResponseMessage();
                    resp.setCertificate(certificate);
                    caAdminSession.receiveResponse(getAuthenticationToken(), cainfo.getCAId(), resp, null, null);
                    log.info("Received certificate response and activated CA " + caName);
                } else if (cainfo.getStatus() == CAConstants.CA_EXTERNAL) {
                    if (initAuth) {
                        log.warn("Warning: " + INIT_AUTH_KEY + " was defined but was ignored when updating an externally imported CA.");
                    }
                    // CA exists and this is assumed to be an update of the imported CA certificate
                    log.info("CA '" + caName + "' is an external CA created by CA certificate import. Trying to update the CA certificate chain.");
                    caAdminSession.updateCACertificate(getAuthenticationToken(), cainfo.getCAId(), EJBTools.wrapCertCollection(certs));
                    log.info("Updated certificate chain for imported external CA " + caName);
                } else {
                    log.error("CA '" + caName + "' already exists and is not waiting for certificate response from an external CA.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                return CommandResult.SUCCESS;
            } catch (CADoesntExistsException e) {
                // CA does not exist, we can import the certificate
                if (initAuth) {
                    String subjectdn = CertTools.getSubjectDN(certificate);
                    Integer caid = Integer.valueOf(subjectdn.hashCode());
                    initAuthorizationModule(getAuthenticationToken(), caid.intValue(), superAdminCN);
                }
                caAdminSession.importCACertificate(getAuthenticationToken(), caName, EJBTools.wrapCertCollection(certs));
                log.info("Imported CA " + caName);
                return CommandResult.SUCCESS;
            }
        } catch (CAExistsException e) {
            log.error(e.getMessage());
        } catch (IllegalCryptoTokenException e) {
            log.error(e.getMessage());
        } catch (AuthorizationDeniedException e) {
            log.error(e.getMessage());
        } catch (AccessRuleNotFoundException e) {
            log.error(e.getMessage());
        } catch (RoleExistsException e) {
            log.error(e.getMessage());
        } catch (CertPathValidatorException e) {
            log.error(e.getMessage());
        } catch (EjbcaException e) {
            log.error(e.getMessage());
        } catch (CesecoreException e) {
            log.error(e.getMessage());
        }
        return CommandResult.FUNCTIONAL_FAILURE;
    }

    @Override
    public String getCommandDescription() {
        return "Imports a PEM file and creates a new external CA representation from it";

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
