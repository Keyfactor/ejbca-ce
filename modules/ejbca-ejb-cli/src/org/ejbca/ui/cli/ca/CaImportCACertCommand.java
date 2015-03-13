package org.ejbca.ui.cli.ca;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;

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
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "If no caname is given, CRLs will be created for all the CAs where it is neccessary."));
        registerParameter(new Parameter(FILE_KEY, "File Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Use if you are importing an initial administration CA, and this will be the first CA in your system. "
                        + "Only used during installation when there is no local AdminCA on the EJBCA instance, "
                        + "but an external CA is used for administration."));
        registerParameter(new Parameter(INIT_AUTH_KEY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Use DER encoding. Default is PEM encoding."));
        registerParameter(new Parameter(SUPERADMIN_CN_KEY, "CN", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Required when using " + INIT_AUTH_KEY + ", makes an initial super administrator using the common name SuperAdmin (select you CN) "
                        + "when initializing the authorization module. Note only used together with -initauthorization when importing initial CA."));
    }

    @Override
    public String getMainCommand() {
        return "importcacert";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String caName = parameters.get(CA_NAME_KEY);
        String pemFile = parameters.get(FILE_KEY);
    
        boolean initAuth = parameters.get(INIT_AUTH_KEY) != null;
        String superAdminCN = parameters.get(SUPERADMIN_CN_KEY);
        try {
            CryptoProviderTools.installBCProvider();
            Collection<Certificate> certs = CertTools.getCertsFromPEM(pemFile);
            try {
                // We need to check if the CA already exists to determine what to do:
                // - If CA already exist, it might be a sub CA that waits for certificate from an external CA
                // - If the CA does not already exist, we import the CA certificate as an "External CA" certificate in EJBCA, so we have the CA cert in EJBCA as a trust point
                // getCAInfo throws an exception (CADoesntExistsException) if the CA does not exists, that is how we check if the CA exists 
                CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
                if (cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
                    if (certs.size() != 1) {
                        log.error("PEM file must only contain one CA certificate, this PEM file contains " + certs.size() + ".");
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                    log.info("CA '" + caName
                            + "' is waiting for certificate response from external CA, importing certificate as certificate response to this CA.");
                    X509ResponseMessage resp = new X509ResponseMessage();
                    resp.setCertificate(certs.iterator().next());
                    EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).receiveResponse(getAuthenticationToken(), cainfo.getCAId(),
                            resp, null, null);
                    log.info("Received certificate response and activated CA " + caName);
                } else if (cainfo.getStatus() == CAConstants.CA_EXTERNAL) {
                    // CA exists and this is assumed to be an update of the imported CA certificate
                    log.info("CA '" + caName
                            + "' is an external CA created by CA certificate import. Trying to update the CA certificate chain.");
                    EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).importCACertificateUpdate(getAuthenticationToken(), cainfo.getCAId(), certs);
                    log.info("Updated certificate chain for imported external CA " + caName);
                } else {
                    log.error("CA '" + caName
                            + "' already exists and is not waiting for certificate response from an external CA.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
                return CommandResult.SUCCESS;
            } catch (CADoesntExistsException e) {
                // CA does not exist, we can import the certificate
                if (initAuth) {
                    String subjectdn = CertTools.getSubjectDN(certs.iterator().next());
                    Integer caid = Integer.valueOf(subjectdn.hashCode());
                    initAuthorizationModule(getAuthenticationToken(), caid.intValue(), superAdminCN);
                }
                EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).importCACertificate(getAuthenticationToken(), caName, certs);
                log.info("Imported CA " + caName);
                return CommandResult.SUCCESS;
            }
        } catch (CertificateException e) {
            log.error(e.getMessage());
        } catch (IOException e) {
            log.error(e.getMessage());
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
