package org.ejbca.ui.cli.ca;

import java.io.IOException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;

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
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

/**
 * Imports a PEM file and creates a new external CA representation from it.
 */
public class CaImportCACertCommand extends BaseCaAdminCommand {

    @Override
    public String getSubCommand() { return "importcacert"; }
    @Override
    public String getDescription() { return "Imports a PEM file and creates a new external CA representation from it"; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        if (args.length < 3) {
        	getLogger().info("Description: " + getDescription());
        	getLogger().info("Usage: " + getCommand() + " <CA name> <PEM file> [-initauthorization] [-superadmincn SuperAdmin]\n");
			getLogger().info("Add the argument '-initauthorization' if you are importing an initial administration CA, and this will be the first CA in your system. Only used during installation when there is no local AdminCA on the EJBCA instance, but an external CA is used for administration.\n");
    		getLogger().info("Adding the parameters '-superadmincn SuperAdmin' (required when using -initauthorization) makes an initial super administrator using the common name SuperAdmin (select you CN) when initializing the authorization module. Note only used together with -initauthorization when importing initial CA.");
			return;
		}
		String caName = args[1];
		String pemFile = args[2];
		List<String> argsList = CliTools.getAsModifyableList(args);
		boolean initAuth = argsList.remove("-initauthorization");

		int superAdminCNInd = argsList.indexOf("-superadmincn");
		String superAdminCN = null;
		if (superAdminCNInd > -1) {
			if (argsList.size() <= (superAdminCNInd+1)) {
				getLogger().info("Use -superadmincn SuperAdminCN");
				return;
			}
			superAdminCN = argsList.get(superAdminCNInd+1);
			argsList.remove(superAdminCN);
			argsList.remove("-superadmincn");
		}

		try {
			CryptoProviderTools.installBCProvider();
			Collection<Certificate> certs = CertTools.getCertsFromPEM(pemFile);
			if (certs.size() != 1) {
				throw new ErrorAdminCommandException("PEM file must only contain one CA certificate, this PEM file contains "+certs.size()+".");
			}
			try {
                // We need to check if the CA already exists to determine what to do:
                // - If CA already exist, it might be a sub CA that waits for certificate from an external CA
                // - If the CA does not already exist, we import the CA certificate as an "External CA" certificate in EJBCA, so we have the CA cert in EJBCA as a trust point
                // getCAInfo throws an exception (CADoesntExistsException) if the CA does not exists, that is how we check if the CA exists 
			    CAInfo cainfo = ejb.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caName);
			    if (cainfo.getStatus() == CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
			        getLogger().info("CA '"+caName+"' is waiting for certificate response from external CA, importing certificate as certificate response to this CA.");
			        X509ResponseMessage resp = new X509ResponseMessage();
			        resp.setCertificate(certs.iterator().next());
			        ejb.getRemoteSession(CAAdminSessionRemote.class).receiveResponse(getAuthenticationToken(cliUserName, cliPassword), cainfo.getCAId(), resp, null, null);
	                getLogger().info("Received certificate response and activated CA "+caName);                
			    } else {
			        throw new ErrorAdminCommandException("CA '"+caName+"' already exists and is not waiting for certificate response from an external CA.");                    
			    }
			} catch (CADoesntExistsException e) {
			    // CA does not exist, we can import the certificate
			    if (initAuth) {
			        String subjectdn = CertTools.getSubjectDN(certs.iterator().next());
			        Integer caid = Integer.valueOf(subjectdn.hashCode());
			        initAuthorizationModule(getAuthenticationToken(cliUserName, cliPassword), caid.intValue(), superAdminCN);
			    }
			    ejb.getRemoteSession(CAAdminSessionRemote.class).importCACertificate(getAuthenticationToken(cliUserName, cliPassword), caName, certs);
			    getLogger().info("Imported CA "+caName);
            }
		} catch (CertificateException e) {
			getLogger().error(e.getMessage());
		} catch (IOException e) {
			getLogger().error(e.getMessage());
		} catch (CAExistsException e) {
			getLogger().error(e.getMessage());
		} catch (IllegalCryptoTokenException e) {
			getLogger().error(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			getLogger().error(e.getMessage());
		} catch (AccessRuleNotFoundException e) {
			getLogger().error(e.getMessage());
		} catch (RoleExistsException e) {
			getLogger().error(e.getMessage());
		} catch (RoleNotFoundException e) {
			getLogger().error(e.getMessage());
        } catch (CertPathValidatorException e) {
            getLogger().error(e.getMessage());
        } catch (EjbcaException e) {
            getLogger().error(e.getMessage());
        } catch (CesecoreException e) {
            getLogger().error(e.getMessage());
		}
	}
}
