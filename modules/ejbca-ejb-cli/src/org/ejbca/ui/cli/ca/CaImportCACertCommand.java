package org.ejbca.ui.cli.ca;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;
import java.util.List;

import javax.ejb.CreateException;

import org.ejbca.core.model.authorization.AdminGroupExistsException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CliTools;

/**
 * Imports a PEM file and creates a new external CA representation from it.
 */
public class CaImportCACertCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importcacert"; }
	public String getDescription() { return "Imports a PEM file and creates a new external CA representation from it"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		if (args.length < 3) {
        	getLogger().info("Description: " + getDescription());
        	getLogger().info("Usage: " + getCommand() + " <CA name> <PEM file> [-initauthorization]\n");
			getLogger().info("Add the argument initauthorization if you are importing an initial administration CA, and this will be the first CA in your system. Only used during installation when there is no local AdminCA on the EJBCA instance, but an external CA is used for administration.\n");
			return;
		}
		String caName = args[1];
		String pemFile = args[2];
		List<String> argsList = CliTools.getAsModifyableList(args);
		boolean initAuth = argsList.remove("-initauthorization");
		try {
			Collection certs = CertTools.getCertsFromPEM(pemFile);
			if (certs.size() != 1) {
				throw new ErrorAdminCommandException("PEM file must only contain one CA certificate, this PEM file contains "+certs.size()+".");
			}
			if (initAuth) {
				String subjectdn = CertTools.getSubjectDN((Certificate)certs.iterator().next());
				Integer caid = new Integer(subjectdn.hashCode());
				getLogger().info("Initializing authorization module for caid: "+caid);
				initAuthorizationModule(caid.intValue());
			}
			getCAAdminSession().importCACertificate(getAdmin(), caName, certs);
			getLogger().info("Imported CA "+caName);			
		} catch (CertificateException e) {
			getLogger().error(e.getMessage());
		} catch (IOException e) {
			getLogger().error(e.getMessage());
		} catch (CreateException e) {
			getLogger().error(e.getMessage());
		} catch (AdminGroupExistsException e) {
			getLogger().error(e.getMessage());
		}
	}
}
