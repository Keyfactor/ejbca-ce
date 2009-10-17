package org.ejbca.ui.cli.ca;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;

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
        	getLogger().info("Usage: " + getCommand() + " <CA name> <PEM file>\n");
			return;
		}
		String caName = args[1];
		String pemFile = args[2];
		try {
			Collection certs = CertTools.getCertsFromPEM(pemFile);
			getCAAdminSession().importCACertificate(getAdmin(), caName, certs);
		} catch (CertificateException e) {
			getLogger().error(e.getMessage());
		} catch (IOException e) {
			getLogger().error(e.getMessage());
		} catch (Exception e) {	// CreateException
			getLogger().error(e.getMessage());
		}
	}
}
