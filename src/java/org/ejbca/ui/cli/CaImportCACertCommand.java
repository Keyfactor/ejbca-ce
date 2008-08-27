package org.ejbca.ui.cli;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Collection;

import javax.ejb.CreateException;

import org.ejbca.util.CertTools;

/**
 * Imports a PEM file and created a new external CA representation from it.
 */
public class CaImportCACertCommand extends BaseCaAdminCommand {

	public CaImportCACertCommand(String[] args) {
		super(args);
	}

	/**
	 * @see org.ejbca.ui.cli.IAdminCommand
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		if (args.length < 3) {
			String msg = "Usage: ca importcacert <CA name> <PEM file>\n";
			throw new IllegalAdminCommandException(msg);
		}
		String caName = args[1];
		String pemFile = args[2];
		Collection certs;
		try {
			certs = CertTools.getCertsFromPEM(pemFile);
			getCAAdminSession().importCACertificate(administrator, caName, certs);
		} catch (CertificateException e) {
			error(e.getMessage());
		} catch (IOException e) {
			error(e.getMessage());
		} catch (CreateException e) {
			error(e.getMessage());
		}
	}
}
