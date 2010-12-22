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
 
package org.ejbca.ui.cli.ca;

import java.io.FileOutputStream;
import java.util.List;

import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CliTools;
import org.ejbca.util.CryptoProviderTools;

/**
 * Retrieves the latest CRL from a CA.
 *
 * @version $Id$
 */
public class CaGetCrlCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "getcrl"; }
	public String getDescription() { return "Retrieves the latest CRL from a CA"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		// Get and remove switches
		List<String> argsList = CliTools.getAsModifyableList(args);
		boolean deltaSelector = argsList.remove("-delta");
		boolean pem = argsList.remove("-pem");
		args = argsList.toArray(new String[0]);
		// Parse the rest of the arguments
		if (args.length < 3) {
			getLogger().info("Description: " + getDescription());
			getLogger().info("Usage: " + getCommand() + " [-delta] [-pem] <caname> <outfile>");
			getLogger().info(" -delta  Fetch the latest delta CRL. Default is regular CRL.");
			getLogger().info(" -pem    Use PEM encoding. Default is DER encoding.");
			return;
		}
		try {
			CryptoProviderTools.installBCProvider();
			// Perform CRL fetch
			String caname = args[1];
			String outfile = args[2];
			String issuerdn = getIssuerDN(caname);
			byte[] crl = ejb.getCrlSession().getLastCRL(getAdmin(), issuerdn, deltaSelector);
			if (crl != null) {
				FileOutputStream fos = new FileOutputStream(outfile);
				if (pem) {		
					fos.write(CertTools.getPEMFromCrl(crl));
				} else {					
					fos.write(crl);
				}
				fos.close();				
				getLogger().info("Wrote latest " + (deltaSelector?"delta ":"") + "CRL to " + outfile + " using " + (pem?"PEM":"DER") + " format");
			} else {
				getLogger().info("No " + (deltaSelector?"delta ":"") + "CRL exists for CA "+caname+".");				
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
    }
}
