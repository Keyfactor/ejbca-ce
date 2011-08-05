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

import java.util.Collection;
import java.util.Properties;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.catoken.CATokenInfo;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Changes the signature algorithm and possible keyspec of a CA token.
 *
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class CaChangeCATokenSignAlg extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "changecatokensignalg"; }
	public String getDescription() { return "Changes the signature algorithm and possible keyspec of a CA token"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
		CryptoProviderTools.installBCProvider(); // need this for CVC certificate
		if ( args.length<3 ) {
			usage();
			return;
		}

		try {
			String caName = args[1];
			CAInfo cainfo = ejb.getCaSession().getCAInfo(getAdmin(), caName);
			String signAlg = args[2];
			getLogger().info("Setting new signature algorithm: " + signAlg);
			CATokenInfo tokeninfo = cainfo.getCATokenInfo();
			tokeninfo.setSignatureAlgorithm(signAlg);
			if (args.length > 3) {
				String keyspec = args[3];
				Properties prop = tokeninfo.getProperties();
				prop.setProperty(CryptoToken.KEYSPEC_PROPERTY, keyspec);
				tokeninfo.setProperties(prop);
			}
			cainfo.setCATokenInfo(tokeninfo);
			ejb.getCAAdminSession().editCA(getAdmin(), cainfo);
			getLogger().info("CA token signature algorithm for CA changed.");
		} catch (Exception e) {
			getLogger().error(e.getMessage());
			usage();
		}
		getLogger().trace("<execute()");
	}
    
	private void usage() {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <caname> <signature alg> [<keyspec>]");
		getLogger().info(" Signature alg is one of SHA1WithRSA, SHA256WithRSA, SHA256WithRSAAndMGF1, SHA224WithECDSA, SHA256WithECDSA, or any other string available in the admin-GUI.");
		getLogger().info(" Keyspec can be set on CA tokens and is 1024, 2048, 4096, 8192 for RSA and a ECC curve name, i.e. prime192v1, secp256r1 etc from User Guide.");
		getLogger().info(" Existing CAs: ");
		try {
			// Print available CAs
			Collection<Integer> cas = ejb.getCaSession().getAvailableCAs(getAdmin());
			for (Integer caid : cas) {
				CAInfo info = ejb.getCaSession().getCAInfo(getAdmin(), caid);
				getLogger().info("    "+info.getName()+": "+info.getCATokenInfo().getSignatureAlgorithm());				
			}
		} catch (Exception e) {
			e.printStackTrace();
			getLogger().error("<unable to fetch available CA>");
		}
	}
}
