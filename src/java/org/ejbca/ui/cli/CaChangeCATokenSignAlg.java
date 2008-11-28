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

package org.ejbca.ui.cli;

import java.util.Collection;

import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenInfo;
import org.ejbca.core.model.ca.catoken.SoftCATokenInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;

/**
 * Changes the signature algorithm and possible keyspec of a CA token.
 *
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class CaChangeCATokenSignAlg extends BaseAdminCommand {
	/**
	 * Creates a new instance of CaInfoCommand
	 *
	 * @param args command line arguments
	 */
	public CaChangeCATokenSignAlg(String[] args) {
        super(args, Admin.TYPE_CACOMMANDLINE_USER, "cli");
	}
	
	protected void usage() {
		getOutputStream().println();
		getOutputStream().println("Usage: changecatokensignalg <caname> <signature alg> [<keyspec>]");
		getOutputStream().println("Signature alg is one of SHA1WithRSA, SHA256WithRSA, SHA256WithRSAAndMGF1, SHA224WithECDSA, SHA256WithECDSA, or any other string available in the admin-GUI.");
		getOutputStream().println("Keyspec can only be set on soft CA tokens and is 1024, 2048, 4096 for RSA and a ECC curve name, i.e. prime192v1, secp256r1 etc from User Guide.");
		getOutputStream().println("  Existing CAs: ");
		try {
			// Print available CAs
			Collection<Integer> cas = getCAAdminSession().getAvailableCAs(administrator);
			for (Integer caid : cas) {
				CAInfo info = getCAAdminSession().getCAInfo(administrator, caid);
				getOutputStream().println("    "+info.getName()+": "+info.getCATokenInfo().getSignatureAlgorithm());				
			}
		} catch (Exception e) {
			e.printStackTrace();
			getOutputStream().print("<unable to fetch available CA>");
		}
		getOutputStream().println();
	}

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		trace(">execute()");
		CertTools.installBCProvider(); // need this for CVC certificate
		if ( args.length<3 ) {
			usage();
			return;
		}

		try {
			String caName = args[1];
			CAInfo cainfo = getCAAdminSession().getCAInfo(administrator, caName);
			String signAlg = args[2];
			getOutputStream().println("Setting new signature algorithm: " + signAlg);
			CATokenInfo tokeninfo = cainfo.getCATokenInfo();
			tokeninfo.setSignatureAlgorithm(signAlg);
			if (args.length > 3) {
				String keyspec = args[3];
				if (tokeninfo instanceof SoftCATokenInfo) {
					SoftCATokenInfo sinfo = (SoftCATokenInfo) tokeninfo;
					getOutputStream().println("Setting new signature keyspec: " + keyspec);
					sinfo.setSignKeySpec(keyspec);
				} else {
					getOutputStream().println("CA token is not a soft token, not setting keyspec.");
				}
			}
			cainfo.setCATokenInfo(tokeninfo);
			getCAAdminSession().editCA(administrator, cainfo);
			getOutputStream().println("CA token signature algorithm for CA changed.");
		} catch (Exception e) {
			getOutputStream().println("Error: " + e.getMessage());
			usage();
		}
		trace("<execute()");
	}
}
