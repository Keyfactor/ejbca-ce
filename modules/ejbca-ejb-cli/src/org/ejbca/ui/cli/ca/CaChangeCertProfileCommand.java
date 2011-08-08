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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.model.SecConst;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Changes the certificate profile of a CA.
 *
 * @author Lars
 * @version $Id$
 */
public class CaChangeCertProfileCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "changecertprofile"; }
	public String getDescription() { return "Changes the certificate profile of a CA"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
		CryptoProviderTools.installBCProvider(); // need this for CVC certificate
		if ( args.length<3 ) {
			usage();
			return;
		}
		try {
		    final String caName = args[1];
		    {
		        final CAInfo cainfo = ejb.getCaSession().getCAInfo(getAdmin(), caName);
		        final String certProfileName = args[2];
		        getLogger().debug("Searching for Certificate Profile " + certProfileName);
		        final int certificateprofileid = ejb.getCertificateProfileSession().getCertificateProfileId(certProfileName);
		        if (certificateprofileid == SecConst.PROFILE_NO_PROFILE) {
		        	getLogger().error("Certificate Profile " + certProfileName + " doesn't exists.");
		            throw new Exception("Certificate Profile '" + certProfileName + "' doesn't exists.");
		        }
                cainfo.setCertificateProfileId(certificateprofileid);
                ejb.getCAAdminSession().editCA(getAdmin(), cainfo);
		    }{
                final CAInfo cainfo = ejb.getCaSession().getCAInfo(getAdmin(), caName);
                getLogger().info("Certificate profile for CA changed:");
                getLogger().info("CA Name: " + caName);
                getLogger().info("Certificate Profile: " + ejb.getCertificateProfileSession().getCertificateProfileName(cainfo.getCertificateProfileId()));
		    }
		} catch (Exception e) {
			getLogger().error(e.getMessage());
			usage();
		}
		getLogger().trace("<execute()");
	}

	protected void usage() {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <caname> <certificateprofile>");
		String existingCasInfo = " Existing CAs: ";
		Collection<Integer> cas = null;
		try {
			// Print available CAs
			cas = ejb.getCaSession().getAvailableCAs(getAdmin());
			boolean first = true;
			for (Integer caid : cas) {
				if (first) {
					first = false;					
				} else {
					existingCasInfo += ", ";
				}
				CAInfo info = ejb.getCaSession().getCAInfo(getAdmin(), caid);
				existingCasInfo += info.getName();				
			}
		} catch (Exception e) {
			existingCasInfo += "<unable to fetch available CA>";
		}
		getLogger().info(existingCasInfo);
		try {
			// Print available Root CA and Sub CA profiles
			Collection<Integer> cpssub = ejb.getCertificateProfileSession().getAuthorizedCertificateProfileIds(SecConst.CERTTYPE_SUBCA, cas);
			Collection<Integer> cpsroot = ejb.getCertificateProfileSession().getAuthorizedCertificateProfileIds(SecConst.CERTTYPE_ROOTCA, cas);
			HashMap<String,Collection<Integer>> cps = new HashMap<String,Collection<Integer>>();
			cps.put("Root CA profiles: ", cpsroot);
			cps.put("Sub CA profiles: ", cpssub);
			Set<String> entries = cps.keySet();
			Iterator<String> keys = entries.iterator();
			while (keys.hasNext()) {
				String type = keys.next();
				String profileInfo = type;
				Collection<Integer> col = cps.get(type);
				boolean first = true;
				for (Integer profid: col) {
					if (first) {
						first = false;
					} else {
						profileInfo += ", ";
					}
					profileInfo += ejb.getCertificateProfileSession().getCertificateProfileName(profid);					
				}
				getLogger().info(profileInfo);
			}
		} catch (Exception e) {
			getLogger().error("<unable to fetch available certificate profile>");
		}
	}
}
