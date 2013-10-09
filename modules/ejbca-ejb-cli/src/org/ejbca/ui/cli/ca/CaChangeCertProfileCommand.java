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
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Changes the certificate profile of a CA.
 *
 * @version $Id$
 */
public class CaChangeCertProfileCommand extends BaseCaAdminCommand {

    @Override
	public String getSubCommand() { return "changecertprofile"; }
    @Override
	public String getDescription() { return "Changes the certificate profile of a CA"; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
		CryptoProviderTools.installBCProvider(); // need this for CVC certificate
		
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
		
		if ( args.length<3 ) {
			usage(cliUserName, cliPassword);
			return;
		}
		try {
		    final String caName = args[1];
		    {
		        final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caName);
		        final String certProfileName = args[2];
		        getLogger().debug("Searching for Certificate Profile " + certProfileName);
		        final int certificateprofileid = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileId(certProfileName);
		        if (certificateprofileid == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
		        	getLogger().error("Certificate Profile " + certProfileName + " does not exist.");
		            throw new Exception("Certificate Profile '" + certProfileName + "' does not exist.");
		        }
                cainfo.setCertificateProfileId(certificateprofileid);
                ejb.getRemoteSession(CAAdminSessionRemote.class).editCA(getAuthenticationToken(cliUserName, cliPassword), cainfo);
		    }{
                final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caName);
                getLogger().info("Certificate profile for CA changed:");
                getLogger().info("CA Name: " + caName);
                getLogger().info("Certificate Profile: " + ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(cainfo.getCertificateProfileId()));
		    }
		} catch (Exception e) {
			getLogger().error(e.getMessage());
			usage(cliUserName, cliPassword);
		}
		getLogger().trace("<execute()");
	}

	protected void usage(String cliUserName, String cliPassword) {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <caname> <certificateprofile>");
		String existingCasInfo = " Existing CAs: ";
		Collection<Integer> cas = null;
		try {
			// Print available CAs
			cas = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCAs(getAuthenticationToken(cliUserName, cliPassword));
			boolean first = true;
			for (Integer caid : cas) {
				if (first) {
					first = false;					
				} else {
					existingCasInfo += ", ";
				}
				CAInfo info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caid);
				existingCasInfo += info.getName();				
			}
		} catch (Exception e) {
			existingCasInfo += "<unable to fetch available CA>";
		}
		getLogger().info(existingCasInfo);
		try {
			// Print available Root CA and Sub CA profiles
			Collection<Integer> cpssub = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getAuthorizedCertificateProfileIds(CertificateConstants.CERTTYPE_SUBCA, cas);
			Collection<Integer> cpsroot = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getAuthorizedCertificateProfileIds(CertificateConstants.CERTTYPE_ROOTCA, cas);
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
					profileInfo += ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(profid);					
				}
				getLogger().info(profileInfo);
			}
		} catch (Exception e) {
			getLogger().error("<unable to fetch available certificate profile>");
		}
	}
}
