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
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.log.Admin;

/**
 * Changes the certificate profile of a CA.
 *
 * @author Lars
 * @version $Id: CaChangeCertProfileCommand.java,v 1.1 2008-03-26 13:22:49 anatom Exp $
 */
public class CaChangeCertProfileCommand extends BaseAdminCommand {
	/**
	 * Creates a new instance of CaInfoCommand
	 *
	 * @param args command line arguments
	 */
	public CaChangeCertProfileCommand(String[] args) {
        super(args, Admin.TYPE_CACOMMANDLINE_USER, "cli");
	}
	
	protected void usage() {
		getOutputStream().println();
		getOutputStream().println("Usage: changecertprofile <caname> <certificateprofile>");
		
		getOutputStream().print("  Existing CAs: ");
		try {
			// Print available CAs
			Collection<Integer> cas = getCAAdminSessionRemote().getAvailableCAs(administrator);
			boolean first = true;
			for (Integer caid : cas) {
				if (first) {
					first = false;					
				} else {
					getOutputStream().print(", ");
				}
				CAInfo info = getCAAdminSessionRemote().getCAInfo(administrator, caid);
				getOutputStream().print(info.getName());				
			}
		} catch (Exception e) {
			getOutputStream().print("<unable to fetch available CA>");
		}
		try {
			// Print available Root CA and Sub CA profiles
			Collection<Integer> cpssub = getCertificateStoreSession().getAuthorizedCertificateProfileIds(administrator, CertificateDataBean.CERTTYPE_SUBCA);
			Collection<Integer> cpsroot = getCertificateStoreSession().getAuthorizedCertificateProfileIds(administrator, CertificateDataBean.CERTTYPE_ROOTCA);
			HashMap<String,Collection<Integer>> cps = new HashMap<String,Collection<Integer>>();
			cps.put("Root CA profiles: ", cpsroot);
			cps.put("Sub CA profiles: ", cpssub);
			Set<String> entries = cps.keySet();
			Iterator<String> keys = entries.iterator();
			while (keys.hasNext()) {
				String type = keys.next();
				getOutputStream().println();
				getOutputStream().print(type);
				Collection<Integer> col = cps.get(type);
				boolean first = true;
				for (Integer profid: col) {
					if (first) {
						first = false;
					} else {
						getOutputStream().print(", ");
					}
					getOutputStream().print(getCertificateStoreSession().getCertificateProfileName(administrator, profid));					
				}
			}
		} catch (Exception e) {
			getOutputStream().print("<unable to fetch available certificate profile>");
		}
		getOutputStream().println();
	}

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		debug(">execute()");
		if ( args.length<3 ) {
			usage();
			return;
		}

		try {
		    final String caName = args[1];
		    {
		        final CAInfo cainfo = getCAAdminSessionRemote().getCAInfo(administrator, caName);
		        final String certProfileName = args[2];
		        debug("Searching for Certificate Profile " + certProfileName);
		        final int certificateprofileid = getCertificateStoreSession().getCertificateProfileId(administrator, certProfileName);
		        if (certificateprofileid == SecConst.PROFILE_NO_PROFILE) {
		            error("Certificate Profile " + certProfileName + " doesn't exists.");
		            throw new Exception("Certificate Profile '" + certProfileName + "' doesn't exists.");
		        }
                cainfo.setCertificateProfileId(certificateprofileid);
                getCAAdminSessionRemote().editCA(administrator, cainfo);
		    }{
                final CAInfo cainfo = getCAAdminSessionRemote().getCAInfo(administrator, caName);
		        getOutputStream().println("Certificate profile for CA changed:");
		        getOutputStream().println("CA Name: " + caName);
		        getOutputStream().println("Certificate Profile: " + getCertificateStoreSession().getCertificateProfileName(administrator, cainfo.getCertificateProfileId()));
		    }
		} catch (Exception e) {
			getOutputStream().println("Error: " + e.getMessage());
			usage();
		}
		debug("<execute()");
	}
}
