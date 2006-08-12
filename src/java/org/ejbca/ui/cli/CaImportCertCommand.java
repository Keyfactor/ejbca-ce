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

import java.io.File;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;





/**
 * Imports a certificate file in the database.
 *
 * @author Marco Ferrante, (c) 2005 CSITA - University of Genoa (Italy)
 * @version $Id: CaImportCertCommand.java,v 1.5 2006-08-12 09:49:30 herrvendil Exp $
 */
public class CaImportCertCommand extends BaseCaAdminCommand {
	/**
	 * Creates a new instance of CaInfoCommand
	 *
	 * @param args command line arguments
	 */
	public CaImportCertCommand(String[] args) {
		super(args);
	}
	
	protected void usage() {
		getOutputStream().println();
		getOutputStream().println("Usage: importcert <username> <password> <caname> <status> "
				+ "<certificate file> "
				+ "[<endentityprofile> | <endentityprofile> <certificateprofile>]");
		
		getOutputStream().print("  Existing CAs: ");
		try {
			Collection cas = getCAAdminSessionRemote().getAvailableCAs(administrator);
			boolean first = true;
			Iterator iter = cas.iterator();
			while (iter.hasNext()) {
				int caid = ((Integer)iter.next()).intValue();
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
		getOutputStream().println();
		getOutputStream().println("  Status: ACTIVE, REVOKED");
		getOutputStream().println("  Certificate: must be PEM encoded");
		getOutputStream().print("  End entity profiles: ");
		try {
			Collection eps = getRaAdminSession().getAuthorizedEndEntityProfileIds(administrator);
			boolean first = true;
			Iterator iter = eps.iterator();
			while (iter.hasNext()) {
				int epid = ((Integer)iter.next()).intValue();
				if (first) {
					first = false;
				} else {
					getOutputStream().print(", ");
				}
				getOutputStream().print(getRaAdminSession().getEndEntityProfileName(administrator, epid));
			}
		}
		catch (Exception e) {
			getOutputStream().print("<unable to fetch available end entity profiles>");
		}
		getOutputStream().println();
		getOutputStream().print("  Certificate profiles: ");
		try {
			Collection cps = getCertificateStoreSession().getAuthorizedCertificateProfileIds(administrator, CertificateDataBean.CERTTYPE_ENDENTITY);
			boolean first = true;
			Iterator iter = cps.iterator();
			while (iter.hasNext()) {
				int cpid = ((Integer)iter.next()).intValue();
				if (first) {
					first = false;
				} else {
					getOutputStream().print(", ");
				}
				getOutputStream().print(getCertificateStoreSession().getCertificateProfileName(administrator, cpid));
			}
		} catch (Exception e) {
			getOutputStream().print("<unable to fetch available certificate profile>");
		}
		getOutputStream().println();
		getOutputStream().println("  If an End entity profile is selected it must allow selected Certificate profiles.");
		getOutputStream().println();
	}
	
	protected X509Certificate loadcert(String filename) throws Exception {
		File certfile = new File(filename);
		if (!certfile.exists()) {
			throw new Exception(filename + " is not a file.");
		}
		try {
			byte[] bytes = FileTools.getBytesFromPEM(
					FileTools.readFiletoBuffer(filename),
					"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
			X509Certificate cert = CertTools.getCertfromByteArray(bytes);
			return cert;
		} catch (java.io.IOException ioe) {
			throw new Exception("Error reading " + filename + ": " + ioe.toString());
		} catch (java.security.cert.CertificateException ce) {
			throw new Exception(filename + " is not a valid X.509 certificate: " + ce.toString());
		} catch (Exception e) {
			throw new Exception("Error parsing certificate from " + filename + ": " + e.toString());
		}
	}
		
	
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
		//getOutputStream().println("Certificate import tool. V 1.1, (c) 2005 CSITA - University of Genoa (Italy)");
		debug(">execute()");
		if ((args.length < 6) || (args.length > 8)) {
			usage();
			return;
		}
		
		try {
			int type = SecConst.USER_ENDUSER;
			int status;
			if ("ACTIVE".equalsIgnoreCase(args[4])) {
				status = CertificateDataBean.CERT_ACTIVE;
			}
			else if ("REVOKED".equalsIgnoreCase(args[4])) {
				status = CertificateDataBean.CERT_REVOKED;
			}
			else {
				throw new Exception("Invalid certificate status.");
			}
			
			X509Certificate certificate = loadcert(args[5]);
			String fingerprint = CertTools.getFingerprintAsString(certificate);
			if (getCertificateStoreSession().findCertificateByFingerprint(administrator, fingerprint) != null) {
				throw new Exception("Certificate number '" + certificate.getSerialNumber().toString() + "' is already present.");
			}
			if (certificate.getNotAfter().compareTo(new java.util.Date()) < 0) {
				status = CertificateDataBean.CERT_EXPIRED;
			}
			
			String username = args[1];
			// Check if username already exists.
			UserDataVO userdata = getAdminSession().findUser(administrator, username);
			if (userdata != null) {
				if (userdata.getStatus() != UserDataConstants.STATUS_REVOKED) {
					throw new Exception("User " + username +
					" already exists; only revoked user can be overwrite.");
				}
			}
			String password = args[2];
			CAInfo cainfo = getCAInfo(args[3]);
			
			CertTools.verify(certificate, cainfo.getCertificateChain());
			
			String email = CertTools.getEMailAddress(certificate);
			
			int endentityprofileid = SecConst.EMPTY_ENDENTITYPROFILE;
			if (args.length > 6) {
				debug("Searching for End Entity Profile " + args[6]);
				endentityprofileid = getRaAdminSession().getEndEntityProfileId(administrator, args[6]);
				if (endentityprofileid == 0) {
					error("End Entity Profile " + args[6] + " doesn't exists.");
					throw new Exception("End Entity Profile '" + args[6] + "' doesn't exists.");
				}
			}
			
			int certificateprofileid = SecConst.CERTPROFILE_FIXED_ENDUSER;
			if (args.length > 7) {
				debug("Searching for Certificate Profile " + args[7]);
				certificateprofileid = getCertificateStoreSession().getCertificateProfileId(administrator, args[7]);
				if (certificateprofileid == SecConst.PROFILE_NO_PROFILE) {
					error("Certificate Profile " + args[7] + " doesn't exists.");
					throw new Exception("Certificate Profile '" + args[7] + "' doesn't exists.");
				}
			}
			
			getOutputStream().println("Trying to add user:");
			getOutputStream().println("Username: " + username);
			getOutputStream().println("Password (hashed only): " + password);
			getOutputStream().println("DN: " + certificate.getSubjectDN());
			getOutputStream().println("CA Name: " + args[3]);
			getOutputStream().println("Certificate Profile: " + getCertificateStoreSession().getCertificateProfileName(administrator, certificateprofileid));
			getOutputStream().println("End Entity Profile: " +
					getRaAdminSession().getEndEntityProfileName(administrator, endentityprofileid));
			
			String subjectAltName = CertTools.getSubjectAlternativeName(certificate);
			if (subjectAltName != null) {
				getOutputStream().println("SubjectAltName: " + subjectAltName);
			}
			getOutputStream().println("Type: " + type);
			
			debug("Loading/updating user " + username);
			if (userdata == null) {
				getAdminSession().addUser(administrator,
						username, password,
						certificate.getSubjectDN().getName(),
						subjectAltName, email,
						false,
						endentityprofileid,
						certificateprofileid,
						type,
						SecConst.TOKEN_SOFT_BROWSERGEN,
						SecConst.NO_HARDTOKENISSUER,
						cainfo.getCAId());
				if (status == CertificateDataBean.CERT_ACTIVE) {
					getAdminSession().setUserStatus(administrator, username, UserDataConstants.STATUS_GENERATED);
				}
				else {
					getAdminSession().setUserStatus(administrator, username, UserDataConstants.STATUS_REVOKED);
				}
				getOutputStream().println("User '" + args[1] + "' has been added.");
			}
			else {
				getAdminSession().changeUser(administrator,
						username, password,
						certificate.getSubjectDN().getName(),
						subjectAltName, email,
						false,
						endentityprofileid,
						certificateprofileid,
						type,
						SecConst.TOKEN_SOFT_BROWSERGEN,
						SecConst.NO_HARDTOKENISSUER,
						(status == CertificateDataBean.CERT_ACTIVE ?
								UserDataConstants.STATUS_GENERATED :
									UserDataConstants.STATUS_REVOKED),
									cainfo.getCAId());
				getOutputStream().println("User '" + args[1] + "' has been updated.");
			}
			
			getCertificateStoreSession().storeCertificate(administrator,
					certificate, username,
					fingerprint,
					status, type);
			
			getOutputStream().println("Certificate number '" + certificate.getSerialNumber().toString() + "' has been added.");
		}
		catch (Exception e) {
			getOutputStream().println("Error: " + e.getMessage());
			usage();
		}
		debug("<execute()");
	}
}
