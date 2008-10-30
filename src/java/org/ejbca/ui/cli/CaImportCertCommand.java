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
import java.security.cert.Certificate;
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
 * @version $Id$
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
		getOutputStream().println("Usage: importcert <username> <password> <caname> <status> <email> "
				+ "<certificate file> "
				+ "[<endentityprofile> | <endentityprofile> <certificateprofile>]");
		
		getOutputStream().println("Email can be set to null to try to use the value from the certificate.");
		getOutputStream().println();
		getOutputStream().print("  Existing CAs: ");
		try {
			Collection cas = getCAAdminSession().getAvailableCAs(administrator);
			boolean first = true;
			Iterator iter = cas.iterator();
			while (iter.hasNext()) {
				int caid = ((Integer)iter.next()).intValue();
				if (first) {
					first = false;					
				} else {
					getOutputStream().print(", ");
				}
				CAInfo info = getCAAdminSession().getCAInfo(administrator, caid);
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
	
	protected Certificate loadcert(String filename) throws Exception {
		File certfile = new File(filename);
		if (!certfile.exists()) {
			throw new Exception(filename + " is not a file.");
		}
		try {
			byte[] bytes = FileTools.getBytesFromPEM(
					FileTools.readFiletoBuffer(filename),
					"-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
			Certificate cert = CertTools.getCertfromByteArray(bytes);
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
		if ((args.length < 7) || (args.length > 9)) {
			usage();
			return;
		}
		
		try {
			String username = args[1];
			String password = args[2];
			String caname = args[3];
			String active = args[4];
			String email = args[5];
			String certfile = args[6];
			String eeprofile = null;
			if (args.length > 7) {
				eeprofile = args[7];
			}
			String certificateprofile = null;
			if (args.length > 8) {
				certificateprofile = args[8];				
			}
			
			int type = SecConst.USER_ENDUSER;
			int status;
			if ("ACTIVE".equalsIgnoreCase(active)) {
				status = CertificateDataBean.CERT_ACTIVE;
			}
			else if ("REVOKED".equalsIgnoreCase(active)) {
				status = CertificateDataBean.CERT_REVOKED;
			}
			else {
				throw new Exception("Invalid certificate status.");
			}
			
			Certificate certificate = loadcert(certfile);
			String fingerprint = CertTools.getFingerprintAsString(certificate);
			if (getCertificateStoreSession().findCertificateByFingerprint(administrator, fingerprint) != null) {
				throw new Exception("Certificate number '" + CertTools.getSerialNumberAsString(certificate) + "' is already present.");
			}
			if (CertTools.getNotAfter(certificate).compareTo(new java.util.Date()) < 0) {
				status = CertificateDataBean.CERT_EXPIRED;
			}
			
			// Check if username already exists.
			UserDataVO userdata = getUserAdminSession().findUser(administrator, username);
			if (userdata != null) {
				if (userdata.getStatus() != UserDataConstants.STATUS_REVOKED) {
					throw new Exception("User " + username +
					" already exists; only revoked user can be overwrite.");
				}
			}
			
			//CertTools.verify(certificate, cainfo.getCertificateChain());
			
			if (email.equalsIgnoreCase("null")) {
				email = CertTools.getEMailAddress(certificate);				
			}
			
			int endentityprofileid = SecConst.EMPTY_ENDENTITYPROFILE;
			if (eeprofile != null) {
				debug("Searching for End Entity Profile " + eeprofile);
				endentityprofileid = getRaAdminSession().getEndEntityProfileId(administrator, eeprofile);
				if (endentityprofileid == 0) {
					error("End Entity Profile " + eeprofile + " doesn't exists.");
					throw new Exception("End Entity Profile '" + eeprofile + "' doesn't exists.");
				}
			}
			
			int certificateprofileid = SecConst.CERTPROFILE_FIXED_ENDUSER;
			if (certificateprofile != null) {
				debug("Searching for Certificate Profile " + certificateprofile);
				certificateprofileid = getCertificateStoreSession().getCertificateProfileId(administrator, certificateprofile);
				if (certificateprofileid == SecConst.PROFILE_NO_PROFILE) {
					error("Certificate Profile " + certificateprofile + " doesn't exists.");
					throw new Exception("Certificate Profile '" + certificateprofile + "' doesn't exists.");
				}
			}
			
			CAInfo cainfo = getCAInfo(caname);
			
			getOutputStream().println("Trying to add user:");
			getOutputStream().println("Username: " + username);
			getOutputStream().println("Password (hashed only): " + password);
			getOutputStream().println("Email: " + email);
			getOutputStream().println("DN: " + CertTools.getSubjectDN(certificate));
			getOutputStream().println("CA Name: " + caname);
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
				getUserAdminSession().addUser(administrator,
						username, password,
						CertTools.getSubjectDN(certificate),
						subjectAltName, email,
						false,
						endentityprofileid,
						certificateprofileid,
						type,
						SecConst.TOKEN_SOFT_BROWSERGEN,
						SecConst.NO_HARDTOKENISSUER,
						cainfo.getCAId());
				if (status == CertificateDataBean.CERT_ACTIVE) {
					getUserAdminSession().setUserStatus(administrator, username, UserDataConstants.STATUS_GENERATED);
				}
				else {
					getUserAdminSession().setUserStatus(administrator, username, UserDataConstants.STATUS_REVOKED);
				}
				getOutputStream().println("User '" + username + "' has been added.");
			}
			else {
				getUserAdminSession().changeUser(administrator,
						username, password,
						CertTools.getSubjectDN(certificate),
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
				getOutputStream().println("User '" + username + "' has been updated.");
			}
			
			getCertificateStoreSession().storeCertificate(administrator,
					certificate, username,
					fingerprint,
					status, type);
			
			getOutputStream().println("Certificate number '" + CertTools.getSerialNumberAsString(certificate) + "' has been added.");
		}
		catch (Exception e) {
			getOutputStream().println("Error: " + e.getMessage());
			usage();
		}
		debug("<execute()");
	}
}
