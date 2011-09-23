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

import java.io.File;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Imports a certificate file to the database.
 *
 * @author Marco Ferrante, (c) 2005 CSITA - University of Genoa (Italy)
 * @version $Id$
 */
public class CaImportCertCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "importcert"; }
	public String getDescription() { return "Imports a certificate file to the database"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        args = parseUsernameAndPasswordFromArgs(args);
        
        getLogger().trace(">execute()");
		if ((args.length < 7) || (args.length > 9)) {
			usage(cliUserName, cliPassword);
			return;
		}
		try {
			CryptoProviderTools.installBCProvider();
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
				status = SecConst.CERT_ACTIVE;
			}
			else if ("REVOKED".equalsIgnoreCase(active)) {
				status = SecConst.CERT_REVOKED;
			}
			else {
				throw new Exception("Invalid certificate status.");
			}
			
			Certificate certificate = loadcert(certfile);
			String fingerprint = CertTools.getFingerprintAsString(certificate);
			if (ejb.getCertStoreSession().findCertificateByFingerprint(fingerprint) != null) {
				throw new Exception("Certificate number '" + CertTools.getSerialNumberAsString(certificate) + "' is already present.");
			}
			// Certificate has expired, but we are obviously keeping it for archival purposes
			if (CertTools.getNotAfter(certificate).compareTo(new java.util.Date()) < 0) {
				status = SecConst.CERT_ARCHIVED;
			}
			
			// Check if username already exists.
			EndEntityInformation userdata = ejb.getEndEntityAccessSession().findUser(getAdmin(cliUserName, cliPassword), username);
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
				getLogger().debug("Searching for End Entity Profile " + eeprofile);
				endentityprofileid = ejb.getEndEntityProfileSession().getEndEntityProfileId(getAdmin(cliUserName, cliPassword), eeprofile);
				if (endentityprofileid == 0) {
					getLogger().error("End Entity Profile " + eeprofile + " does not exist.");
					throw new Exception("End Entity Profile '" + eeprofile + "' does not exist.");
				}
			}
			
			int certificateprofileid = SecConst.CERTPROFILE_FIXED_ENDUSER;
			if (certificateprofile != null) {
				getLogger().debug("Searching for Certificate Profile " + certificateprofile);
				certificateprofileid = ejb.getCertificateProfileSession().getCertificateProfileId(certificateprofile);
				if (certificateprofileid == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
					getLogger().error("Certificate Profile " + certificateprofile + " does not exist.");
					throw new Exception("Certificate Profile '" + certificateprofile + "' does not exist.");
				}
			}
			
			CAInfo cainfo = getCAInfo(getAdmin(cliUserName, cliPassword), caname);
			
			getLogger().info("Trying to add user:");
			getLogger().info("Username: " + username);
			getLogger().info("Password (hashed only): " + password);
			getLogger().info("Email: " + email);
			getLogger().info("DN: " + CertTools.getSubjectDN(certificate));
			getLogger().info("CA Name: " + caname);
			getLogger().info("Certificate Profile: " + ejb.getCertificateProfileSession().getCertificateProfileName(certificateprofileid));
			getLogger().info("End Entity Profile: " +
			        ejb.getEndEntityProfileSession().getEndEntityProfileName(getAdmin(cliUserName, cliPassword), endentityprofileid));
			
			String subjectAltName = CertTools.getSubjectAlternativeName(certificate);
			if (subjectAltName != null) {
				getLogger().info("SubjectAltName: " + subjectAltName);
			}
			getLogger().info("Type: " + type);
			
			getLogger().debug("Loading/updating user " + username);
			if (userdata == null) {
				ejb.getUserAdminSession().addUser(getAdmin(cliUserName, cliPassword),
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
				if (status == SecConst.CERT_ACTIVE) {
					ejb.getUserAdminSession().setUserStatus(getAdmin(cliUserName, cliPassword), username, UserDataConstants.STATUS_GENERATED);
				}
				else {
					ejb.getUserAdminSession().setUserStatus(getAdmin(cliUserName, cliPassword), username, UserDataConstants.STATUS_REVOKED);
				}
				getLogger().info("User '" + username + "' has been added.");
			}
			else {
				ejb.getUserAdminSession().changeUser(getAdmin(cliUserName, cliPassword),
						username, password,
						CertTools.getSubjectDN(certificate),
						subjectAltName, email,
						false,
						endentityprofileid,
						certificateprofileid,
						type,
						SecConst.TOKEN_SOFT_BROWSERGEN,
						SecConst.NO_HARDTOKENISSUER,
						(status == SecConst.CERT_ACTIVE ?
								UserDataConstants.STATUS_GENERATED :
									UserDataConstants.STATUS_REVOKED),
									cainfo.getCAId());
				getLogger().info("User '" + username + "' has been updated.");
			}
			
			ejb.getCertStoreSession().storeCertificate(getAdmin(cliUserName, cliPassword),
					certificate, username,
					fingerprint,
					status, type, certificateprofileid, null, new Date().getTime());
			
			getLogger().info("Certificate number '" + CertTools.getSerialNumberAsString(certificate) + "' has been added.");
		}
		catch (Exception e) {
			getLogger().info("Error: " + e.getMessage());
			usage(cliUserName, cliPassword);
		}
		getLogger().trace("<execute()");
	}
	
	protected void usage(String cliUserName, String cliPassword) {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <username> <password> <caname> <status> <email> "
				+ "<certificate file> <endentityprofile> [<certificateprofile>]");
		getLogger().info(" Email can be set to null to try to use the value from the certificate.");
		String existingCas = "";
		Collection<Integer> cas = null;
		try {
			cas = ejb.getCaSession().getAvailableCAs(getAdmin(cliUserName, cliPassword));
			Iterator<Integer> iter = cas.iterator();
			while (iter.hasNext()) {
				int caid = ((Integer)iter.next()).intValue();
				CAInfo info = ejb.getCaSession().getCAInfo(getAdmin(cliUserName, cliPassword), caid);
				existingCas += (existingCas.length()==0?"":", ") + "\"" + info.getName() + "\"";
			}
		} catch (Exception e) {
			existingCas += "<unable to fetch available CA(s)>";
		}
		getLogger().info(" Existing CAs: " + existingCas);
		getLogger().info(" Status: ACTIVE, REVOKED");
		getLogger().info(" Certificate: must be PEM encoded");
		String endEntityProfiles = "";
		try {
			Collection<Integer> eps = ejb.getEndEntityProfileSession().getAuthorizedEndEntityProfileIds(getAdmin(cliUserName, cliPassword));
			Iterator<Integer> iter = eps.iterator();
			while (iter.hasNext()) {
				int epid = ((Integer)iter.next()).intValue();
				endEntityProfiles += (endEntityProfiles.length()==0?"":", ") + "\"" + ejb.getEndEntityProfileSession().getEndEntityProfileName(getAdmin(cliUserName, cliPassword), epid) + "\"";
			}
		}
		catch (Exception e) {
			endEntityProfiles += "<unable to fetch available end entity profiles>";
		}
		getLogger().info(" End entity profiles: " + endEntityProfiles);
		String certificateProfiles = "";
		try {
			Collection<Integer> cps = ejb.getCertificateProfileSession().getAuthorizedCertificateProfileIds(SecConst.CERTTYPE_ENDENTITY, cas);
			boolean first = true;
			Iterator<Integer> iter = cps.iterator();
			while (iter.hasNext()) {
				int cpid = ((Integer)iter.next()).intValue();
				if (first) {
					first = false;
				} else {
					certificateProfiles += ", ";
				}
				certificateProfiles += (certificateProfiles.length()==0?"":", ") + "\"" + ejb.getCertificateProfileSession().getCertificateProfileName(cpid) + "\"";
			}
		} catch (Exception e) {
			certificateProfiles += "<unable to fetch available certificate profile>";
		}
		getLogger().info(" Certificate profiles: " + certificateProfiles);
		getLogger().info(" If an End entity profile is selected it must allow selected Certificate profiles.");
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
}
