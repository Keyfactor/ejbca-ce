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
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CliTools;

/**
 * Imports certificate files to the database for a given CA
 *
 * @version $Id$
 */
public class CaImportCertDirCommand extends BaseCaAdminCommand {

	@Override
	public String getSubCommand() { return "importcertdir"; }
	@Override
	public String getDescription() { return "Imports a directory with PEM encoded certficate file(s) to the database"; }

	private static final int STATUS_OK = 0;
	private static final int STATUS_REDUNDANT = 1;
	private static final int STATUS_CAMISMATCH = 2;
	private static final int STATUS_CONSTRAINTVIOLATION = 4;
	private static final int STATUS_GENERALIMPORTERROR = 5;

	@Override
    public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
		
		CryptoProviderTools.installBCProvider();

		// Process the switches and remove them from the argument list.
		List<String> argsList = CliTools.getAsModifyableList(args);

		// Specifies whether the import should resume in case of errors, or stop
		// on first one. Default is stop.
		boolean resumeOnError = argsList.remove("-resumeonerror");
		args = argsList.toArray(new String[argsList.size()]);

		if (args.length != 7) {
			usage(cliUserName, cliPassword);
			return;
		}
		try {
			// Parse arguments into more coder friendly variable names and validate switches
			final String usernameFilter = args[1];
			final String caName = args[2];
			final String active = args[3];
			final String certificateDir = args[4];
			final String eeProfile = args[5];
			final String certificateProfile = args[6];				
			final int status;
			if ("ACTIVE".equalsIgnoreCase(active)) {
				status = CertificateConstants.CERT_ACTIVE;
			} else if ("REVOKED".equalsIgnoreCase(active)) {
				status = CertificateConstants.CERT_REVOKED;
			} else {
				throw new Exception("Invalid certificate status.");
			}
			if (!usernameFilter.equalsIgnoreCase("DN") && 
					!usernameFilter.equalsIgnoreCase ("CN") &&
					!usernameFilter.equalsIgnoreCase("FILE")) {
				throw new Exception(usernameFilter + "is not a valid option. Currently only \"DN\", \"CN\" and \"FILE\" username-source are implemented");
			}
			// Fetch CA info
			final CAInfo caInfo = getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caName);
			final X509Certificate cacert = (X509Certificate) caInfo.getCertificateChain().iterator().next();
			final String issuer = CertTools.stringToBCDNString(cacert.getSubjectDN().toString());
			getLogger().info("CA: " + issuer);
			// Fetch End Entity Profile info
			getLogger().debug("Searching for End Entity Profile " + eeProfile);
			final int endEntityProfileId;
			try {
			    endEntityProfileId = ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileId(eeProfile);
			} catch(EndEntityProfileNotFoundException e) {
			    getLogger().error("ERROR: End Entity Profile " + eeProfile + " does not exist.");
                throw new Exception("End Entity Profile '" + eeProfile + "' does not exist.", e);
			}
			// Fetch Certificate Profile info
			getLogger().debug("Searching for Certificate Profile " + certificateProfile);
			int certificateProfileId = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileId(certificateProfile);
			if (certificateProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
				getLogger().error("ERROR: Certificate Profile " + certificateProfile + " does not exist.");
				throw new Exception("Certificate Profile '" + certificateProfile + "' does not exist.");
			}
			// Get all files in the directory to import from and try to read and import each as a certificate
			final File dir = new File(certificateDir);
			if ( !dir.isDirectory() ) {
				throw new IOException ("'"+certificateDir+"' is not a directory.");
			}
			final File files[] = dir.listFiles();
			if ( files==null || files.length<1 ) {
				throw new IOException("No files in directory '" + dir.getCanonicalPath() + "'. Nothing to do.");
			}
			int redundant = 0;
			int caMismatch = 0;
			int readError = 0;
			int constraintViolation = 0;
			int generalImportError = 0;
			int importOk = 0;
			for (final File file : files) {

				final String filename = file.getName();
				final X509Certificate certificate;

				// Read certificate from the file.
				try {
					certificate = (X509Certificate) loadcert(file.getCanonicalPath());
				} catch (Exception e) {
					getLogger().error("ERROR: A problem was encountered while reading the certificate, file: " + filename);
					readError++;
					if (!resumeOnError) {
						throw e;
					} else {
						getLogger().error(e.getMessage());
					}

					// We have to continue here since the rest of the code depends
					// on reading of certificate.
					continue;
				}

				// Generate the end entity username.

				// Use the filename as username by default since it's something that's always present.
				String username = filename;

				// Use the DN if requested, but fall-back to filename if DN is empty.
				if (usernameFilter.equalsIgnoreCase("DN")) {
					String dn = CertTools.getSubjectDN(certificate);
					if (dn == null || dn.length() == 0) {
						getLogger().warn("WARN: Certificate with serial '" + CertTools.getSerialNumberAsString(certificate) + "' lacks DN, filename used instead, file: " + filename);
					} else {
						username = dn;
					}
				// Use CN if requested, but fallback to DN if it's empty, or if
				// DN is empty as well, fall back to filename.
				} else if (usernameFilter.equalsIgnoreCase("CN")) {
					String dn = CertTools.getSubjectDN(certificate);
					String cn = CertTools.getPartFromDN(dn, "CN");

					if (cn == null || cn.length() == 0) {
						if (dn == null || dn.length() == 0) {
							getLogger().warn("WARN: Certificate with serial '" + CertTools.getSerialNumberAsString(certificate) + "' lacks both CN and DN, filename used instead, file: " +filename);
						} else {
							username = dn;
							getLogger ().warn("WARN: Certificate with serial '" + CertTools.getSerialNumberAsString(certificate) + "' lacks CN, DN used instead, file: " +filename);
						}
					} else {
						username = cn;
					}
				}

				// Assume the worst-case scenario. We have to set this to
				// something due to try/catch block.
				int performImportStatus = STATUS_GENERALIMPORTERROR;

				try {
					performImportStatus = performImport(cliUserName, cliPassword, certificate, status, endEntityProfileId, certificateProfileId, cacert, caInfo, filename, issuer, username);
				} catch (UserDoesntFullfillEndEntityProfile e) {
					getLogger().error("ERROR: End entity profile constraints were violated by the certificate, file: " + filename);
					performImportStatus = STATUS_CONSTRAINTVIOLATION;
					if (!resumeOnError) {
						throw e;
					} else {
						getLogger().error(e.getMessage());
					}
				} catch (Exception e) {
					getLogger().error("ERROR: Unclassified general import error has occurred, file: " + filename);
					performImportStatus = STATUS_GENERALIMPORTERROR;
					if (!resumeOnError) {
						throw e;
					} else {
						getLogger().error(e.getMessage());
					}
				}

				switch (performImportStatus) {
				case STATUS_REDUNDANT: redundant++; break;
				case STATUS_CAMISMATCH: caMismatch++; break;
				case STATUS_CONSTRAINTVIOLATION: constraintViolation++; break;
				case STATUS_OK: importOk++; break;
				default: generalImportError++; break;
				}
			}
			// Print resulting statistics
			getLogger().info("\nImport summary:");
			getLogger().info(importOk + " certificates were imported with success (STATUS_OK)");
			if (redundant > 0) {
				getLogger().info(redundant + " certificates were already present in the database (STATUS_REDUNDANT)");
			}
			if (caMismatch > 0) {
				getLogger().info(caMismatch + " certificates were not issued by the specified CA (STATUS_CAMISMATCH)");
			}
			if (readError > 0) {
				getLogger().info(readError + " certificates could not be read (STATUS_READERROR)");
			}
			if ( constraintViolation > 0) {
				getLogger().info(constraintViolation + " certificates violated the end entity constraints (STATUS_CONSTRAINTVIOLATION)");
			}
			if ( generalImportError > 0) {
				getLogger().info(generalImportError + " certificates were not imported due to other errors (STATUS_GENERALIMPORTERROR)");
			}
		} catch (Exception e) {
			getLogger().error("ERROR: " + e.getMessage());
		}
		getLogger().trace("<execute()");
	}

	/**
	 * Imports a certificate to the database and creates a user if necessary.
	 * @return STATUS_OK, STATUS_REDUNDANT or STATUS_CAMISMATCH
	 */
	private int performImport(String cliUserName, String cliPassword, X509Certificate certificate, int status, int endEntityProfileId, int certificateProfileId,
			                   X509Certificate cacert, CAInfo caInfo, String filename, String issuer, String username) throws Exception {
		final String fingerprint = CertTools.getFingerprintAsString(certificate);
		if (ejb.getRemoteSession(CertificateStoreSessionRemote.class).findCertificateByFingerprint(fingerprint) != null) {
			getLogger ().info("SKIP: Certificate with serial '" + CertTools.getSerialNumberAsString(certificate) + "' is already present, file: " +filename);
			return STATUS_REDUNDANT;
		}

		// Strip the username of dangerous characters before using it.
		username = StringTools.strip(username);

		final Date now = new Date();
		// Certificate has expired, but we are obviously keeping it for archival purposes
		if (CertTools.getNotAfter(certificate).compareTo(now) < 0) {
			status = CertificateConstants.CERT_ARCHIVED;
		}
		if (!cacert.getSubjectX500Principal().equals(certificate.getIssuerX500Principal())){
			getLogger().error("ERROR: The certificates issuer subject DN does not match with the specified CA's subject, file: " + filename);
			return STATUS_CAMISMATCH;
		}
		try {
			certificate.verify(cacert.getPublicKey());
		} catch (GeneralSecurityException gse) {
			getLogger().error("ERROR: The certificate's signature does not validate against the specified CA, file: " + filename);
			return STATUS_CAMISMATCH;
		}
		getLogger().debug("Loading/updating user " + username);
		// Check if username already exists.
		EndEntityInformation userdata = ejb.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAuthenticationToken(cliUserName, cliPassword), username);
		if (userdata==null) {
			// Add a "user" to map this certificate to
			final String subjectAltName = CertTools.getSubjectAlternativeName(certificate);
			final String email = CertTools.getEMailAddress(certificate);				
			userdata = new EndEntityInformation(username, CertTools.getSubjectDN(certificate), caInfo.getCAId(), subjectAltName, email,
			        EndEntityConstants.STATUS_GENERATED, new EndEntityType(EndEntityTypes.ENDUSER), endEntityProfileId,
					certificateProfileId, null, null, SecConst.TOKEN_SOFT_BROWSERGEN, SecConst.NO_HARDTOKENISSUER, null);
			userdata.setPassword("foo123");
			ejb.getRemoteSession(EndEntityManagementSessionRemote.class).addUser(getAuthenticationToken(cliUserName, cliPassword), userdata, false);
			getLogger().info("User '" + username + "' has been added.");
		}
		// addUser always adds the user with STATUS_NEW (even if we specified otherwise)
		// We always override the userdata with the info from the certificate even if the user existed.
		userdata.setStatus(EndEntityConstants.STATUS_GENERATED);
		ejb.getRemoteSession(EndEntityManagementSessionRemote.class).changeUser(getAuthenticationToken(cliUserName, cliPassword), userdata, false);
		getLogger().info("User '" + username + "' has been updated.");
		// Finally import the certificate and revoke it if necessary
		ejb.getRemoteSession(CertificateStoreSessionRemote.class).storeCertificate(getAuthenticationToken(cliUserName, cliPassword),
		                                           certificate, username, fingerprint,
		                                           CertificateConstants.CERT_ACTIVE,
		                                           CertificateConstants.CERTTYPE_ENDENTITY, 
		                                           certificateProfileId, null, now.getTime());
		if (status == CertificateConstants.CERT_REVOKED) {
			ejb.getRemoteSession(EndEntityManagementSessionRemote.class).revokeCert(getAuthenticationToken(cliUserName, cliPassword), certificate.getSerialNumber(), issuer, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
		}
		getLogger().info("Certificate with serial '" + CertTools.getSerialNumberAsString(certificate) + "' has been added.");
		return STATUS_OK;
	}

	/** Print out usage. */
	private void usage(String cliUserName, String cliPassword) {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <username-source> <caname> <status> <certificate dir> <endentityprofile> <certificateprofile> [-resumeonerror]");
		getLogger().info("The import will proceed as long as the only error encountered is a mismatch between the signer of end entity certificate and the specified certification authority. If the -resumeonerror options is provided, the import will resume even in case of more critical errors (such as violation of end entity constraints, malformed files etc). The offending files will be printed-out to the standard output, and a summary will contain exact numbers on imported and failed certificates.");
		getLogger().info(" Username-source: \"DN\" means use certificate's SubjectDN as username, \"CN\" means use certificate subject's common name as username and \"FILE\" means user the file's name as username");
		// List available CAs by name
		getLogger().info(" Available CAs: " + getAvailableCasString(cliUserName, cliPassword));
		getLogger().info(" Status: ACTIVE, REVOKED");
		getLogger().info(" Certificate dir: A directory where all files are PEM encoded certificates");
		getLogger().info(" Available end entity profiles: " + getAvailableEepsString(cliUserName, cliPassword));
		getLogger().info(" Available certificate profiles: " + getAvailableEndUserCpsString(cliUserName, cliPassword));
	}
	
	/** Load a PEM encoded certificate from the specified file. */
	private Certificate loadcert(final String filename) throws Exception {
		try {
			final byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(filename), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
			return CertTools.getCertfromByteArray(bytes);
		} catch (IOException ioe) {
			throw new Exception("Error reading " + filename + ": " + ioe.toString());
		} catch (CertificateException ce) {
			throw new Exception(filename + " is not a valid X.509 certificate: " + ce.toString());
		} catch (Exception e) {
			throw new Exception("Error parsing certificate from " + filename + ": " + e.toString());
		}
	}
}

