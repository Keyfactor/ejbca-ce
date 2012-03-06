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

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Imports a CRL file to the database.
 *
 * @author Anders Rundgren
 * @version $Id$
 */
public class CaImportCRLCommand extends BaseCaAdminCommand {

	@Override
	public String getMainCommand() { return MAINCOMMAND; }
	@Override
	public String getSubCommand() { return "importcrl"; }
	@Override
	public String getDescription() { return "Imports a CRL file (and updates certificates) to the database"; }

	private static final String STRICT_OP = "STRICT";
	private static final String LENIENT_OP = "LENIENT";
	private static final String ADAPTIVE_OP = "ADAPTIVE";

	@Override
	public void execute(String[] args) throws ErrorAdminCommandException {
		getLogger().trace(">execute()");
		CryptoProviderTools.installBCProvider();
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
	        
		
		if (args.length != 4 || (!args[3].equalsIgnoreCase(STRICT_OP) && !args[3].equalsIgnoreCase(LENIENT_OP) && !args[3].equalsIgnoreCase(ADAPTIVE_OP))) {
			usage(cliUserName, cliPassword);
			return;
		}
		try {
			// Parse arguments
			final String caname = args[1];
			final String crl_file = args[2];
			final boolean strict = args[3].equalsIgnoreCase(STRICT_OP);
			final boolean adaptive = args[3].equalsIgnoreCase(ADAPTIVE_OP);
			// Fetch CA and related info
			final CAInfo cainfo = getCAInfo(getAdmin(cliUserName, cliPassword), caname);
			final X509Certificate cacert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
			final String issuer = CertTools.stringToBCDNString(cacert.getSubjectDN().toString());
			getLogger().info("CA: " + issuer);
			// Read the supplied CRL and verify that it is issued by the specified CA
			final X509CRL x509crl = (X509CRL) CertTools.getCertificateFactory().generateCRL(new FileInputStream (crl_file));
	        if (!x509crl.getIssuerX500Principal().getName().equals(cacert.getSubjectX500Principal().getName())){
	        	throw new IOException ("CRL wasn't issued by this CA");
	        }
	        x509crl.verify(cacert.getPublicKey());
	        int crl_no = CrlExtensions.getCrlNumber(x509crl).intValue();
	        getLogger().info("Processing CRL #" + crl_no);
	        int miss_count = 0;	// Number of certs not already in database
	        int revoked = 0;	// Number of certs activly revoked by this algorithm
	        int already_revoked = 0;	// Number of certs already revoked in database and ignored in non-strict mode
	        final String missing_user_name = "*** Missing During CRL Import to: " + caname;
	        @SuppressWarnings("unchecked")
            Set<X509CRLEntry> entries = (Set<X509CRLEntry>) x509crl.getRevokedCertificates();
	        if (entries != null) {
	            for (final X509CRLEntry entry : entries) {
	                final BigInteger serialNr = entry.getSerialNumber();
	                final String serialHex = serialNr.toString(16).toUpperCase();
	                final String username = ejb.getRemoteSession(CertificateStoreSessionRemote.class).findUsernameByCertSerno(serialNr, issuer);
	                // If this certificate exists and has an assigned username, we keep using that. Otherwise we create this coupling to a user.
	                if (username == null) {
	                    getLogger().info ("Certificate '"+ serialHex +"' missing in the database");
	                    if (strict) {
	                        throw new IOException ("Aborted! Running in strict mode and is missing certificate in database.");
	                    }
	                    miss_count++;
	                    if (!adaptive) {
	                        continue;
	                    }
	                    final Date time = new Date();              // time from which certificate is valid
	                    final KeyPair key_pair = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);     
	                    final X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
	                    final X500Principal dnName = new X500Principal("CN=Dummy Missing in Imported CRL, serialNumber=" + serialHex);
	                    certGen.setSerialNumber(serialNr);
	                    certGen.setIssuerDN(cacert.getSubjectX500Principal());
	                    certGen.setNotBefore(time);
	                    certGen.setNotAfter(new Date (time.getTime() + 1000L * 60 * 60 * 24 * 365 * 10));  // 10 years of life
	                    certGen.setSubjectDN(dnName);                       // note: same as issuer
	                    certGen.setPublicKey(key_pair.getPublic());
	                    certGen.setSignatureAlgorithm("SHA1withRSA");
	                    final X509Certificate certificate = certGen.generate(key_pair.getPrivate(), "BC");
	                    final String fingerprint = CertTools.getFingerprintAsString(certificate);
	                    // We add all certificates that does not have a user already to "missing_user_name"
	                    final EndEntityInformation missingUserDataVO = ejb.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAdmin(cliUserName, cliPassword), missing_user_name);
	                    if (missingUserDataVO == null) {
	                        // Add the user and change status to REVOKED
	                        getLogger().debug("Loading/updating user " + missing_user_name);
	                        final EndEntityInformation userdataNew = new EndEntityInformation(missing_user_name, CertTools.getSubjectDN(certificate), cainfo.getCAId(), null, null,
	                                UserDataConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
	                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null,
	                                SecConst.TOKEN_SOFT_BROWSERGEN, SecConst.NO_HARDTOKENISSUER, null);
	                        userdataNew.setPassword("foo123");
	                        ejb.getRemoteSession(EndEntityManagementSessionRemote.class).addUser(getAdmin(cliUserName, cliPassword), userdataNew, false);
	                        getLogger().info("User '" + missing_user_name + "' has been added.");
	                        ejb.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(getAdmin(cliUserName, cliPassword), missing_user_name, UserDataConstants.STATUS_REVOKED);
	                        getLogger().info("User '" + missing_user_name + "' has been updated.");
	                    }
	                    ejb.getRemoteSession(CertificateStoreSessionRemote.class).storeCertificate(getAdmin(cliUserName, cliPassword), certificate, missing_user_name, fingerprint,
	                            CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, 
	                            CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, new Date().getTime());
	                    getLogger().info("Dummy certificate  '" + serialHex + "' has been stored.");
	                }
	                // This check will not catch a certificate with status CertificateConstants.CERT_ARCHIVED
	                if (!strict && ejb.getRemoteSession(CertificateStoreSessionRemote.class).isRevoked(issuer, serialNr)) {
	                    getLogger().info("Certificate '" + serialHex +"' is already revoked");
	                    already_revoked++;
	                    continue;
	                }
	                getLogger().info("Revoking '" + serialHex +"' " + "(" + serialNr.toString() + ")");
	                try {
	                    int reason = getCRLReasonValue(entry);
	                    getLogger().info("Reason code: "+reason);
	                    ejb.getRemoteSession(EndEntityManagementSessionRemote.class).revokeCert(getAdmin(cliUserName, cliPassword), serialNr, entry.getRevocationDate(), issuer, reason);
	                    revoked++;
	                } catch (AlreadyRevokedException e) {
	                    already_revoked++;
	                    getLogger().warn("Failed to revoke '" + serialHex +"'. (Status might be 'Archived'.) Error message was: " + e.getMessage());
	                }
	            }	            
	        } // if (entries != null)
	        if (ejb.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLNumber(issuer, false) < crl_no) {
	        	ejb.getRemoteSession(CrlStoreSessionRemote.class).storeCRL(getAdmin(cliUserName, cliPassword), x509crl.getEncoded(), CertTools.getFingerprintAsString(cacert), crl_no, issuer, x509crl.getThisUpdate(), x509crl.getNextUpdate(), -1);
	        } else {
	        	if (strict) {
	        		throw new IOException("CRL #" + crl_no + " or higher is already in the database");
	        	}
	        }
			getLogger().info("\nSummary:\nRevoked " + revoked + " certificates");
			if (already_revoked > 0) {
				getLogger().info(already_revoked + " certificates were already revoked");
			}
			if (miss_count > 0) {
				getLogger().info("There were " + miss_count + (adaptive ? " dummy certificates added to" : " certificates missing in") +  " the database");
			}
        	getLogger().info("CRL #" + crl_no + " stored in the database");
		} catch (Exception e) {
			getLogger().info("Error: " + e.getMessage());
		}
		getLogger().trace("<execute()");
	}

	private void usage(String cliUserName, String cliPassword) {
		getLogger().info("Description: " + getDescription());
		getLogger().info("Usage: " + getCommand() + " <caname> <crl file> <" + STRICT_OP + "|" + LENIENT_OP + "|" + ADAPTIVE_OP + ">");
		getLogger().info(STRICT_OP + " means that all certificates must be in the database and that the CRL must not already be in the database.");
		getLogger().info(LENIENT_OP + " means not strict and not adaptive, i.e. all certificates must not be in the database, but no dummy certificates will be created.");
		getLogger().info(ADAPTIVE_OP + " means that missing certficates will be replaced by dummy certificates to cater for proper CRLs for missing certificates.");
		getLogger().info(" Existing CAs: " + getAvailableCasString(cliUserName, cliPassword));
	}
	
    /**
     * Return a CRL reason code from a CRL entry, or RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED if a reson code extension does not exist
     */
    private int getCRLReasonValue(final X509CRLEntry entry) throws IOException {
        int reason = RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED; 
        if ((entry != null) && entry.hasExtensions()) {
            final byte[] bytes = entry.getExtensionValue(X509Extensions.ReasonCode.getId());
            if (bytes != null) {
                ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
                final ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
                aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
                final DERObject obj = aIn.readObject();
                if (obj != null) {
                    try {
                    final DEREnumerated ext = (DEREnumerated)obj;
                    reason = ext.getValue().intValue();
                    } catch (ClassCastException e) {
                        // this was not a reason code, very strange
                        getLogger().info("Reason code extension did not contain DEREnumerated, is this CRL corrupt?. "+obj.getClass().getName());
                    }
                }
            }
        }
        return reason;
    } // getCRLReasonValue

}
