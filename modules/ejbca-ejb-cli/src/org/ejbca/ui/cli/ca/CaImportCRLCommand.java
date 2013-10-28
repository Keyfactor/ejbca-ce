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

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
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
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Imports a CRL file to the database.
 *
 * @version $Id$
 */
public class CaImportCRLCommand extends BaseCaAdminCommand {

    public static final String MISSING_USERNAME_PREFIX = "*** Missing During CRL Import to: ";
    
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
			final CAInfo cainfo = getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caname);
			final X509Certificate cacert = (X509Certificate) cainfo.getCertificateChain().iterator().next();
			final String issuer = CertTools.stringToBCDNString(cacert.getSubjectDN().toString());
			getLogger().info("CA: " + issuer);
			// Read the supplied CRL and verify that it is issued by the specified CA
			final X509CRL x509crl = (X509CRL) CertTools.getCertificateFactory().generateCRL(new FileInputStream (crl_file));
	        if (!x509crl.getIssuerX500Principal().equals(cacert.getSubjectX500Principal())){
	        	throw new IOException ("CRL wasn't issued by this CA");
	        }
	        x509crl.verify(cacert.getPublicKey());
	        int crl_no = CrlExtensions.getCrlNumber(x509crl).intValue();
	        getLogger().info("Processing CRL #" + crl_no);
	        int miss_count = 0;	// Number of certs not already in database
	        int revoked = 0;	// Number of certs activly revoked by this algorithm
	        int already_revoked = 0;	// Number of certs already revoked in database and ignored in non-strict mode
	        final String missing_user_name = MISSING_USERNAME_PREFIX + caname;
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
	                    final KeyPair key_pair = KeyTools.genKeys("2048", AlgorithmConstants.KEYALGORITHM_RSA);     

	                    final SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence)ASN1Primitive.fromByteArray(key_pair.getPublic().getEncoded()));
	                    final X500Name dnName = new X500Name("CN=Dummy Missing in Imported CRL, serialNumber=" + serialHex);
	                    final Date notAfter = new Date (time.getTime() + 1000L * 60 * 60 * 24 * 365 * 10); // 10 years of life
	                    final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(X500Name.getInstance(cacert.getSubjectX500Principal().getEncoded()), serialNr, time, notAfter, dnName, pkinfo);
	                    final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder("SHA1withRSA").build(key_pair.getPrivate()), 20480);
	                    final X509CertificateHolder certHolder = certbuilder.build(signer);
	                    final X509Certificate certificate = (X509Certificate)CertTools.getCertfromByteArray(certHolder.getEncoded());
	                    
	                    final String fingerprint = CertTools.getFingerprintAsString(certificate);
	                    // We add all certificates that does not have a user already to "missing_user_name"
	                    final EndEntityInformation missingUserEndEntityInformation = ejb.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAuthenticationToken(cliUserName, cliPassword), missing_user_name);
	                    if (missingUserEndEntityInformation == null) {
	                        // Add the user and change status to REVOKED
	                        getLogger().debug("Loading/updating user " + missing_user_name);
	                        final EndEntityInformation userdataNew = new EndEntityInformation(missing_user_name, CertTools.getSubjectDN(certificate), cainfo.getCAId(), null, null,
	                                EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE,
	                                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null,
	                                SecConst.TOKEN_SOFT_BROWSERGEN, SecConst.NO_HARDTOKENISSUER, null);
	                        userdataNew.setPassword("foo123");
	                        ejb.getRemoteSession(EndEntityManagementSessionRemote.class).addUser(getAuthenticationToken(cliUserName, cliPassword), userdataNew, false);
	                        getLogger().info("User '" + missing_user_name + "' has been added.");
	                        ejb.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(getAuthenticationToken(cliUserName, cliPassword), missing_user_name, EndEntityConstants.STATUS_REVOKED);
	                        getLogger().info("User '" + missing_user_name + "' has been updated.");
	                    }
	                    ejb.getRemoteSession(CertificateStoreSessionRemote.class).storeCertificate(getAuthenticationToken(cliUserName, cliPassword), certificate, missing_user_name, fingerprint,
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
	                    ejb.getRemoteSession(EndEntityManagementSessionRemote.class).revokeCert(getAuthenticationToken(cliUserName, cliPassword), serialNr, entry.getRevocationDate(), issuer, reason, false);
	                    revoked++;
	                } catch (AlreadyRevokedException e) {
	                    already_revoked++;
	                    getLogger().warn("Failed to revoke '" + serialHex +"'. (Status might be 'Archived'.) Error message was: " + e.getMessage());
	                }
	            }	            
	        } // if (entries != null)
	        if (ejb.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLNumber(issuer, false) < crl_no) {
	        	ejb.getRemoteSession(CrlStoreSessionRemote.class).storeCRL(getAuthenticationToken(cliUserName, cliPassword), x509crl.getEncoded(), CertTools.getFingerprintAsString(cacert), crl_no, issuer, x509crl.getThisUpdate(), x509crl.getNextUpdate(), -1);
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
            final byte[] bytes = entry.getExtensionValue(Extension.reasonCode.getId());
            if (bytes != null) {
                ASN1InputStream aIn = new ASN1InputStream(new ByteArrayInputStream(bytes));
                final ASN1OctetString octs = (ASN1OctetString) aIn.readObject();
                aIn = new ASN1InputStream(new ByteArrayInputStream(octs.getOctets()));
                final ASN1Primitive obj = aIn.readObject();
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
