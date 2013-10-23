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
import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Renews the CA certificate and optionally regenerates the key pair. This is the CLI equivalent of pushing 
 * the renewal button in EJBCA Admin Web.
 *
 * @version $Id$
 */
public class CaRenewCACommand extends BaseCaAdminCommand {

	private static final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssZZ");
	private static final String NEWLINE = System.getProperty("line.separator");
	
    @Override
	public String getSubCommand() { return "renewca"; }
    @Override
    public String getDescription() { return "Renew CA certificate and optionally regenerate keys"; }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        if (args.length < 2 || args.length > 5) {
			printUsage();
        	return;
        }
        try {
        	// Bouncy Castle security provider
        	CryptoProviderTools.installBCProvider();
            
        	// Get the CAs info and id
        	final String caname = args[1];
        	CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caname);
        	
        	boolean regenerateKeys = false;
        	String authCode = null;
        	boolean prompt = false;
        	Date customNotBefore = null;
        	if (args.length > 2) {
        		if ("TRUE".equalsIgnoreCase(args[2])) {
        			regenerateKeys = true;
        		} else if (!"FALSE".equalsIgnoreCase(args[2])) {
        			getLogger().error("Error: Specify true or false for <regenerate keys>");
        			printUsage();
        			return;
        		}
        		regenerateKeys = Boolean.parseBoolean(args[2]);
        	}
        	if (args.length > 3) {
        		if (!"-prompt".equals(args[3])) {
        			authCode = args[3];
        		} else {
        			prompt = true;
        		}
        	}
        	if (args.length > 4) {
        	    try {
        	        customNotBefore = ValidityDate.parseAsIso8601(args[4]);
        	        if (customNotBefore == null) {
        	            getLogger().error("Error: Could not parse date. Use ISO 8601 format, for example '2010-09-08 07:06:05+02:00' ");
        	            return;
        	        }
        	    } catch (ParseException e) {
        	        getLogger().error("Error: "+e.getMessage()+". Use ISO 8601 format, for example '2010-09-08 07:06:05+02:00' ");
                    return;        	        
        	    }
        	}
            
    		final StringBuilder buff = new StringBuilder();
    		buff.append("Renew CA ");
    		buff.append(caname);
    		buff.append(" ");
    		if (regenerateKeys) {
    			buff.append("with a new key pair");
    		} else {
    			buff.append("with the current key pair");
    		}
    		if (customNotBefore != null) {
    			buff.append(" and with custom notBefore date: ");
    			buff.append(format.format(customNotBefore));
    		}
    		getLogger().info(buff.toString());
    		
    		getLogger().info("Current certificate: ");
    		final Object oldCertificate = cainfo.getCertificateChain().iterator().next();
            if (oldCertificate instanceof Certificate) {
            	printCertificate((Certificate) oldCertificate);
            } else {
            	getLogger().error("Error: Certificate not found");
            }
    		
    		if (authCode == null && regenerateKeys) {
	            getLogger().info("Enter authorization code to continue: ");
	            authCode = String.valueOf(System.console().readPassword());
    		} else if (prompt) {
    		getLogger().info("Press ENTER to continue: ");
                    System.console().readPassword();
    		}
            
    		ejb.getRemoteSession(CAAdminSessionRemote.class).renewCA(getAuthenticationToken(cliUserName, cliPassword), cainfo.getCAId(), regenerateKeys, customNotBefore, regenerateKeys);
            getLogger().info("New certificate created:");
            cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(cliUserName, cliPassword), caname);
            final Object newCertificate = cainfo.getCertificateChain().iterator().next();
            if (newCertificate instanceof Certificate) {
            	printCertificate((Certificate) newCertificate);
            } else {
            	getLogger().error("Error: Certificate not found");
            }
        } catch (CADoesntExistsException e) {
            getLogger().error(e.getMessage());  
            return;                             
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    private void printUsage() {
    	getLogger().info(new StringBuilder()
    		.append("Description: ").append(getDescription()).append(NEWLINE)
    		.append("Usage: ").append(getCommand()).append(" <CA name> [<regenerate keys>] [<authorization code> | -prompt] [<custom notBefore>]").append(NEWLINE)
    		.append("Authorization code is only used when generating new keys.").append(NEWLINE)
    		.append("Example: ").append(getCommand()).append(" ExampleCA1 false -prompt \"2010-09-08 07:06:05+02:00\"").append(NEWLINE)
    		.toString());
    }

    private void printCertificate(final Certificate certificate) throws IOException {
    	if (certificate instanceof X509Certificate) {
        	final X509Certificate x509 = (X509Certificate) certificate;
        	getLogger().info(new StringBuilder()
        		.append("  Serial number:  ").append(x509.getSerialNumber().toString(16)).append(NEWLINE)
        		.append("  Issuer DN:      ").append(x509.getIssuerDN().getName()).append(NEWLINE)
        		.append("  Subject DN:     ").append(x509.getSubjectDN().getName()).append(NEWLINE)
        		.append("  Not Before:     ").append(format.format(x509.getNotBefore())).append(NEWLINE)
        		.append("  Not After:      ").append(format.format(x509.getNotAfter())).append(NEWLINE)
        		.append("  Subject key id: ").append(computeSubjectKeyIdentifier(x509)).append(NEWLINE)
        		.toString());
        } else if (certificate instanceof CardVerifiableCertificate) {
        	final CardVerifiableCertificate cvc = (CardVerifiableCertificate) certificate;
        	try {
	        	getLogger().info(new StringBuilder()
	        		.append("  ").append(cvc.getCVCertificate().getCertificateBody().getHolderReference().getAsText(false)).append(NEWLINE)
	        		.append("  ").append(cvc.getCVCertificate().getCertificateBody().getAuthorityReference().getAsText(false)).append(NEWLINE)
	        		.append("  Not Before:      ").append(format.format(cvc.getCVCertificate().getCertificateBody().getValidFrom())).append(NEWLINE)
	        		.append("  Not After:       ").append(format.format(cvc.getCVCertificate().getCertificateBody().getValidTo())).append(NEWLINE)
	        		.append("  Public key hash: ").append(computePublicKeyHash(cvc.getPublicKey())).append(NEWLINE)
	        		.toString());
        	} catch (NoSuchFieldException ex) {
        		getLogger().error("Error: Could not read field in CV Certificate: " + ex.getMessage());
    		}
        } else {
        	getLogger().info(new StringBuilder()
	    		.append("  Unknown certificate type:").append(NEWLINE)
	    		.append(certificate.toString())
	    		.toString());
        }
    }
    
    private static String computeSubjectKeyIdentifier(final X509Certificate certificate) throws IOException {
       
        ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(certificate.getPublicKey().getEncoded()));
        try {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo((ASN1Sequence) asn1InputStream.readObject());
            X509ExtensionUtils utils = new X509ExtensionUtils(SHA1DigestCalculator.buildSha1Instance());
            SubjectKeyIdentifier ski = utils.createSubjectKeyIdentifier(spki);
            return new String(Hex.encode(ski.getKeyIdentifier()));

        } catch (IOException e) {
            return "n/a";
        } finally {
            asn1InputStream.close();
        }
    }
    
    private static String computePublicKeyHash(final PublicKey publicKey) {
    	final Digest digest = new SHA1Digest();
    	final byte[] hash = new byte[digest.getDigestSize()];
    	final byte[] data = publicKey.getEncoded();
    	digest.update(data, 0, data.length);
    	digest.doFinal(hash, 0);
    	return new String(Hex.encode(hash));
    }
}
