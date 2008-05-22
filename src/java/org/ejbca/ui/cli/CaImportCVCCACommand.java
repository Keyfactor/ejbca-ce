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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;

/**
 * Imports a PKCS12 file and created a new CA from it.
 *
 * @version $Id$
 */
public class CaImportCVCCACommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaInfoCommand
     *
     * @param args command line arguments
     */
    public CaImportCVCCACommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 4) {
           String msg = "Usage 1: ca importcvcca <CA name> <pkcs8 RSA private key file> <certificate file>\n" +
        				"Imports a private key and a self signed CVCA certificate and creates a CVCA.\n" +
        				"Usage 2: ca importcvcca <CA name> <pkcs8 private key file> <certificate file> <DN of form C=country,O=mnemonic,CN=sequence> <signatureAlgorithm> <validity days>\n" +
        				"Imports a private key and generates a new self signed CVCA certificate with the given DN and creates a CVCA. Signature algorithm can be SHA1WithRSA, SHA256WithRSA, SHA256WithRSAAndMGF1";
           throw new IllegalAdminCommandException(msg);
        }
        try {
        	String caName = args[1];
        	String pkFile = args[2];
        	String certFile = args[3];
        	
        	// Import key and certificate
			CertTools.installBCProvider();
			byte[] pkbytes = FileTools.readFiletoBuffer(pkFile);
	        KeyFactory keyfact = KeyFactory.getInstance("RSA", "BC");
	        PrivateKey privKey = keyfact.generatePrivate(new PKCS8EncodedKeySpec(pkbytes));

	        byte[] certbytes = FileTools.readFiletoBuffer(certFile);
	        Certificate cert = CertTools.getCertfromByteArray(certbytes);
	        PublicKey pubKey = cert.getPublicKey();
	        // Verify that the public and private key belongs together
	        testKey(privKey, pubKey);
//	        try {
//	        	cert.verify(pubKey);
//	        } catch (SignatureException e) {
//	        	getOutputStream().println("Can not verify self signed certificate '"+certFile+"': "+e.getMessage());
//            	System.exit(2);
//            }
	        Certificate cacert = null;
	        if (args.length > 6) {
		        // Create a self signed CVCA cert from the DN
	        	getOutputStream().println("Generating new self signed certificate.");
	        	String dn = args[4];
	        	String sigAlg = args[5];
	        	Integer valdays = Integer.parseInt(args[6]);
	        	
	    		String country = CertTools.getPartFromDN(dn, "C");
	    		String mnemonic = CertTools.getPartFromDN(dn, "O");
	    		String seq = CertTools.getPartFromDN(dn, "CN");
	            HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);
	            CAReferenceField caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());
	            AuthorizationRoleEnum authRole = AuthorizationRoleEnum.CVCA;
	            Date notBefore = new Date();
	            Calendar notAfter = Calendar.getInstance();
	            notAfter.add(Calendar.DAY_OF_MONTH, valdays);
	            CVCertificate cvc = CertificateGenerator.createCertificate(pubKey, privKey, 
	            		sigAlg, caRef, holderRef, authRole, notBefore, notAfter.getTime(), "BC");
	            cacert = new CardVerifiableCertificate(cvc);
	        } else {
	        	getOutputStream().println("Using passed in self signed certificate.");
	        	cacert = cert;
	        }
	        try {
	        	cacert.verify(pubKey);
	        } catch (SignatureException e) {
	        	getOutputStream().println("Can not verify self signed certificate: "+e.getMessage());
            	System.exit(3);
            }

	        Certificate[] chain = new Certificate[1];
	        chain[0] = cacert;
        	getCAAdminSessionRemote().importCAFromKeys(administrator, caName, "foo123", chain, pubKey, privKey, null, null);
        	
        } catch (ErrorAdminCommandException e) {
        	throw e;
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
    private void testKey(PrivateKey priv, PublicKey pub) throws Exception {
        final byte input[] = "Lillan gick p� v�gen ut, m�tte d�r en katt ...".getBytes();
        final byte signBV[];
        String keyalg = pub.getAlgorithm();
        getOutputStream().println("Testing keys with algorithm: "+keyalg);        	
        String testSigAlg = "SHA1withRSA";
        if (StringUtils.equals(keyalg, "EC")) {
        	testSigAlg = "SHA1withECDSA";
        }
        {
            Signature signature = Signature.getInstance(testSigAlg, "BC");
            signature.initSign( priv );
            signature.update( input );
            signBV = signature.sign();
        }{
            Signature signature = Signature.getInstance(testSigAlg, "BC");
            signature.initVerify(pub);
            signature.update(input);
            if ( !signature.verify(signBV) )
                throw new InvalidKeyException("Not possible to sign and then verify with key pair.");
        }
    }

} // CaImportCACommand
