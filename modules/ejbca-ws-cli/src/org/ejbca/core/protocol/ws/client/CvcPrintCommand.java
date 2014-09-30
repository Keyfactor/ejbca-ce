/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.ws.client;

import java.io.IOException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.CvcException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;


/**
 * Pretty prints a CV Certificate or certificate request
 *
 * @version $Id$
 */
public class CvcPrintCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


	/**
	 * @param args command line arguments
	 */
	public CvcPrintCommand(String[] args) {
		super(args);
	}

	/**
	 * Runs the command
	 *
	 * @throws IllegalAdminCommandException Error in command args
	 * @throws ErrorAdminCommandException Error running command
	 */
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {

		try {   
			if(args.length < 2 || args.length > 4){
				usage();
				System.exit(-1); // NOPMD, this is not a JEE app
			}
			CryptoProviderTools.installBCProvider();
			String filename = args[1];
			getPrintStream().println("Printing CV Certificate: "+filename);
			// Read file to a buffer and use the toString functions in the cvc-lib
			CVCObject parsedObject = getCVCObject(filename);
			getPrintStream().println(parsedObject.getAsText(""));
			if (args.length > 2) {
				String verifycert = args[2];
				String type = "certificate";
				if (parsedObject instanceof CVCAuthenticatedRequest) {
					type = "authenticated request";
				}
				getPrintStream().println("Verifying "+type+" "+filename+" with certificate "+verifycert);
				CVCObject parsedVerifyObject = getCVCObject(verifycert);
				CVCertificate cert2 = (CVCertificate)parsedVerifyObject;
				PublicKey pk = cert2.getCertificateBody().getPublicKey();
				if (args.length > 3) {
					// we have an additional curve name
					String cvcacert = args[3];
					getPrintStream().println("Using CVCA certificate "+cvcacert+" for EC parameters.");
					CVCObject parsedCvcaObject = getCVCObject(cvcacert);
					CVCertificate cvca = (CVCertificate)parsedCvcaObject;
					pk = KeyTools.getECPublicKeyWithParams(pk, cvca.getCertificateBody().getPublicKey());
				}
				try {
					if (parsedObject instanceof CVCAuthenticatedRequest) {
						CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
						authreq.verify(pk);											
					} else {
						CVCertificate cert1 = (CVCertificate)parsedObject;
						CardVerifiableCertificate cvcert = new CardVerifiableCertificate(cert1);
						cvcert.verify(pk);											
					}
					getPrintStream().println("Verification of certificate was successful");
				} catch (Exception e) {
					getPrintStream().println("Verification of certificate failed: "+e.getMessage());
				}
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}

	protected static CVCObject getCVCObject(String filename) throws IOException, CvcException, CertificateException {
		CVCObject ret = null;
		try {
			byte[] cvcdata = FileTools.readFiletoBuffer(filename);				
			ret = CertificateParser.parseCVCObject(cvcdata);
		} catch (Exception e) {
			try {
				// this was not parseable, try to see it it was a PEM certificate
				Collection<Certificate> col = CertTools.getCertsFromPEM(filename);
				Certificate cert = (Certificate)col.iterator().next();
	        	ret = CertificateParser.parseCVCObject(cert.getEncoded());			
			} catch (Exception ie) {
				// this was not a PEM cert, try to see it it was a PEM certificate req
				byte[] cvcdata = FileTools.readFiletoBuffer(filename);				
				byte[] req = RequestMessageUtils.getRequestBytes(cvcdata);
				ret = CertificateParser.parseCVCObject(req);
			}
		}
		return ret;
	}

	protected void usage() {
		getPrintStream().println("Command used to pretty print a CVC certificate or request.");
		getPrintStream().println("Usage : cvcprint <filename> [verifycert] [CVCA-certificate for EC params]\n\n");
		getPrintStream().println("If adding the optional parameter verifycert the program tries to verify a certifcate given as filename with the certificate given as verifycert.");
		getPrintStream().println("If verifying an IS cert with a DV cert no curve parameters exist in the public key in the certificate, you can therefore add the CVCA certificate to complete the public key.");
	}


}
