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

package org.ejbca.core.protocol.ws.client;

import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.ejbca.core.protocol.CVCRequestMessage;
import org.ejbca.core.protocol.RequestMessageUtils;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;


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
				System.exit(-1);
			}
			CertTools.installBCProvider();
			String filename = args[1];
			getPrintStream().println("Printing CV Certificate: "+filename);
			// Read file to a buffer and use the toString functions in the cvc-lib
			CVCObject parsedObject = getCVCObject(filename);
			getPrintStream().println(parsedObject.getAsText(""));
			if (args.length > 2) {
				String verifycert = args[2];
				getPrintStream().println("Verifying certificate "+filename+" with certificate "+verifycert);
				CVCertificate cert1 = (CVCertificate)parsedObject;
				parsedObject = getCVCObject(verifycert);
				CVCertificate cert2 = (CVCertificate)parsedObject;
				CardVerifiableCertificate cvcert = new CardVerifiableCertificate(cert1);
				try {
					cvcert.verify(cert2.getCertificateBody().getPublicKey());					
					getPrintStream().println("Verification of certificate was successful");
				} catch (Exception e) {
					getPrintStream().println("Verification of certificate failed: "+e.getMessage());
				}
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}

	private CVCObject getCVCObject(String filename) throws IOException, ConstructionException, CertificateException {
		CVCObject ret = null;
		try {
			byte[] cvcdata = FileTools.readFiletoBuffer(filename);				
			ret = CertificateParser.parseCVCObject(cvcdata);
		} catch (IllegalArgumentException e) {
			try {
				// this was not parseable, try to see it it was a PEM certificate
				Collection col = CertTools.getCertsFromPEM(filename);
				Certificate cert = (Certificate)col.iterator().next();
	        	ret = CertificateParser.parseCVCObject(cert.getEncoded());			
			} catch (IOException ie) {
				// this was not a PEM cert, try to see it it was a PEM certificate req
				byte[] cvcdata = FileTools.readFiletoBuffer(filename);				
				CVCRequestMessage req = RequestMessageUtils.genCVCRequestMessageFromPEM(cvcdata);
				ret = req.getCVCertificate();
			}
		}
		return ret;
	}

	protected void usage() {
		getPrintStream().println("Command used to pretty print a CVC certificate or request.");
		getPrintStream().println("Usage : cvcprint <filename> [verifycert]\n\n");
		getPrintStream().println("If adding the optional parameter verifycert the program tries to verify a certifcate given as filename with the certificate given as verifycert.");
	}


}
