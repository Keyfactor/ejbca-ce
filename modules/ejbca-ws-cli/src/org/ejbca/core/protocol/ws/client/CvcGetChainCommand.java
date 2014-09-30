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

import java.io.FileOutputStream;
import java.util.List;

import org.cesecore.util.Base64;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;


/**
 * Creates or edits a user and sends a CVC request. Writes the issues CV Certificate to file
 *
 * @version $Id$
 */
public class CvcGetChainCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


	private static final int ARG_USERNAME           = 1;
	private static final int ARG_BASEFILENAME        = 2;

	/**
	 * Creates a new instance of CvcRequestCommand
	 *
	 * @param args command line arguments
	 */
	public CvcGetChainCommand(String[] args) {
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
			if(args.length < 3 || args.length > 3){
				getPrintStream().println("Number of argument: "+args.length);
				usage();
				System.exit(-1); // NOPMD, this is not a JEE app
			}

			String username = args[ARG_USERNAME];
			String basefilename = args[ARG_BASEFILENAME];

			getPrintStream().println("Getting last certificate chain::");
			getPrintStream().println("Username: "+username);
			getPrintStream().println("Base file name: "+basefilename);

			try{
				// Edit a user, creating it if it does not exist
				List<Certificate> resp = getEjbcaRAWS().getLastCertChain(username);
				// Handle the response
				int i = 1;
				for (Certificate certificate : resp) {
					byte[] b64cert = certificate.getCertificateData();
					CVCObject parsedObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
					CVCertificate cvcert = (CVCertificate)parsedObject;
					FileOutputStream fos = new FileOutputStream(basefilename+i+".cvcert");
					fos.write(cvcert.getDEREncoded());
					fos.close();
					getPrintStream().println("Wrote binary certificate to: "+basefilename+i+".cvcert");
					getPrintStream().println("You can look at the certificate with the command cvcwscli.sh cvcprint "+basefilename+i+".cvcert");					
					i++;
				}
			}catch(AuthorizationDeniedException_Exception e){
				getPrintStream().println("Error : " + e.getMessage());
			}
		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}

	protected void usage() {
		getPrintStream().println("Command used to get the certificate chain for a user. The users last issued certificate is returned, according to the certificate validity date. If two certificates have the exact same issue date the order is indefined.");
		getPrintStream().println("Usage : cvcgetchain <username> <basefilename>\n");
		getPrintStream().println("The certificates are written to <basefilename><order>.cvcert. Order nr 1 is the users certificate, followed by the CAs certificates.");
	}


}
