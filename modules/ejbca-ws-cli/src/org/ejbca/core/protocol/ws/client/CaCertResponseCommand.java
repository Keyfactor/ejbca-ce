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

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.FileTools;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;


/**
 * Imports a certificate issued by an external CA. Used to import certificates sent as a reply to a request created with CaCertRequestCommand.
 *
 * @version $Id$
 */
public class CaCertResponseCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


	private static final int ARG_CANAME           = 1;
	private static final int ARG_CERT             = 2;
	private static final int ARG_CACHAIN          = 3;
	private static final int ARG_KEYSTOREPWD      = 4;

	/**
	 * Creates a new instance of CvcRequestCommand
	 *
	 * @param args command line arguments
	 */
	public CaCertResponseCommand(String[] args) {
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
			if(args.length < 4 || args.length > 5){
				getPrintStream().println("Number of arguments: "+args.length);
				usage();
				System.exit(-1); // NOPMD, this is not a JEE app
			}

			String caname = args[ARG_CANAME];
			String certfile = args[ARG_CERT];
			String cachainfile = args[ARG_CACHAIN];
			String keystorepwd = null;
			if (args.length > 5) {
				keystorepwd = args[ARG_KEYSTOREPWD];				
			}
			if (keystorepwd == null) {
				// prompt for keystore password
				 System.out.print("Enter CA token password: ");
			
				 keystorepwd = String.valueOf(System.console().readPassword());            	
			}

			getPrintStream().println("Importing certificate for CA: "+caname);
			getPrintStream().println("Certificate filename: "+certfile);
			getPrintStream().println("CA chain filename: "+cachainfile);
			//getPrintStream().println("CA token password: "+keystorepwd);                        

			CryptoProviderTools.installBCProvider();

			Certificate incert = null;
			try {
				FileInputStream in = new FileInputStream(certfile);
				Collection<Certificate> certs = CertTools.getCertsFromPEM(in);
				Iterator<Certificate> iter = certs.iterator();
				if (iter.hasNext()) {
					incert = (Certificate)iter.next();
				}
			} catch (IOException e) {
				// It was perhaps not a PEM chain...see if it was a single binary CVC certificate
				byte[] bytes = FileTools.readFiletoBuffer(certfile);
				incert = CertTools.getCertfromByteArray(bytes); // check if it is a good cert, decode PEM if it is PEM, etc
			}

			getPrintStream().println("Importing certificate with subjectDN '"+CertTools.getSubjectDN(incert)+"', and issuerDN '"+CertTools.getIssuerDN(incert)+"'.");

			List<byte[]> cachain = new ArrayList<byte[]>();
			try {
				FileInputStream in = new FileInputStream(cachainfile);
				Collection<Certificate> certs = CertTools.getCertsFromPEM(in);
				Iterator<Certificate> iter = certs.iterator();
				while (iter.hasNext()) {
					Certificate c = iter.next();
					cachain.add(c.getEncoded());
				}
			} catch (IOException e) {
				// It was perhaps not a PEM chain...see if it was a single binary CVC certificate
				byte[] bytes = FileTools.readFiletoBuffer(cachainfile);
				Certificate c = CertTools.getCertfromByteArray(bytes); // check if it is a good cert, decode PEM if it is PEM, etc
				cachain.add(c.getEncoded());
			}
	        getEjbcaRAWS().caCertResponse(caname, incert.getEncoded(), cachain, keystorepwd);
			getPrintStream().println("Imported CA certificate.");	        
		} catch (Exception e) {
			if (e instanceof EjbcaException_Exception) {
				EjbcaException_Exception e1 = (EjbcaException_Exception)e;
				getPrintStream().println("Error code is: "+e1.getFaultInfo().getErrorCode().getInternalErrorCode());
			}
			throw new ErrorAdminCommandException(e);
		}
	}

	protected void usage() {
		getPrintStream().println("Command used to import a certificate from an external CA. Can be X.509 or CVC. Used to receive certificate responses to request created with 'cacertrequest' command.");
		getPrintStream().println("Usage : cacertrequest <caname> <certfile> <cachainfile> [<CA token password>]\n\n");
		getPrintStream().println("Caname is the name of the CA that will generate the request.");
		getPrintStream().println("Certfile is a file with the certificate issued by the external CA. This is a file with a single PEM or binary certificate.");
		getPrintStream().println("Cachainfile is a file with the certificate chain of the external CA. This can be a file with several PEM certificates in it, or a file with a single PEM or binary Root CA certificate.");
		getPrintStream().println("CA token password is needed if importing this certificate means that a new CA signing key pair must be activated. If not given this command will prompt for the input. If you are certain that a new key pair will not be activated you can give any input as this password will be ignored.");
	}


}
