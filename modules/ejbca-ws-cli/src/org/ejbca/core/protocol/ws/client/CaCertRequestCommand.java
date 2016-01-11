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
import java.io.FileOutputStream;
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
 * Creates a certificate request from a CA, optionally also renews keys. The certificate request is sent to 
 * an external CA for certification or cross-certification. the received certificate is imported with the CaCertResponseCommand.
 *
 * @version $Id$
 */
public class CaCertRequestCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


	private static final int ARG_CANAME           = 1;
	private static final int ARG_CACHAIN          = 2;
	private static final int ARG_REGENKEYS        = 3;
	private static final int ARG_ACIVATEKEYS      = 4;
	private static final int ARG_USENEXTKEY       = 5;
	private static final int ARG_OUTFILE          = 6;
	private static final int ARG_KEYSTOREPWD      = 7;

	/**
	 * Creates a new instance of Command
	 *
	 * @param args command line arguments
	 */
	public CaCertRequestCommand(String[] args) {
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
			if (args.length < 7 || args.length > 8) {
				getPrintStream().println("Number of arguments: "+args.length);
				usage();
				System.exit(-1); // NOPMD, this is not a JEE app
			}

			CryptoProviderTools.installBCProvider();
			
			String caname = args[ARG_CANAME];
			String cachainfile = args[ARG_CACHAIN];
			boolean regenkeys = args[ARG_REGENKEYS].equalsIgnoreCase("true");
			boolean activatekeys = args[ARG_ACIVATEKEYS].equalsIgnoreCase("true");
			boolean usenext = args[ARG_USENEXTKEY].equalsIgnoreCase("true");
			String outfile = args[ARG_OUTFILE];
			String keystorepwd = null;
			if (args.length > 7) {
				keystorepwd = args[ARG_KEYSTOREPWD];				
			}
			if (regenkeys && (keystorepwd == null)) {
				// prompt for keystore password
				 System.out.print("Enter CA token password: ");
				 keystorepwd = String.valueOf(System.console().readPassword());            	
			}

			getPrintStream().println("Creating request for CA: "+caname);
			getPrintStream().println("CA chain file: "+cachainfile);
			getPrintStream().println("Regenerate keys: "+regenkeys);
			getPrintStream().println("Activate keys: "+activatekeys);                        
			getPrintStream().println("Use next key: "+usenext);
			getPrintStream().println("Output file: "+outfile);
			//getPrintStream().println("CA token password: "+keystorepwd);                        

			List<byte[]> cachain = new ArrayList<byte[]>();
			if (!cachainfile.equalsIgnoreCase("NULL")){
				try {
					FileInputStream in = new FileInputStream(cachainfile);
					Collection<Certificate> certs = CertTools.getCertsFromPEM(in, Certificate.class);
					Iterator<Certificate> iter = certs.iterator();
					while (iter.hasNext()) {
						Certificate cert = iter.next();
						cachain.add(cert.getEncoded());
					}
				} catch (IOException e) {
					// It was perhaps not a PEM chain...see if it was a single binary CVC certificate
					byte[] certbytes = FileTools.readFiletoBuffer(cachainfile);
					Certificate cert = CertTools.getCertfromByteArray(certbytes, Certificate.class); // check if it is a good cert, decode PEM if it is PEM, etc
					cachain.add(cert.getEncoded());
				}
			}
	        byte[] request = getEjbcaRAWS().caRenewCertRequest(caname, cachain, regenkeys, usenext, activatekeys, keystorepwd);
	        if (request != null) {
				FileOutputStream fos = new FileOutputStream(outfile);
				fos.write(request);
				fos.close();
				getPrintStream().println("Wrote certificate request to file: "+outfile);	        	
	        } else {
	        	getPrintStream().println("Received null reply. Does the CA exists and does the admin have renew privileges for this CA?");
	        }
		} catch (Exception e) {
			if (e instanceof EjbcaException_Exception) {
				EjbcaException_Exception e1 = (EjbcaException_Exception)e;
				getPrintStream().println("Error code is: "+e1.getFaultInfo().getErrorCode().getInternalErrorCode());
			}
			throw new ErrorAdminCommandException(e);
		}
	}

	protected void usage() {
		getPrintStream().println("Command used to make a certificate request from a CA to an external CA. Can be X.509 or CVC. Can be used for cross certification and for renewing a Sub CA.");
		getPrintStream().println("Usage : cacertrequest <caname> <cachainfile | NULL> <regenkeys true/false> <activatekeys true/false> <usenextkey true/false> <outfile> [<CA token password>]\n\n");
		getPrintStream().println("Caname is the name of the CA that will generate the request.");
		getPrintStream().println("Cachainfile is a file with the certificate chain of the external CA. This can be a file with several PEM certificates in it, or a file with a single PEM or binary Root CA certificate.");
		getPrintStream().println("  Specifying NULL means that no cachain is supplied.");
		getPrintStream().println("Regenkeys will generate new CA signing keys that will be used to sign the request.");
		getPrintStream().println("Activatekeys is valid if regenkeys=true. Activatekeys determins if the new keys will be activated by the CA immediately or not. If activated immediately the CA will be set in status \"waiting for certificate response\". In this state the CA will not be able to issue certificates until the response from the external CA has been imported. If activatekeys=false the new keys will be used to generate the request, but the old keys will still be active until the response from the external CA is imported.");
		getPrintStream().println("Usenextkey is valid if regenkeys=false but there has already been a call with regenkeys=true and activatekeys=false. This will then generate a new request using the new, not yet activated keys. Useful if the original request got lost, or if the same key should be used to generate a request for several external CAs.");
		getPrintStream().println("Outfile is the filename where the resulting request will be written, in binary format.");
		getPrintStream().println("CA token password is needed if regenkeys=true. If not given this command will prompt for the input if regenkeys=true.");
	}


}
