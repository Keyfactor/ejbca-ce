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
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collection;

import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.util.Base64;
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
 * Converts a CV Certificate or certificate request to/from binary and PEM
 *
 * @version $Id$
 */
public class CvcPemCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


	/**
	 * @param args command line arguments
	 */
	public CvcPemCommand(String[] args) {
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
			if(args.length < 4 || args.length > 6){
				usage();
				System.exit(-1); // NOPMD, this is not a JEE app
			}
			CryptoProviderTools.installBCProvider();
			String inform = args[1];
			String infile = args[2];
			String outform = args[3];
			String outfile = args[4];
			System.out.println(inform+infile+outform+outfile);
			if (inform.equals(outform)) {
				getPrintStream().println("No point in converting to the same format, exiting.");
				return;
			}
			getPrintStream().println("converting CV Certificate ("+inform+"): "+infile+" to "+outform);
			// Read file to a buffer and use the toString functions in the cvc-lib
			CVCObject parsedObject = getCVCObject(infile);
			byte[] bytes = null;
			if (parsedObject instanceof CVCAuthenticatedRequest) {
				CVCAuthenticatedRequest authreq = (CVCAuthenticatedRequest)parsedObject;
				bytes = authreq.getDEREncoded();
			} else {
				CVCertificate cert1 = (CVCertificate)parsedObject;
				CardVerifiableCertificate cvcert = new CardVerifiableCertificate(cert1);
				bytes = cvcert.getEncoded();
			}
			if ("pem".equalsIgnoreCase(outform)) {
				byte[] b64 = Base64.encode(bytes);
				FileOutputStream fos = new FileOutputStream(outfile);
				String begin = CertTools.BEGIN_CERTIFICATE;
				String end = CertTools.END_CERTIFICATE;
				if (args.length > 5 && args[5].equals("-req")) {					
					begin = CertTools.BEGIN_CERTIFICATE_REQUEST;
					end = CertTools.END_CERTIFICATE_REQUEST;
				}
				fos.write((begin+"\n").getBytes());
				fos.write(b64);
				fos.write(("\n"+end+"\n").getBytes());
				fos.close();
			} else {
				FileOutputStream fos = new FileOutputStream(outfile);
				fos.write(bytes);
				fos.close();				
			}
			getPrintStream().println("Wrote output file "+outfile);
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
				Collection<Certificate> col = CertTools.getCertsFromPEM(filename, Certificate.class);
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
		getPrintStream().println("Command used to convert between binary and PEM formats.");
		getPrintStream().println("Usage : cvcpem <inform bin/pem> <in filename> <outform bin/pem> <out filename> [-req]\n\n");
		getPrintStream().println("If adding the optional parameter -req the PEM output/input is a certificate request as opposed to a certificate.");
	}


}
