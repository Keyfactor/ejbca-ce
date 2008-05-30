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

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.List;

import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;


/**
 * Creates or edits a user and sends a CVC request. Writes the issues CV Certificate to file
 *
 * @version $Id$
 */
public class CvcRequestCommand extends EJBCAWSRABaseCommand implements IAdminCommand{


	private static final int ARG_USERNAME           = 1;
	private static final int ARG_PASSWORD           = 2;
	private static final int ARG_SUBJECTDN          = 3;
	private static final int ARG_CA                 = 4;
	private static final int ARG_SIGNALG            = 5;
	private static final int ARG_KEYSPEC            = 6;
	private static final int ARG_ENDENTITYPROFILE   = 7;
	private static final int ARG_CERTIFICATEPROFILE = 8;
	private static final int ARG_GENREQ             = 9;
	private static final int ARG_BASEFILENAME        = 10;

	/**
	 * Creates a new instance of CvcRequestCommand
	 *
	 * @param args command line arguments
	 */
	public CvcRequestCommand(String[] args) {
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
			if(args.length < 11 || args.length > 11){
				getPrintStream().println("Number of argument: "+args.length);
				usage();
				System.exit(-1);
			}

			UserDataVOWS userdata = new UserDataVOWS();
			userdata.setUsername(args[ARG_USERNAME]);
			userdata.setPassword(args[ARG_PASSWORD]);
			userdata.setClearPwd(false);
			userdata.setSubjectDN(args[ARG_SUBJECTDN]);
			userdata.setCaName(args[ARG_CA]);
			userdata.setEndEntityProfileName(args[ARG_ENDENTITYPROFILE]);
			userdata.setCertificateProfileName(args[ARG_CERTIFICATEPROFILE]);
			userdata.setTokenType("USERGENERATED");
			userdata.setStatus(UserDataConstants.STATUS_NEW);
			String signatureAlg = args[ARG_SIGNALG];
			String keySpec = args[ARG_KEYSPEC];
			boolean genrequest = args[ARG_GENREQ].equalsIgnoreCase("true");
			String basefilename = args[ARG_BASEFILENAME];

			getPrintStream().println("Trying to add user:");
			getPrintStream().println("Username: "+userdata.getUsername());
			getPrintStream().println("Subject name: "+userdata.getSubjectDN());
			getPrintStream().println("CA Name: "+userdata.getCaName());                        
			getPrintStream().println("Signature algorithm: "+signatureAlg);                        
			getPrintStream().println("Key spec: "+keySpec);                        
			getPrintStream().println("End entity profile: "+userdata.getEndEntityProfileName());
			getPrintStream().println("Certificate profile: "+userdata.getCertificateProfileName());

			try{
				String cvcreq = null;
				if (genrequest) {
					getPrintStream().println("Generating a new request with base filename: "+basefilename);
					// Generate a request for 1024 bit RSA keys
					CertTools.installBCProvider();
					KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
					keyGen.initialize(Integer.valueOf(keySpec), new SecureRandom());
					KeyPair keyPair = keyGen.generateKeyPair();
					String dn = userdata.getSubjectDN();
					String country = CertTools.getPartFromDN(dn, "C");
					String mnemonic = CertTools.getPartFromDN(dn, "O");
					String sequence = CertTools.getPartFromDN(dn, "CN");
					CAReferenceField caRef = new CAReferenceField(country,mnemonic,sequence);
					// We are making a self signed request, so holder ref is same as ca ref
					HolderReferenceField holderRef = new HolderReferenceField(caRef.getCountry(), caRef.getMnemonic(), caRef.getSequence());
					CVCertificate request = CertificateGenerator.createRequest(keyPair, signatureAlg, caRef, holderRef);
					CVCAuthenticatedRequest authRequest = CertificateGenerator.createAuthenticatedRequest(request, keyPair, signatureAlg, caRef);
					byte[] der = authRequest.getDEREncoded();
					cvcreq = new String(Base64.encode(der));
					// Print the generated request to file
					FileOutputStream fos = new FileOutputStream(basefilename+".req");
					fos.write(der);
					fos.close();					
					getPrintStream().println("Wrote binary request to: "+basefilename+".req");
					fos = new FileOutputStream(basefilename+".pkcs8");
					fos.write(keyPair.getPrivate().getEncoded());
					fos.close();					
					getPrintStream().println("Wrote private key in "+keyPair.getPrivate().getFormat()+" format to to: "+basefilename+".pkcs8");
				} else {
					// Read request from file
					getPrintStream().println("Reading request from filename: "+basefilename+".req");
					byte[] der = FileTools.readFiletoBuffer(basefilename+".req");
					cvcreq = new String(Base64.encode(der));
				}
				
				// Edit a user, creating it if it does not exist
				getEjbcaRAWS().editUser(userdata);
				// Use the request and request a certificate
				List<Certificate> resp = getEjbcaRAWS().cvcRequest(userdata.getUsername(), userdata.getPassword(), cvcreq);

				getPrintStream().println("CVC request submitted for user '"+userdata.getUsername()+"'.");
				getPrintStream().println();              

				// Handle the response
				Certificate cert = resp.get(0);
				byte[] b64cert = cert.getCertificateData();
				CVCObject parsedObject = CertificateParser.parseCertificate(Base64.decode(b64cert));
				CVCertificate cvcert = (CVCertificate)parsedObject;
				FileOutputStream fos = new FileOutputStream(basefilename+".cvcert");
				fos.write(cvcert.getDEREncoded());
				fos.close();
				getPrintStream().println("Wrote binary certificate to: "+basefilename+".cvcert");
				getPrintStream().println("You can look at the certificate with the command cvcwscli.sh cvcprint "+basefilename+".cvcert");
			}catch(AuthorizationDeniedException_Exception e){
				getPrintStream().println("Error : " + e.getMessage());
			}catch(UserDoesntFullfillEndEntityProfile_Exception e){
				getPrintStream().println("Error : Given userdata doesn't fullfill end entity profile. : " +  e.getMessage());
			}

		} catch (Exception e) {
			throw new ErrorAdminCommandException(e);
		}
	}

	protected void usage() {
		getPrintStream().println("Command used to make a CVC request. If user does not exist a new will be created and if user exist will the data be overwritten.");
		getPrintStream().println("Usage : cvcrequest <username> <password> <subjectdn> <caname> <signatureAlg> <keyspec (1024/2048)> <endentityprofilename> <certificateprofilename> <genreq=true|false> <basefilename>\n\n");
		getPrintStream().println("SignatureAlg can be SHA1WithRSA, SHA256WithRSA, SHA256WithRSAAndMGF1");
		getPrintStream().println("DN is of form \"C=SE, O=RPS, CN=00001\".");
		getPrintStream().println("If genreq is true a new request is generated and the generated request is written to <basefilename>.req, and the private key to <basefilename>.pkcs8.");
		getPrintStream().println("If genreq is false a request is read from <reqfilename>.req and sent to the CA.");
		getPrintStream().println("The issued certificate is written to <basefilename>.cvcert");
	}


}
