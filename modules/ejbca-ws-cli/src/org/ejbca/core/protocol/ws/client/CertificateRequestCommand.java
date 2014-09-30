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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Request a certificate given a pkcs10
 *
 * @version $Id$
 */
public class CertificateRequestCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_USERNAME                 = 1;
	private static final int ARG_SUBJECTDN                = 2;
	private static final int ARG_SUBJECTALTNAME           = 3;
	private static final int ARG_CANAME                   = 4;
	private static final int ARG_EEPROF                   = 5;
	private static final int ARG_CERTPROF                 = 6;
	private static final int ARG_REQPATH                  = 7;
	private static final int ARG_REQTYPE                  = 8;
	private static final int ARG_ENCODING                 = 9;
	private static final int ARG_HARDTOKENSN              = 10;
	private static final int ARG_OUTPUTPATH               = 11;
	
    /**
     * Creates a new instance of CertificateRequestCommand
     *
     * @param args command line arguments
     */
    public CertificateRequestCommand(String[] args) {
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
           
            if(args.length <  11 || args.length > 12){
            	usage();
            	System.exit(-1); // NOPMD, it's not a JEE app
            }
            
            UserDataVOWS userdata = new UserDataVOWS();
            userdata.setUsername(args[ARG_USERNAME]);
            userdata.setSubjectDN(args[ARG_SUBJECTDN]);
            if(!args[ARG_SUBJECTALTNAME].equalsIgnoreCase("NULL")){                        
            	userdata.setSubjectAltName(args[ARG_SUBJECTALTNAME]);
            }
            userdata.setCaName(args[ARG_CANAME]);
            userdata.setEndEntityProfileName(args[ARG_EEPROF]);
            userdata.setCertificateProfileName(args[ARG_CERTPROF]);
            String requestdata = getRequestData(args[ARG_REQPATH]);
            int requesttype = getRequestType (args[ARG_REQTYPE]);
            String encoding = getEncoding(args[ARG_ENCODING]);
            String hardtokensn = getHardTokenSN(args[ARG_HARDTOKENSN]);

            String outputPath = null;
            if(args.length > ARG_OUTPUTPATH){
              outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
            }
            
            getPrintStream().println("Requesting certificate for end entity:");
            getPrintStream().println("Username: "+userdata.getUsername());
            getPrintStream().println("Subject DN: "+userdata.getSubjectDN());
            getPrintStream().println("Subject Altname: "+userdata.getSubjectAltName());
            getPrintStream().println("Email: "+userdata.getEmail());
            getPrintStream().println("CA Name: "+userdata.getCaName());                        
            getPrintStream().println("Token: "+userdata.getTokenType());
            getPrintStream().println("End entity profile: "+userdata.getEndEntityProfileName());
            getPrintStream().println("Certificate profile: "+userdata.getCertificateProfileName());
            getPrintStream().println("Hard token SN: "+hardtokensn);
            getPrintStream().println("Request type: "+requesttype);
            getPrintStream().println("Encoding: "+encoding);
            getPrintStream().println("Output path: "+outputPath);

            try{
            	//UserDataVOWS userdata, String requestData, int requestType, String hardTokenSN, String responseType)
            	CertificateResponse result = getEjbcaRAWS().certificateRequest(userdata,requestdata,requesttype, hardtokensn,CertificateHelper.RESPONSETYPE_CERTIFICATE);
            	
            	if(result==null){
            		getPrintStream().println("No certificate could be generated for user, check server logs for error.");
            	}else{
            		String filepath = userdata.getUsername();
            		if(encoding.equals("DER")){
            			filepath += ".cer";
            		}else{
            			filepath += ".pem";
            		}
            		if(outputPath != null){
            			filepath = outputPath + "/" + filepath;
            		}
            		
            		
            		if(encoding.equals("DER")){
            			FileOutputStream fos = new FileOutputStream(filepath);
            			fos.write(CertificateHelper.getCertificate(result.getData()).getEncoded());
            			fos.close();
            		}else{
            			FileOutputStream fos = new FileOutputStream(filepath);
            			ArrayList<java.security.cert.Certificate> list = new ArrayList<java.security.cert.Certificate>();
            			list.add(CertificateHelper.getCertificate(result.getData()));
            			fos.write(CertTools.getPemFromCertificateChain(list));
            			fos.close();            				            				
            		}
            		getPrintStream().println("Certificate generated, written to " + filepath);
            	}
            	             

            }catch(AuthorizationDeniedException_Exception e){
            	getPrintStream().println("Error : " + e.getMessage());            
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }



	

	private String getHardTokenSN(String hardtokensn) {
		if(hardtokensn.equalsIgnoreCase("NONE")){
		  return null;
		}
		
		return hardtokensn;
	}

	private String getRequestData(String regestDataPath) {
		String retval=null;
		try {
			FileInputStream fis = new FileInputStream(regestDataPath);
			byte[] contents = new byte[fis.available()];
			fis.read(contents);			
			fis.close();
			retval = new String(contents);
		} catch (FileNotFoundException e) {
			getPrintStream().println("Error : request data file couln't be found.");
			System.exit(-1); // NOPMD, it's not a JEE app		
		} catch (IOException e) {
			getPrintStream().println("Error reading content of request data file.");
			System.exit(-1); // NOPMD, it's not a JEE app	
		}
		
		
		return retval;
	}

	private String getOutputPath(String outputpath) {
		File dir = new File(outputpath);
		if(!dir.exists()){
			getPrintStream().println("Error : Output directory doesn't seem to exist.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		if(!dir.isDirectory()){
			getPrintStream().println("Error : Output directory doesn't seem to be a directory.");
			System.exit(-1); // NOPMD, it's not a JEE app			
		}
		if(!dir.canWrite()){
			getPrintStream().println("Error : Output directory isn't writeable.");
			System.exit(-1); // NOPMD, it's not a JEE app

		}
		return outputpath;
	}

	private String getEncoding(String encoding) {
		if(!encoding.equalsIgnoreCase("PEM") && !encoding.equalsIgnoreCase("DER")){
			usage();
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		
		return encoding.toUpperCase();
	}

	private int getRequestType(String requestype) {
		if(requestype.equals("PKCS10")){
			return CertificateHelper.CERT_REQ_TYPE_PKCS10;
		}
		if(requestype.equals("CRMF")){
			return CertificateHelper.CERT_REQ_TYPE_CRMF;
		}
		if(requestype.equals("SPKAC")){
			return CertificateHelper.CERT_REQ_TYPE_SPKAC;
		}
		usage();
		System.exit(-1); // NOPMD, it's not a JEE app
		return 0;
	}



	protected void usage() {
		getPrintStream().println("Command used to generate a users certificate.");
        getPrintStream().println("Usage : certreq <username> <subjectdn> <subjectaltname or NULL> <caname> <endentityprofilename> <certificateprofilename> <reqpath> <reqtype (PKCS10|SPKAC|CRMF)> <encoding (DER|PEM)> <hardtokensn (or NONE)> <outputpath (optional)> \n\n");       
        getPrintStream().println("outputpath : directory where certificate is written in form outputpath/username+.cer|.pem ");
   }


}
