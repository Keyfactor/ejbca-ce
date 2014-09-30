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
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Request a certificate given a pkcs10
 *
 * @version $Id$
 */
public class PKCS10ReqCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_USERNAME                 = 1;
	private static final int ARG_PASSWORD                 = 2;
	private static final int ARG_PKCS10                   = 3;
	private static final int ARG_ENCODING                 = 4;
	private static final int ARG_HARDTOKENSN              = 5;
	private static final int ARG_OUTPUTPATH               = 6;
	
    /**
     * Creates a new instance of PKCS10ReqCommand
     *
     * @param args command line arguments
     */
    public PKCS10ReqCommand(String[] args) {
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
           
            if(args.length <  6 || args.length > 7){
            	usage();
            	System.exit(-1); // NOPMD, it's not a JEE app
            }
            
            String username = args[ARG_USERNAME];            
            String password = args[ARG_PASSWORD];
            String pkcs10 = getPKCS10(args[ARG_PKCS10]);
            String encoding = getEncoding(args[ARG_ENCODING]);
            String hardtokensn = getHardTokenSN(args[ARG_HARDTOKENSN]);
            
            String outputPath = null;
            if(args.length == 7){
              outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
            }
            
            try{
            	CertificateResponse result = getEjbcaRAWS().pkcs10Request(username,password,pkcs10,hardtokensn,CertificateHelper.RESPONSETYPE_CERTIFICATE);
            	
            	if(result==null){
            		getPrintStream().println("No certificate could be generated for user, check server logs for error.");
            	}else{
            		String filepath = username;
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

	private String getPKCS10(String pkcs10Path) {
		String retval=null;
		try {
			FileInputStream fis = new FileInputStream(pkcs10Path);
			byte[] contents = new byte[fis.available()];
			fis.read(contents);			
			fis.close();
			retval = new String(contents);
		} catch (FileNotFoundException e) {
			getPrintStream().println("Error : PKCS10 file couln't be found.");
			System.exit(-1); // NOPMD, it's not a JEE app		
		} catch (IOException e) {
			getPrintStream().println("Error reading content of PKCS10 file.");
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



	protected void usage() {
		getPrintStream().println("Command used to generate a users certificate");
		getPrintStream().println("Usage : pkcs10req <username> <password> <pkcs10path> <encoding (DER|PEM)> <hardtokensn (or NONE)> <outputpath (optional)> \n\n");       
        getPrintStream().println("outputpath : directory where certificate is written in form username+.cer|.pem ");
   }


}
