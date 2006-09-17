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

import java.io.File;
import java.io.FileOutputStream;

//import org.ejbca.core.model.authorization.wsclient.AuthorizationDeniedException;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
//import org.ejbca.core.protocol.ws.wsclient.KeyStore;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Request a keystore given a pkcs12
 *
 * @version $Id: PKCS12ReqCommand.java,v 1.1 2006-09-17 23:00:25 herrvendil Exp $
 */
public class PKCS12ReqCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_USERNAME                 = 1;
	private static final int ARG_PASSWORD                 = 2;
	private static final int ARG_KEYSIZE                  = 3;
	private static final int ARG_HARDTOKENSN              = 4;
	private static final int ARG_OUTPUTPATH               = 5;
	
    /**
     * Creates a new instance of PKCS12ReqCommand
     *
     * @param args command line arguments
     */
    public PKCS12ReqCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        /*
    	try {   
           
            if(args.length <  5 || args.length > 6){
            	usage();
            	System.exit(-1);
            }
            
            String username = args[ARG_USERNAME];            
            String password = args[ARG_PASSWORD];
            int keysize = getKeySize(args[ARG_KEYSIZE]);
            String hardtokensn = getHardTokenSN(args[ARG_HARDTOKENSN]);
            
            String outputPath = null;
            if(args.length == 6){
              outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
            }
            
            try{
            	KeyStore result = getEjbcaRAWS().pkcs12Req(username,password,hardtokensn,keysize);
            	
            	if(result==null){
            		getPrintStream().println("No keystore could be generated for user, check server logs for error.");
            	}else{
            		String filepath = username + ".p12";
            		
            		if(outputPath != null){
            			filepath = outputPath + "/" + filepath;
            		}
            		            		
            		FileOutputStream fos = new FileOutputStream(filepath);
            		java.security.KeyStore ks = KeyStoreHelper.getKeyStore(result.getKeystoreData(),"PKCS12",password);
            		ks.store(fos, password.toCharArray());
            		fos.close();            		
            		getPrintStream().println("Keystore generated, written to " + filepath);
            	}
            	             
            }catch(AuthorizationDeniedException e){
            	getPrintStream().println("Error : " + e.getMessage());            
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }*/
    }



	

	private int getKeySize(String keysize) {
		if(keysize.equals("512")){
			return 512;
		}
		if(keysize.equals("1024")){
			return 1024;
		}
		if(keysize.equals("2048")){
			return 2048;
		}
		if(keysize.equals("4096")){
			return 4096;
		}		
		getPrintStream().println("Error in keysize : " + keysize);
		usage();
		System.exit(-1);
		
		return 0;
	}

	private String getHardTokenSN(String hardtokensn) {
		if(hardtokensn.equalsIgnoreCase("NONE")){
		  return null;
		}
		
		return hardtokensn;
	}


	private String getOutputPath(String outputpath) {
		File dir = new File(outputpath);
		if(!dir.exists()){
			getPrintStream().println("Error : Output directory doesn't seem to exist.");
			System.exit(-1);
		}
		if(!dir.isDirectory()){
			getPrintStream().println("Error : Output directory doesn't seem to be a directory.");
			System.exit(-1);			
		}
		if(!dir.canWrite()){
			getPrintStream().println("Error : Output directory isn't writeable.");
			System.exit(-1);

		}
		return outputpath;
	}




	protected void usage() {
		getPrintStream().println("Command used to generate a users keystore");
		getPrintStream().println("Usage : pkcs12req <username> <password>  <keysize (512|1024|2048|4096)> <hardtokensn (or NONE)> <outputpath (optional)> \n\n");                
   }


}
