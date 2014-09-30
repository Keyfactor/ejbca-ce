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
import java.io.FileOutputStream;

import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.common.KeyStoreHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Request a keystore given a pkcs12
 *
 * @version $Id$
 */
public class PKCS12ReqCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_USERNAME                 = 1;
	private static final int ARG_PASSWORD                 = 2;
	private static final int ARG_KEYSPEC                  = 3;
	private static final int ARG_KEYALG                   = 4;
	private static final int ARG_HARDTOKENSN              = 5;
	private static final int ARG_OUTPUTPATH               = 6;
	
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
       
    	try {   
           
            if (args.length < 6 || args.length > 7) {
            	usage();
            	System.exit(-1); // NOPMD, it's not a JEE app
            }
            
            String username = args[ARG_USERNAME];            
            String password = args[ARG_PASSWORD];
            String keyspec = args[ARG_KEYSPEC];
            String keyalg = args[ARG_KEYALG];
            String hardtokensn = getHardTokenSN(args[ARG_HARDTOKENSN]);
            
            String outputPath = null;
            if (args.length == 7) {
              outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
            }
            
            try{
            	KeyStore result = getEjbcaRAWS().pkcs12Req(username,password,hardtokensn,keyspec,keyalg);
            	
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




	protected void usage() {
		getPrintStream().println("Command used to generate a users keystore");
		getPrintStream().println("Usage : pkcs12req <username> <password>  <keyspec (1024|1536|2048|4096|8192|secp256r1|etc.)> <keyalg (RSA|ECDSA)> <hardtokensn (or NONE)> <outputpath (optional)> \n\n");                
   }


}
