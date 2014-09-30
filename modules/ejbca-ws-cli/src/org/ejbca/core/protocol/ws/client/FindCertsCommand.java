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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Finds a certificates in the database
 *
 * @version $Id$
 */
public class FindCertsCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_USERNAME                 = 1;
	private static final int ARG_ONLYVALID                = 2;  
	private static final int ARG_ENCODING                 = 3;
	private static final int ARG_OUTPUTPATH               = 4;
	
    public FindCertsCommand(String[] args) {
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
           
            if(args.length !=  5){
            	usage();
            	System.exit(-1); // NOPMD, it's not a JEE app
            }
            
            String username = args[ARG_USERNAME];            
            boolean onlyValid = getOnlyValid(args[ARG_ONLYVALID]);
            String encoding = getEncoding(args[ARG_ENCODING]);
            String outputPath = getOutputPath(args[ARG_OUTPUTPATH]);
            
            
            try{
            	List<Certificate> result = getEjbcaRAWS().findCerts(username, onlyValid);
            	
            	if(result==null || result.size() == 0){
            		getPrintStream().println("No certificate could be found for user");
            	}else{
            		getPrintStream().println(result.size() + " certificate found, written to " + outputPath);
            		Iterator<Certificate> iter = result.iterator();
            		int i=0;
            		while(iter.hasNext()){
            			i++;
            			Certificate cert = iter.next();
            			if(encoding.equals("DER")){
            			    FileOutputStream fos = new FileOutputStream(outputPath + "/" + username + "-" + i +".cer");
            			    fos.write(CertificateHelper.getCertificate(cert.getCertificateData()).getEncoded());
            			    fos.close();
            			}else{
            				FileOutputStream fos = new FileOutputStream(outputPath + "/" + username + "-" + i +".pem");
            				ArrayList<java.security.cert.Certificate> list = new ArrayList<java.security.cert.Certificate>();
            				list.add(CertificateHelper.getCertificate(cert.getCertificateData()));
            				fos.write(CertTools.getPemFromCertificateChain(list));
            				fos.close();            				            				
            			}                        
            		}
            	}
            	             
            }catch(AuthorizationDeniedException_Exception e){
            	getPrintStream().println("Error : " + e.getMessage());
            }           
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
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

	private boolean getOnlyValid(String onlyValid) {
		if(onlyValid.equalsIgnoreCase("true")){
			return true;
		}
		if(onlyValid.equalsIgnoreCase("false")){
			return false;
		}
		usage();
		System.exit(-1); // NOPMD, it's not a JEE app				
		return false; // Should never happen
	}

	protected void usage() {
		getPrintStream().println("Command used to find a users certificates");
		getPrintStream().println("Usage : findcerts <username> <onlyvalid (true|false)> <encoding (DER|PEM)> <outputpath> \n\n");
        getPrintStream().println("onlyvalid = true only returns nonexired and unrevoked certificates ");
        getPrintStream().println("outputpath : directory where certificates are written in form username+nn ");
   }


}
