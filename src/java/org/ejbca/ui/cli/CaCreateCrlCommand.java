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
 
package org.ejbca.ui.cli;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id: CaCreateCrlCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class CaCreateCrlCommand extends BaseCaAdminCommand {
    /**
     * Creates a new instance of CaCreateCrlCommand
     *
     * @param args command line arguments
     */
    public CaCreateCrlCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 1) {
	       throw new IllegalAdminCommandException("Usage: CA createcrl <caname>" +
	       		                                                               "If no caname is given then will CRLs for all neccessary CAs be created.");
	    }	
        
        if (args.length == 1) {
        	try{
        	  createCRL((String) null);
        	} catch (Exception e) {
        		throw new ErrorAdminCommandException(e);
        	}        	
        }	
        
        if(args.length == 2){
          try {            
            String caname = args[1];	    
            // createCRL prints info about crl generation            
            createCRL(getIssuerDN(caname));
          } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
          }
        }  
    }

    // execute
}
