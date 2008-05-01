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

import org.apache.commons.lang.StringUtils;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id$
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
        if ( (args.length < 1) || ((args.length > 1) && StringUtils.equals(args[1], "-?")) ) {
	       throw new IllegalAdminCommandException("Usage: CA createcrl <caname> <-delta>\n" 
	    		   + "If no caname is given then will CRLs for all neccessary CAs be created.");
	    }	
        
        if (args.length == 1) {
        	try{
        	  createCRL((String) null, false);
        	} catch (Exception e) {
        		throw new ErrorAdminCommandException(e);
        	}        	
        }	
        
        if(args.length > 1){
            try {            
              String caname = args[1];
              boolean deltaCRL = false;
              if (args.length > 2) {
              	if (StringUtils.equals(args[2], "-delta")) {
              		deltaCRL = true;
              	}
              }
              // createCRL prints info about crl generation            
              createCRL(getIssuerDN(caname), deltaCRL);
          } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
          }
        }  
    }

    // execute
}
