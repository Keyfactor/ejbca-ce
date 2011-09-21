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
 
package org.ejbca.ui.cli.ca;

import org.apache.commons.lang.StringUtils;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Issues a new CRL from the CA.
 *
 * @version $Id$
 */
public class CaCreateCrlCommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "createcrl"; }
	public String getDescription() { return "Issues a new CRL from the CA"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        String cliUserName = "ejbca";
        String cliPassword = "ejbca";
        
        if ( (args.length < 1) || ((args.length > 1) && StringUtils.equals(args[1], "-?")) ) {
			getLogger().info("Description: " + getDescription());
			getLogger().info("Usage: " + getCommand() + " <caname> <-delta>");
			getLogger().info(" If no caname is given, CRLs will be created for all the CAs where it is neccessary.");
			return;
        }
        if (args.length == 1) {
        	try{
        	  createCRL(getAdmin(cliUserName, cliPassword), (String) null, false);
        	  getLogger().info("You can also run this command with \"" + getCommand() + " <caname> <-delta>\" to force CRL creation for a CA.");
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
              CryptoProviderTools.installBCProvider();
              // createCRL prints info about crl generation
              String issuerName = getIssuerDN(getAdmin(cliUserName, cliPassword), caname);
              if (issuerName != null) {
                  createCRL(getAdmin(cliUserName, cliPassword), issuerName, deltaCRL);
              } else {
            	  getLogger().error("No such CA exists.");
              }
          } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
          }
        }  
    }
}
