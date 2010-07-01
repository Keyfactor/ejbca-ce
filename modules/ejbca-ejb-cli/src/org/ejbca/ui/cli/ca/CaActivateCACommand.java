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

import java.rmi.UnmarshalException;

import javax.security.auth.login.FailedLoginException;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CryptoProviderTools;

/**
 * Activates the specified HSM CA.
 *
 * @version $Id$
 */
public class CaActivateCACommand extends BaseCaAdminCommand {

	public String getMainCommand() { return MAINCOMMAND; }
	public String getSubCommand() { return "activateca"; }
	public String getDescription() { return "Activates the specified HSM CA"; }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            if (args.length < 2) {
    			getLogger().info("Description: " + getDescription());
                getLogger().info("Usage: " + getCommand()+ " <CA name> [<authorization code>]");
                getLogger().info(" Leaving out authorization code will prompt for it.");
                return;
            }
            String caname = args[1];
            String authorizationcode = null;
            if (args.length > 2) {
            	authorizationcode = args[2];
            } else {
            	getLogger().info("Enter authorization code: ");
                // Read the password, but mask it so we don't display it on the console
                authorizationcode = String.valueOf(System.console().readPassword());            	
            }
            CryptoProviderTools.installBCProvider();
            // Get the CAs info and id
            CAInfo cainfo = getCAAdminSession().getCAInfo(getAdmin(), caname);
            if(cainfo == null){
            	getLogger().error("Error: CA " + caname + " cannot be found");	
            	return;            	
            }
            // Check that CA has correct status.
            if ( (cainfo.getStatus() == SecConst.CA_OFFLINE) || (cainfo.getCATokenInfo().getCATokenStatus() == ICAToken.STATUS_OFFLINE) ) {
            	try {
                	getCAAdminSession().activateCAToken(getAdmin(), cainfo.getCAId(), authorizationcode, getRaAdminSession().loadGlobalConfiguration(getAdmin()));            		
                	getLogger().info("CA token activated.");
            	} catch (UnmarshalException e) {
            		// If we get a classnotfound we are probably getting an error back from the token, 
            		// with a class we don't have here at the CLI. It is probably invalid PIN
            		getLogger().error("Error returned, did you enter the correct PIN?");
            		getLogger().error(e.getMessage());
            	} catch (CATokenAuthenticationFailedException e) {
            		getLogger().error("CA Token authentication failed.");
            		getLogger().error(e.getMessage());
            		Throwable t = e.getCause();
            		while (t != null) {
            			if (t instanceof FailedLoginException) {
            				// If it's an HSM the next exception will be a PKCS11 exception. We don't want to search directly for that though, because then we 
            				// will import sun specific classes, and we don't want that.
            				t = t.getCause();
            				if (t != null) {
                				getLogger().error(t.getMessage());
                				break;
            				}
						} else {
		            		t = t.getCause();
						}
            		}
            		getLogger().debug("Exception: ", e);            		
            	} catch (ApprovalException e){
            		getLogger().error("CA Token activation approval request already exists.");
            	} catch (WaitingForApprovalException e){
            		getLogger().error("CA requires an approval to be activated. A request have been sent to authorized getAdmin()s." );
            	}
            }else{
            	getLogger().error("CA or CAToken must be offline to be activated.");
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
}
