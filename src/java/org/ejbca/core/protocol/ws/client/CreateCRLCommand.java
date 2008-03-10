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


import java.util.List;

import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Revokes a given users certificate and set's it status to REVOKED
 *
 * @version $Id: CreateCRLCommand.java,v 1.1 2008-03-10 14:49:24 anatom Exp $
 */
public class CreateCRLCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
    /**
     * @param args command line arguments
     */
    public CreateCRLCommand(String[] args) {
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
           
            if(args.length != 2){
            	usage();
            	System.exit(-1);
            }
            
            String caname = args[1];            
            
            getEjbcaRAWS().createCRL(caname);
            getPrintStream().println("CRL generated for CA: "+caname);
         } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }


	protected void usage() {
		getPrintStream().println("Command used to generate a new CRL for a CA");
		getPrintStream().println("Usage : createcrl <caname>\n\n");
   }


}
