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

import javax.naming.InitialContext;

import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionRemote;
import org.ejbca.core.model.ra.UserDataConstants;


/**
 * Find details of a user in the database.
 *
 * @version $Id: RaKeyRecoverNewestCommand.java,v 1.1 2006-01-17 20:28:05 anatom Exp $
 */
public class RaKeyRecoverNewestCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaFindUserCommand
     *
     * @param args command line arguments
     */
    public RaKeyRecoverNewestCommand(String[] args) {
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
            if (args.length != 2) {
                getOutputStream().println("Usage: RA keyrecovernewest <username>");

                return;
            }

            //InitialContext jndicontext = new InitialContext();
            InitialContext jndicontext = getInitialContext();

            IKeyRecoverySessionHome keyrecoverysessionhome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup(
                        "KeyRecoverySession"), IKeyRecoverySessionHome.class);
            IKeyRecoverySessionRemote keyrecoverysession = keyrecoverysessionhome.create();

            String username = args[1];

             boolean usekeyrecovery = getRaAdminSession().loadGlobalConfiguration(administrator).getEnableKeyRecovery();  
             if(!usekeyrecovery){
               getOutputStream().println("Keyrecovery have to be enabled in the system configuration in order to use this command.");
               return;                   
             }   
               
             if(keyrecoverysession.isUserMarked(administrator,username)){
               getOutputStream().println("User is already marked for recovery.");
               return;                     
             }
             
             keyrecoverysession.markNewestAsRecoverable(administrator, username);
        
             getAdminSession().setUserStatus(administrator, username, UserDataConstants.STATUS_KEYRECOVERY); 
             getOutputStream().println("Key corresponding to users newest certificate has been marked for recovery.");             
 

        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
}
