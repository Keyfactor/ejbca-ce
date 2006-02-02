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

import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.log.Admin;

/**
 * Sets the base url of the web interface
 *
 * @version $Id: SetupSetBaseURLCommand.java,v 1.2 2006-02-02 10:08:39 herrvendil Exp $
 */
public class SetupSetBaseURLCommand extends BaseAdminCommand {
    /**
     * Creates a new instance of CaCreateCrlCommand
     *
     * @param args command line arguments
     */
    public SetupSetBaseURLCommand(String[] args) {
        super(args, Admin.TYPE_CACOMMANDLINE_USER);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 3) {
	       throw new IllegalAdminCommandException("Usage: SETUP setdefaultbaseurl <computername> <applicationpath>\n" + 
	       		                                                               "Example: setup setbaseurl localhost ejbca \n\n");	       
	    }	
        try {            
        	//InitialContext jndicontext = new InitialContext();
        	InitialContext jndicontext = getInitialContext();
        	
        	String computername = args[1];
        	String applicationpath = args[2];
        	IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"),
        			IRaAdminSessionHome.class);
        	
        	IRaAdminSessionRemote raadminsession = raadminsessionhome.create();
        	
        	raadminsession.initGlobalConfigurationBaseURL(new Admin(Admin.TYPE_CACOMMANDLINE_USER), computername, applicationpath);
        	
        	
        } catch (Exception e) {
        	throw new ErrorAdminCommandException(e);            
        }
    }

    // execute
}
