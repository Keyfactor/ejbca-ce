package se.anatom.ejbca.admin;

import javax.naming.InitialContext;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;

/**
 * Sets the base url of the web interface
 *
 * @version $Id: SetupSetBaseURLCommand.java,v 1.1 2004-01-31 14:24:58 herrvendil Exp $
 */
public class SetupSetBaseURLCommand extends BaseAdminCommand {
    /**
     * Creates a new instance of CaCreateCrlCommand
     *
     * @param args command line arguments
     */
    public SetupSetBaseURLCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        if (args.length < 2) {
	       throw new IllegalAdminCommandException("Usage: SETUP setbaseurl <computername> <applicationpath>\n" + 
	       		                                                               "Example: setup setbaseurl localhost ejbca \n\n");	       
	    }	
        try {            
        	InitialContext jndicontext = new InitialContext();
        	
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
