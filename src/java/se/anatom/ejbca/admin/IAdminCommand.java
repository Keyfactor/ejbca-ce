package se.anatom.ejbca.admin;

/**
 * Interface for Commands used for admin cmdline GUI
 *
 * @version $Id: IAdminCommand.java,v 1.2 2003-06-26 11:43:22 anatom Exp $
 */
public interface IAdminCommand {
    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException;
}
