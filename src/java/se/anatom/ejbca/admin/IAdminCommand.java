
package se.anatom.ejbca.admin;

/** Interface for Commands used for admin cmdline GUI
 *
 * @version $Id: IAdminCommand.java,v 1.1 2002-04-07 09:55:29 anatom Exp $
 */
public interface IAdminCommand {

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException;
    
}

