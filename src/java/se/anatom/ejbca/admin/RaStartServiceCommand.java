
package se.anatom.ejbca.admin;

import java.io.*;

/** Starts an external service needed for user administrations, runs in the same JVM.
 *
 * @version $Id: RaStartServiceCommand.java,v 1.1 2002-06-10 10:40:52 anatom Exp $
 */
public class RaStartServiceCommand extends BaseRaAdminCommand {

    /** Creates a new instance of StartServiceCommand */
    public RaStartServiceCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            getAdminSession().startExternalService();
            System.out.println("External service started");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

}
