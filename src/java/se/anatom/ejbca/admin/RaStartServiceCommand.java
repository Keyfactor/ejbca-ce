
package se.anatom.ejbca.admin;


/** Starts an external service needed for user administrations, runs in the same JVM.
 *
 * @version $Id: RaStartServiceCommand.java,v 1.3 2003-01-12 17:16:30 anatom Exp $
 */
public class RaStartServiceCommand extends BaseRaAdminCommand {

    /** Creates a new instance of StartServiceCommand */
    public RaStartServiceCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            getAdminSession().startExternalService(args);
            System.out.println("External service started");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

}
