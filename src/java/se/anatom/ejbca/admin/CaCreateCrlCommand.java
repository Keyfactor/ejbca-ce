
package se.anatom.ejbca.admin;

/** Issues a new CRL from the CA.
 *
 * @version $Id: CaCreateCrlCommand.java,v 1.3 2003-01-12 17:16:30 anatom Exp $
 */
public class CaCreateCrlCommand extends BaseCaAdminCommand {

    /** Creates a new instance of CaCreateCrlCommand */
    public CaCreateCrlCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            // createCRL prints info about crl generation
            createCRL();
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
