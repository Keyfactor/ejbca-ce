
package se.anatom.ejbca.admin;

import java.io.*;

/** Issues a new CRL from the CA.
 *
 * @version $Id: CaCreateCrlCommand.java,v 1.1 2002-04-13 18:11:27 anatom Exp $
 */
public class CaCreateCrlCommand extends BaseCaAdminCommand {

    /** Creates a new instance of CaCreateCrlCommand */
    public CaCreateCrlCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            createCRL();
            System.out.println("Created new CRL.");
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
