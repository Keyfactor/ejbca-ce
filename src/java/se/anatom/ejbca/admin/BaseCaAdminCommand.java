
package se.anatom.ejbca.admin;

import java.security.cert.Certificate;
import javax.naming.*;

import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSession;

/** Base for CA commands, contains comom functions for CA operations
 *
 * @version $Id: BaseCaAdminCommand.java,v 1.1 2002-04-07 09:55:29 anatom Exp $
 */
public abstract class BaseCaAdminCommand extends BaseAdminCommand {

    /** Creates a new instance of BaseCaAdminCommand */
    public BaseCaAdminCommand(String[] args) {
        super(args);
    }
    
    /** Retrieves the complete certificate chain from the CA
     *
     *@return array of certificates, from ISignSession.getCertificateChain()
     */
    protected Certificate[] getCertChain() {
        try {
            Context ctx = getInitialContext();
            ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
            ISignSession ss = home.create();
            Certificate[] chain = ss.getCertificateChain();
            return chain;
        } catch (Exception e) {
            error("Error while getting certfificate chain from CA.", e);
        }
        return null;
    } // getCertChain

}
