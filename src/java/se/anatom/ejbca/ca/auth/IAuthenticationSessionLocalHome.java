
package se.anatom.ejbca.ca.auth;

import javax.ejb.CreateException;
import se.anatom.ejbca.log.Admin;

/**
 * @version $Id: IAuthenticationSessionLocalHome.java,v 1.2 2002-09-12 18:14:16 herrvendil Exp $
 */
public interface IAuthenticationSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return IAuthenticationSessionRemote interface
     */
    IAuthenticationSessionLocal create(Admin administrator) throws CreateException;
}
