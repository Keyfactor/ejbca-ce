
package se.anatom.ejbca.ca.auth;

import javax.ejb.CreateException;

/**
 * @version $Id: IAuthenticationSessionLocalHome.java,v 1.1 2002-05-26 12:42:25 anatom Exp $
 */
public interface IAuthenticationSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return IAuthenticationSessionRemote interface
     */
    IAuthenticationSessionLocal create() throws CreateException;
}
