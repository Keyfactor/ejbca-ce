package se.anatom.ejbca.ca.auth;

import javax.ejb.CreateException;


/**
 * Local home for authentication session
 *
 * @version $Id: IAuthenticationSessionLocalHome.java,v 1.4 2003-06-26 11:43:22 anatom Exp $
 */
public interface IAuthenticationSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IAuthenticationSessionRemote interface
     *
     * @throws CreateException
     */
    IAuthenticationSessionLocal create() throws CreateException;
}
