
package se.anatom.ejbca.ca.auth;

import javax.ejb.CreateException;

/**
 * @version $Id: IAuthenticationSessionLocalHome.java,v 1.3 2002-11-17 14:01:39 herrvendil Exp $
 */
public interface IAuthenticationSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return IAuthenticationSessionRemote interface
     */
    IAuthenticationSessionLocal create() throws CreateException;
}
