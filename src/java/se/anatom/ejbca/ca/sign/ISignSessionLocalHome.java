
package se.anatom.ejbca.ca.sign;

import javax.ejb.CreateException;

/**
 * @version $Id: ISignSessionLocalHome.java,v 1.1 2002-05-26 13:28:53 anatom Exp $
 */
public interface ISignSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return ISignSessionRemote interface
     */
    ISignSessionLocal create() throws CreateException;
}
