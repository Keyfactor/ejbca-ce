
package se.anatom.ejbca.ca.sign;

import javax.ejb.CreateException;

/**
 * @version $Id: ISignSessionLocalHome.java,v 1.3 2002-11-17 14:01:38 herrvendil Exp $
 */
public interface ISignSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return ISignSessionRemote interface
     */
    ISignSessionLocal create() throws CreateException;
}
