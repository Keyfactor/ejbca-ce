package se.anatom.ejbca.ca.sign;

import javax.ejb.CreateException;


/**
 * Local Home interface for session bean
 *
 * @version $Id: ISignSessionLocalHome.java,v 1.4 2003-06-26 11:43:23 anatom Exp $
 */
public interface ISignSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ISignSessionRemote interface
     *
     * @throws CreateException
     */
    ISignSessionLocal create() throws CreateException;
}
