
package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;

/**
 * @version $Id: IPublisherSessionLocalHome.java,v 1.1 2002-06-04 14:37:07 anatom Exp $
 */
public interface IPublisherSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return IPublisherSessionLocal interface
     */
    IPublisherSessionLocal create() throws CreateException;
}
