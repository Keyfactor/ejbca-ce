package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IPublisherSessionLocalHome.java,v 1.2 2003-06-26 11:43:23 anatom Exp $
 */
public interface IPublisherSessionLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return IPublisherSessionLocal interface
     *
     * @throws CreateException
     */
    IPublisherSessionLocal create() throws CreateException;
}
