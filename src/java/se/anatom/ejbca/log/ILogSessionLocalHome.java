package se.anatom.ejbca.log;

import javax.ejb.CreateException;
/**
 * DOCUMENT ME!
 *
 * @version $Id: ILogSessionLocalHome.java,v 1.4 2003-09-04 08:05:01 herrvendil Exp $
 */
public interface ILogSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ILogSessionRemote interface
     *
     * @throws CreateException
     */

    ILogSessionLocal create() throws CreateException;


}

