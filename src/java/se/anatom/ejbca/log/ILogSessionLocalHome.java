package se.anatom.ejbca.log;

import javax.ejb.CreateException;

/**
 * @version $Id: ILogSessionLocalHome.java,v 1.1 2002-09-12 17:12:13 herrvendil Exp $
 */

public interface ILogSessionLocalHome extends javax.ejb.EJBLocalHome {

    /**
     * Default create method. Maps to ejbCreate in implementation.
     * @throws CreateException
     * @return IRaAdminSessionRemote interface
     */

    ILogSessionLocal create() throws Exception;


}

