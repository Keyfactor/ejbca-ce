package se.anatom.ejbca.ca.crl;


import javax.ejb.CreateException;
import javax.ejb.EJBLocalHome;


/**
 * Home interface for Create CRL session.
 *
 * @version $Id: ICreateCRLSessionLocalHome.java,v 1.1 2004-02-11 10:44:12 herrvendil Exp $
 */

public interface ICreateCRLSessionLocalHome extends EJBLocalHome {
    /**
     * Default create method. Maps to ejbCreate in implementation.
     *
     * @return ICreateCRLSessionLocal interface
     *
     * @throws CreateException 
     */
    ICreateCRLSessionLocal create() throws CreateException;
}
