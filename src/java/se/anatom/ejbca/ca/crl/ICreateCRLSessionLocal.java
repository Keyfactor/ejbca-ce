package se.anatom.ejbca.ca.crl;

import se.anatom.ejbca.log.Admin;


/**
 * CreateCRL Session bean is only used to create CRLs.
 *
 * @version $Id: ICreateCRLSessionLocal.java,v 1.1 2004-02-11 10:44:12 herrvendil Exp $
 */
public interface ICreateCRLSessionLocal extends javax.ejb.EJBLocalObject  {
    /**
     * Runs the job
     *
     * @param admin administrator running the job
     *
     */
    public void run(Admin admin,String issuerdn);
    
    /**
     *@see se.anatom.ejbca.ca.crl.ICreateCRLSessionRemote
     */	    
    public int createCRLs(Admin admin);
}
