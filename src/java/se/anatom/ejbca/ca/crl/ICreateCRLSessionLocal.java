/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.ca.crl;

import se.anatom.ejbca.log.Admin;


/**
 * CreateCRL Session bean is only used to create CRLs.
 *
 * @version $Id: ICreateCRLSessionLocal.java,v 1.2 2004-04-16 07:39:00 anatom Exp $
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
