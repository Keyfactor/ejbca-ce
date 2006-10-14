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
package org.ejbca.core.model.services.workers;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Class managing the updating of CRLs.
 * 
 * This is a replacement of the old jboss service.
 * @author Philip Vendil
 *
 * $id$
 */
public class CRLUpdateWorker extends BaseWorker {

    private static Logger log = Logger.getLogger(CRLUpdateWorker.class);	
	
	  private ICreateCRLSessionLocal createcrlsession = null;
	
	/**
	 * Checks if there are any CRL that needs to be updated, and then does the creation.
	 * 
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work() throws ServiceExecutionFailedException {
	    long polltime = getNextInterval();
	    getCreateCRLSession().createCRLs(getAdmin(), polltime*1000);

	}

	
	public ICreateCRLSessionLocal getCreateCRLSession(){
		if(createcrlsession == null){
			try {
				Context context = new InitialContext();
				ICreateCRLSessionLocalHome home = (ICreateCRLSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"CreateCRLSessionLocal"), ICreateCRLSessionLocalHome.class);
				this.createcrlsession = home.create();
			} catch (NamingException e) {
				log.error(e);
			} catch (CreateException e) {
				log.error(e);
			}
		}
  
		return createcrlsession;
	}
}
