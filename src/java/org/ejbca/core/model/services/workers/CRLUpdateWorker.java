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

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Class managing the updating of CRLs.
 * 
 * This is a replacement of the old jboss service.
 * 
 * @author Philip Vendil
 * @version $Id: CRLUpdateWorker.java,v 1.4 2007-12-21 09:02:55 anatom Exp $
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
	    ICreateCRLSessionLocal session = getCreateCRLSession();
	    if (session != null) {
	    	session.createCRLs(getAdmin(), polltime*1000);
	    	session.createDeltaCRLs(getAdmin(), polltime*1000);
	    }
	}

	
	public ICreateCRLSessionLocal getCreateCRLSession(){
		if(createcrlsession == null){
			try {
	            ICreateCRLSessionLocalHome home = (ICreateCRLSessionLocalHome) getLocator().getLocalHome(ICreateCRLSessionLocalHome.COMP_NAME);
				this.createcrlsession = home.create();
			} catch (CreateException e) {
				log.error(e);
			}
		}
  
		return createcrlsession;
	}
}
