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
package org.ejbca.core.protocol.crlstore;

import javax.ejb.EJBException;

import org.cesecore.core.ejb.ca.crl.CrlSessionStandAlone;
import org.cesecore.core.ejb.ca.crl.CrlSessionStandAloneRemote;
import org.ejbca.core.ejb.JndiHelper;
/**
 * DB store of data to be used by the CA
 *
 * @author primelars
 * @version $Id$
 *
 */
public class CRLStoreStandAlone extends CRLStoreBase {
	private CrlSessionStandAlone m_crlSession = null;
	/* (non-Javadoc)
	 * @see org.ejbca.core.protocol.crlstore.CRLStoreBase#getCRLStore()
	 */
	@Override
	synchronized CrlSessionStandAlone getCRLStore(){
		if(this.m_crlSession == null){	
			try {
				this.m_crlSession = JndiHelper.getRemoteSession(CrlSessionStandAloneRemote.class);	// TODO: Use a local EJB stub instead
			}catch(Exception e){
				throw new EJBException(e);      	  	    	  	
			}
		}
		return this.m_crlSession;
	}
}
