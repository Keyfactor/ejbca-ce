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

package org.cesecore.core.ejb.ca.crl;

import java.security.cert.Certificate;
import java.util.Date;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.log.Admin;

/**
 * The name is kept for historic reasons. This Session Bean is used for creating and retrieving CRLs and information about CRLs.
 * CRLs are signed using RSASignSessionBean.
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CrlSessionStandAloneRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlSessionStandAloneBean extends CrlSessionBeanBase implements CrlSessionStandAloneLocal, CrlSessionStandAloneRemote{

	@PersistenceContext(unitName="ejbca") EntityManager entityManager;

	/* (non-Javadoc)
	 * @see org.cesecore.core.ejb.ca.crl.CrlSessionBeanBase#getEntityManager()
	 */
	@Override
	EntityManager getEntityManager() {
		return this.entityManager;
	}

	/* (non-Javadoc)
	 * @see org.cesecore.core.ejb.ca.crl.CrlSessionBeanBase#log(org.ejbca.core.model.log.Admin, int, int, java.util.Date, java.lang.String, java.security.cert.Certificate, int, java.lang.String)
	 */
	@Override
	void log(Admin admin, int hashCode, int moduleCa, Date date,
	         String string, Certificate cert, int eventInfoGetlastcrl, String msg) {
		// do nothing since there is no logging session.
	}

}
