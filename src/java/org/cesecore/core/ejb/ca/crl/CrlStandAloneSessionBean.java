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
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;

/**
 * The name is kept for historic reasons. This Session Bean is used for creating and retrieving CRLs and information about CRLs.
 * CRLs are signed using RSASignSessionBean.
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CrlSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CrlStandAloneSessionBean extends CrlSessionBeanBase implements CrlSessionLocal, CrlSessionRemote {

	@PersistenceContext(unitName="ejbca")
	EntityManager entityManager;

	@Override
	EntityManager getEntityManager() {
		return this.entityManager;
	}

	@Override
	void log(Admin admin, int hashCode, int moduleCa, Date date, String string, Certificate cert, int eventInfoGetlastcrl, String msg) {
		// do nothing since there is no logging session.
	}
	
	// 
	// Methods overriding implementations in CrlSessionBeanBase, needed because of the following bug in JBoss 6.0.0.
	// https://issues.jboss.org/browse/JBMDR-73
	//
	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	@Override
	public byte[] getLastCRL(Admin admin, String issuerdn, boolean deltaCRL) {
		return super.getLastCRL(admin, issuerdn, deltaCRL);
	}

	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	@Override
	public CRLInfo getLastCRLInfo(Admin admin, String issuerdn, boolean deltaCRL) {
		return super.getLastCRLInfo(admin, issuerdn, deltaCRL);
	}

	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	@Override
	public CRLInfo getCRLInfo(Admin admin, String fingerprint) {
		return super.getCRLInfo(admin, fingerprint);
	}

	@TransactionAttribute(TransactionAttributeType.SUPPORTS)
	@Override
	public int getLastCRLNumber(Admin admin, String issuerdn, boolean deltaCRL) {
		return super.getLastCRLNumber(admin, issuerdn, deltaCRL);
	}

	
	/* *******************************************************************
	 * The following methods are not implemented in stand alone VA mode! *
	 *********************************************************************/
	
	@Override
	public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number, String issuerDN, Date thisUpdate, Date nextUpdate, int deltaCRLIndicator) {
		throw new RuntimeException("Not implemented in stand alone version.");
	}
}
