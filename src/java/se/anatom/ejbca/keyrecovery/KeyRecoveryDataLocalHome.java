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
 
package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocalHome.java,v 1.6 2004-04-16 07:38:59 anatom Exp $
 */
public interface KeyRecoveryDataLocalHome extends javax.ejb.EJBLocalHome {
	/**
	 *  @see se.anatom.ejbca.keyrecovery.KeyRecoveryDataBean
	 */
	public KeyRecoveryDataLocal create(BigInteger certificatesn, String issuerdn, String username,
		byte[] keydata) throws CreateException;


	public KeyRecoveryDataLocal findByPrimaryKey(KeyRecoveryDataPK pk)
		throws FinderException;

	public Collection findByUsername(String username) throws FinderException;

	public Collection findByUserMark(String username) throws FinderException;

}
