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



/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocal.java,v 1.7 2004-04-16 07:38:59 anatom Exp $
 */
public interface KeyRecoveryDataLocal extends javax.ejb.EJBLocalObject {
	// Public methods
	public BigInteger getCertificateSN();

	public void setCertificateSN(BigInteger certificatesn);

	public String getIssuerDN();

	public void setIssuerDN(String issuerdn);

	public String getUsername();

	public void setUsername(String username);

	public boolean getMarkedAsRecoverable();

	public void setMarkedAsRecoverable(boolean markedasrecoverable);

	public byte[] getKeyDataAsByteArray();

	public void setKeyDataFromByteArray(byte[] keydata);

}
