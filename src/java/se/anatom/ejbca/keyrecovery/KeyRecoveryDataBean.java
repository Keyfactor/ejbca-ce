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

import javax.ejb.CreateException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.BaseEntityBean;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.StringTools;


/**
 * Entity bean should not be used directly, use though Session beans. Entity Bean representing a
 * certificates key recovery data in the ra. Information stored:
 * <pre>
 *  pk (Primary key, hashcodes of certificatesn and issuerdn)
 *  certificatesn
 *  issuerdn
 *  username
 *  markedasrecoverable
 *  keypair
 * </pre>
 *
 * @version $Id: KeyRecoveryDataBean.java,v 1.12 2004-04-16 07:38:59 anatom Exp $
 */
public abstract class KeyRecoveryDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(KeyRecoveryDataBean.class);

	public abstract String getCertSN();

	public abstract void setCertSN(String certificatesn);

	public abstract String getIssuerDN();

	public abstract void setIssuerDN(String issuerdn);

	public abstract String getUsername();

	/**
	 * username must be called 'striped' using StringTools.strip()
	 *
	 * @see se.anatom.ejbca.util.StringTools
	 */
	public abstract void setUsername(String username);

	public abstract boolean getMarkedAsRecoverable();

	public abstract void setMarkedAsRecoverable(boolean markedasrecoverable);


	public abstract String getKeyData();

	public abstract void setKeyData(String keydata);

	public BigInteger getCertificateSN() {
		return new BigInteger(getCertSN(), 16);
	}

	public void setCertificateSN(BigInteger certificatesn) {
		setCertSN(certificatesn.toString(16));
	}

	public byte[] getKeyDataAsByteArray(){
		return Base64.decode(this.getKeyData().getBytes()); 
	}
	
	public void setKeyDataFromByteArray(byte[] keydata){
	  	setKeyData(new String(Base64.encode(keydata)));
	}
	


	//
	// Fields required by Container
	//

	/**
	 * Entity Bean holding keyrecovery data of users certificate.
	 *
	 * @param certificatesn of certificate the keys are belonging to.
	 * @param issuerdn issuerdn of certificate the keys are belonging to.
	 * @param username of the owner of the keys.
	 * @param keydata the actual keydata.
	 *
	 * @return Primary Key
	 */
	
	public KeyRecoveryDataPK ejbCreate(BigInteger certificatesn, String issuerdn, String username,
		byte[] keydata) throws CreateException {
		KeyRecoveryDataPK pk = new KeyRecoveryDataPK(certificatesn, issuerdn);
		setCertificateSN(certificatesn);
		setIssuerDN(issuerdn);
		setUsername(StringTools.strip(username));
		setMarkedAsRecoverable(false);
		setKeyDataFromByteArray(keydata);

		log.debug("Created Key Recoverydata for user " + username);
		return pk;
	}

	public void ejbPostCreate(BigInteger certificatesn, String issuerdn, String username,
		byte[] keydata) {
		// Do nothing. Required.
	}

}
