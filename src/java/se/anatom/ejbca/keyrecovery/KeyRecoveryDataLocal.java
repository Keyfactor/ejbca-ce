package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;



/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocal.java,v 1.6 2004-01-25 09:37:28 herrvendil Exp $
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
