package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;
import java.security.KeyPair;

import javax.ejb.CreateException;

import org.apache.log4j.*;

import se.anatom.ejbca.BaseEntityBean;
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
 * @version $Id: KeyRecoveryDataBean.java,v 1.9 2003-11-17 10:32:34 anatom Exp $
 */
public abstract class KeyRecoveryDataBean extends BaseEntityBean {
    private static Logger log = Logger.getLogger(KeyRecoveryDataBean.class);

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public abstract int getPK();

	/**
	 * DOCUMENT ME!
	 *
	 * @param pK DOCUMENT ME!
	 */
	public abstract void setPK(int pK);

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public abstract String getCertSN();

	/**
	 * DOCUMENT ME!
	 *
	 * @param certificatesn DOCUMENT ME!
	 */
	public abstract void setCertSN(String certificatesn);

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public abstract String getIssuerDN();

	/**
	 * DOCUMENT ME!
	 *
	 * @param issuerdn DOCUMENT ME!
	 */
	public abstract void setIssuerDN(String issuerdn);

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public abstract String getUsername();

	/**
	 * username must be called 'striped' using StringTools.strip()
	 *
	 * @see se.anatom.ejbca.util.StringTools
	 */
	public abstract void setUsername(String username);

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public abstract boolean getMarkedAsRecoverable();

	/**
	 * DOCUMENT ME!
	 *
	 * @param markedasrecoverable DOCUMENT ME!
	 */
	public abstract void setMarkedAsRecoverable(boolean markedasrecoverable);

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public abstract KeyPair getKeyPair();

	/**
	 * DOCUMENT ME!
	 *
	 * @param keypair DOCUMENT ME!
	 */
	public abstract void setKeyPair(KeyPair keypair);

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public BigInteger getCertificateSN() {
		return new BigInteger(getCertSN(), 16);
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @param certificatesn DOCUMENT ME!
	 */
	public void setCertificateSN(BigInteger certificatesn) {
		setCertSN(certificatesn.toString(16));
	}

	//
	// Fields required by Container
	//

	/**
	 * Entity Bean holding keyrecovery data of users certificate.
	 *
	 * @param certificatesn DOCUMENT ME!
	 * @param issuerdn DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 * @param keypair DOCUMENT ME!
	 *
	 * @return Primary Key
	 */
	public KeyRecoveryDataPK ejbCreate(BigInteger certificatesn, String issuerdn, String username,
		KeyPair keypair) throws CreateException {
		KeyRecoveryDataPK pk = new KeyRecoveryDataPK(certificatesn, issuerdn);
		setPK(pk.pK);
		setCertificateSN(certificatesn);
		setIssuerDN(issuerdn);
		setUsername(StringTools.strip(username));
		setMarkedAsRecoverable(false);
		setKeyPair(keypair);

		log.debug("Created Key Recoverydata for user " + username);
		return pk;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @param certificatesn DOCUMENT ME!
	 * @param issuerdn DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 * @param keypair DOCUMENT ME!
	 */
	public void ejbPostCreate(BigInteger certificatesn, String issuerdn, String username,
		KeyPair keypair) {
		// Do nothing. Required.
	}

}
