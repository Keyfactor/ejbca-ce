package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;
import java.security.KeyPair;

import se.anatom.ejbca.util.StringTools;


/**
 * This is a value class containing the data relating to key saved for recovery for a user, sent
 * between server and clients.
 *
 * @author TomSelleck
 * @version $Id: KeyRecoveryData.java,v 1.5 2003-09-03 11:27:06 herrvendil Exp $
 */
public class KeyRecoveryData implements java.io.Serializable {
	// Public Constructors
	public KeyRecoveryData(BigInteger certificatesn, String issuerdn, String username,
		boolean markedasrecoverable, KeyPair keypair) {
		this.certificatesn = certificatesn;
		this.issuerdn = issuerdn;
		this.username = StringTools.strip(username);
		this.markedasrecoverable = markedasrecoverable;
		this.keypair = keypair;
	}

	/**
	 * Creates a new KeyRecoveryData object.
	 */
	public KeyRecoveryData() {
	}

	// Public Methods
	public BigInteger getCertificateSN() {
		return this.certificatesn;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @param certificatesn DOCUMENT ME!
	 */
	public void setCertificateSN(BigInteger certificatesn) {
		this.certificatesn = certificatesn;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public String getIssuerDN() {
		return this.issuerdn;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @param issuerdn DOCUMENT ME!
	 */
	public void setIssuerDN(String issuerdn) {
		this.issuerdn = issuerdn;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public String getUsername() {
		return this.username;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @param username DOCUMENT ME!
	 */
	public void setUsername(String username) {
		this.username = StringTools.strip(username);
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public boolean getMarkedAsRecoverable() {
		return this.markedasrecoverable;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @param markedasrecoverable DOCUMENT ME!
	 */
	public void setMarkedAsRecoverable(boolean markedasrecoverable) {
		this.markedasrecoverable = markedasrecoverable;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @return DOCUMENT ME!
	 */
	public KeyPair getKeyPair() {
		return this.keypair;
	}

	/**
	 * DOCUMENT ME!
	 *
	 * @param keypair DOCUMENT ME!
	 */
	public void setKeyPair(KeyPair keypair) {
		this.keypair = keypair;
	}

	// Private fields
	private BigInteger certificatesn;
	private String issuerdn;
	private String username;
	private boolean markedasrecoverable;
	private KeyPair keypair;

}
