package se.anatom.ejbca.keyrecovery;

/**
 * Primary key for key recovery data
 *
 * @version $Id: KeyRecoveryDataPK.java,v 1.3 2003-09-03 11:27:06 herrvendil Exp $
 */
public final class KeyRecoveryDataPK implements java.io.Serializable {
	public int pK;

	/**
	 * Creates a new KeyRecoveryDataPK object.
	 *
	 * @param certificatesn certificate serial number
	 * @param issuerdn dn of issuer of certificate
	 */
	public KeyRecoveryDataPK(java.math.BigInteger certificatesn, java.lang.String issuerdn) {
		this.pK = (((certificatesn == null) ? 0 : certificatesn.hashCode()) ^
			((issuerdn == null) ? 0 : issuerdn.hashCode()));
	}

	/**
	 * Creates a new KeyRecoveryDataPK object.
	 */
	public KeyRecoveryDataPK() {
	}

	/**
	 * @see java.lang.Object#equals(java.lang.Object)
	 */
	public boolean equals(java.lang.Object otherOb) {
		if (!(otherOb instanceof se.anatom.ejbca.keyrecovery.KeyRecoveryDataPK)) {
			return false;
		}

		se.anatom.ejbca.keyrecovery.KeyRecoveryDataPK other = (se.anatom.ejbca.keyrecovery.KeyRecoveryDataPK) otherOb;

		return (pK == other.pK);
	}

	/**
	 * @see java.lang.Object#hashCode()
	 */
	public int hashCode() {
		return this.pK;
	}

}
