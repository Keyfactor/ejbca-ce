package se.anatom.ejbca.keyrecovery;

import java.math.BigInteger;

import java.util.Collection;
import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see KeyRecoveryDataBean
 *
 * @version $Id: KeyRecoveryDataLocalHome.java,v 1.5 2004-01-25 09:37:28 herrvendil Exp $
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
