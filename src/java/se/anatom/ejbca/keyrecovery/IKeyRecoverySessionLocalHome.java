package se.anatom.ejbca.keyrecovery;

import javax.ejb.CreateException;


/**
 * DOCUMENT ME!
 *
 * @version $Id: IKeyRecoverySessionLocalHome.java,v 1.3 2003-09-03 11:27:06 herrvendil Exp $
 */
public interface IKeyRecoverySessionLocalHome extends javax.ejb.EJBLocalHome {
	/**
	 * Default create method. Maps to ejbCreate in implementation.
	 *
	 * @return IHardTokenSessionLocal interface
	 *
	 * @throws CreateException
	 * @throws RemoteException
	 */
	IKeyRecoverySessionLocal create() throws CreateException;
}
