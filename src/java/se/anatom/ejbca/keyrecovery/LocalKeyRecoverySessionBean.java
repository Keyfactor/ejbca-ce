package se.anatom.ejbca.keyrecovery;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.util.CertTools;


/**
 * Stores key recovery data. Uses JNDI name for datasource as defined in env 'Datasource' in
 * ejb-jar.xml.
 *
 * @version $Id: LocalKeyRecoverySessionBean.java,v 1.10 2003-11-23 09:47:54 anatom Exp $
 */
public class LocalKeyRecoverySessionBean extends BaseSessionBean {

	/** Var holding JNDI name of datasource */
	private String dataSource = "";

	/** The local home interface of hard token issuer entity bean. */
	private KeyRecoveryDataLocalHome keyrecoverydatahome = null;

	/** The local interface of sign session bean */
	private ISignSessionLocal signsession = null;

	/** The local interface of certificate store session bean */
	private ICertificateStoreSessionLocal certificatestoresession = null;

	/** The remote interface of  log session bean */
	private ILogSessionLocal logsession = null;

	/**
	 * Default create for SessionBean without any creation Arguments.
	 *
	 * @throws CreateException if bean instance can't be created
	 */
	public void ejbCreate() throws CreateException {
		debug(">ejbCreate()");

		try {
			dataSource = (String) lookup("java:comp/env/DataSource", java.lang.String.class);
			debug("DataSource=" + dataSource);
			keyrecoverydatahome = (KeyRecoveryDataLocalHome) lookup("java:comp/env/ejb/KeyRecoveryData",
					KeyRecoveryDataLocalHome.class);

			debug("<ejbCreate()");
		} catch (Exception e) {
			throw new EJBException(e);
		}
	}

	/**
	 * Gets connection to Datasource used for manual SQL searches
	 *
	 * @return Connection
	 */
	private Connection getConnection() throws SQLException, NamingException {
		DataSource ds = (DataSource) getInitialContext().lookup(dataSource);

		return ds.getConnection();
	} //getConnection

	/**
	 * Gets connection to log session bean
	 *
	 * @return Connection
	 */
	private ILogSessionLocal getLogSession() {
		if (logsession == null) {
			try {
				ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",
						ILogSessionLocalHome.class);
				logsession = logsessionhome.create();
			} catch (Exception e) {
				throw new EJBException(e);
			}
		}

		return logsession;
	} //getLogSession

	/**
	 * Gets connection to certificate store session bean
	 *
	 * @return Connection
	 */
	private ICertificateStoreSessionLocal getCertificateStoreSession() {
		if (certificatestoresession == null) {
			try {
				ICertificateStoreSessionLocalHome certificatestoresessionhome = (ICertificateStoreSessionLocalHome) lookup("java:comp/env/ejb/CertificateStoreSession",
						ICertificateStoreSessionLocalHome.class);
				certificatestoresession = certificatestoresessionhome.create();
			} catch (Exception e) {
				throw new EJBException(e);
			}
		}

		return certificatestoresession;
	} //getCertificateStoreSession

	/**
	 * Gets connection to sign session bean
	 *
	 * @return ISignSessionLocal
	 */
	private ISignSessionLocal getSignSession() {
		if (signsession == null) {
			try {
				ISignSessionLocalHome signsessionhome = (ISignSessionLocalHome) lookup("java:comp/env/ejb/RSASignSession",
						ISignSessionLocalHome.class);
				signsession = signsessionhome.create();
			} catch (Exception e) {
				throw new EJBException(e);
			}
		}

		return signsession;
	} //getSignSession

	/**
	 * Adds a certificates keyrecovery data to the database.
	 *
	 * @param admin DOCUMENT ME!
	 * @param certificate DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 * @param keypair DOCUMENT ME!
	 *
	 * @return false if the certificates keyrecovery data already exists.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public boolean addKeyRecoveryData(Admin admin, X509Certificate certificate, String username,
		KeyPair keypair) {
		debug(">addKeyRecoveryData(user: " + username + ")");

		boolean returnval = false;

		try {
			// TODO, encrypt keys.
			keyrecoverydatahome.create(certificate.getSerialNumber(),
				CertTools.getIssuerDN(certificate), username, keypair);
			getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
				certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
				"Keyrecovery data for certificate with serial number : " +
				certificate.getSerialNumber().toString(16) + ", " +
				CertTools.getIssuerDN(certificate) + " added.");
			returnval = true;
		} catch (Exception e) {
				getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
					username, certificate, LogEntry.EVENT_ERROR_KEYRECOVERY,
					"Error when trying to add keyrecovery data for certificate with serial number : " +
					certificate.getSerialNumber().toString(16) + ", " +
					CertTools.getIssuerDN(certificate) + ".");
		}

		debug("<addKeyRecoveryData()");

		return returnval;
	} // addKeyRecoveryData

	/**
	 * Updates keyrecovery data
	 *
	 * @param admin DOCUMENT ME!
	 * @param certificate DOCUMENT ME!
	 * @param markedasrecoverable DOCUMENT ME!
	 * @param keypair DOCUMENT ME!
	 *
	 * @return false if certificates keyrecovery data doesn't exists
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public boolean changeKeyRecoveryData(Admin admin, X509Certificate certificate,
		boolean markedasrecoverable, KeyPair keypair) {
		debug(">changeKeyRecoveryData(certsn: " + certificate.getSerialNumber().toString() + ", " +
			CertTools.getIssuerDN(certificate) + ")");

		boolean returnval = false;

		try {
			KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(
						certificate.getSerialNumber(), CertTools.getIssuerDN(certificate)));
			krd.setMarkedAsRecoverable(markedasrecoverable);

			// TODO, encrypt keys.
			krd.setKeyPair(keypair);
			getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
				krd.getUsername(), certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
				"Keyrecovery data for certificate with serial number : " +
				certificate.getSerialNumber().toString(16) + ", " +
				CertTools.getIssuerDN(certificate) + " changed.");
			returnval = true;
		} catch (Exception e) {
				getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
					certificate, LogEntry.EVENT_ERROR_KEYRECOVERY,
					"Error when trying to update keyrecovery data for certificate with serial number : " +
					certificate.getSerialNumber().toString(16) + ", " +
					CertTools.getIssuerDN(certificate) + ".");
		}

		debug("<changeKeyRecoveryData()");

		return returnval;
	} // changeKeyRecoveryData

	/**
	 * Removes a certificates keyrecovery data from the database.
	 *
	 * @param admin DOCUMENT ME!
	 * @param certificate DOCUMENT ME!
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void removeKeyRecoveryData(Admin admin, X509Certificate certificate) {
		debug(">removeKeyRecoveryData(certificate: " + certificate.getSerialNumber().toString() +
			")");

		try {
			String username = null;
			KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(
						certificate.getSerialNumber(), CertTools.getIssuerDN(certificate)));
			username = krd.getUsername();
			krd.remove();
			getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
				certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
				"Keyrecovery data for certificate with serial number : " +
				certificate.getSerialNumber().toString(16) + ", " +
				CertTools.getIssuerDN(certificate) + " removed.");
		} catch (Exception e) {			
				getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
					certificate, LogEntry.EVENT_ERROR_KEYRECOVERY,
					"Error when removing keyrecovery data for certificate with serial number : " +
					certificate.getSerialNumber().toString(16) + ", " +
					CertTools.getIssuerDN(certificate) + ".");
		}

		debug("<removeKeyRecoveryData()");
	} // removeKeyRecoveryData

	/**
	 * Removes a all keyrecovery data saved for a user from the database.
	 *
	 * @param admin DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void removeAllKeyRecoveryData(Admin admin, String username) {
		debug(">removeAllKeyRecoveryData(user: " + username + ")");

		try {
			Collection result = keyrecoverydatahome.findByUsername(username);
			Iterator iter = result.iterator();

			while (iter.hasNext()) {				
				((KeyRecoveryDataLocal) iter.next()).remove();
			}

			getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
				null, LogEntry.EVENT_INFO_KEYRECOVERY,
				"All keyrecovery data for user: " + username + " removed.");
		} catch (Exception e) {
				getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
					null, LogEntry.EVENT_ERROR_KEYRECOVERY,
					"Error when removing all keyrecovery data for user: " + username + ".");
		}

		debug("<removeAllKeyRecoveryData()");
	} // removeAllKeyRecoveryData

	/**
	 * Returns the keyrecovery data for a user. Observe only one certificates key can be recovered
	 * for every user at the time.
	 *
	 * @param admin DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 *
	 * @return the marked keyrecovery data  or null if no recoverydata can be found.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public KeyRecoveryData keyRecovery(Admin admin, String username) {
		debug(">keyRecovery(user: " + username + ")");

		KeyRecoveryData returnval = null;
		KeyRecoveryDataLocal krd = null;
		X509Certificate certificate = null;

		try {
			Collection result = keyrecoverydatahome.findByUserMark(username);
			Iterator i = result.iterator();

			try {
				while (i.hasNext()) {
					krd = (KeyRecoveryDataLocal) i.next();

					if (returnval == null) {
						// TODO decrypt keys
						KeyPair keys = krd.getKeyPair();
						returnval = new KeyRecoveryData(krd.getCertificateSN(), krd.getIssuerDN(),
								krd.getUsername(), krd.getMarkedAsRecoverable(), keys);
						certificate = (X509Certificate) getCertificateStoreSession()
															.findCertificateByIssuerAndSerno(admin,
								krd.getIssuerDN(), krd.getCertificateSN());
					}

					krd.setMarkedAsRecoverable(false);
				}

				getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
					username, certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
					"Keydata for user: " + username + " have been sent for key recovery.");
			} catch (Exception e) {
				e.printStackTrace();
					getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
						username, null, LogEntry.EVENT_ERROR_KEYRECOVERY,
						"Error when trying to revover key data.");
			}
		} catch (Exception e) {
		}

		debug("<keyRecovery()");

		return returnval;
	} // keyRecovery

	/**
	 * Marks a users newest certificate for key recovery. Newest means certificate with latest not
	 * before date.
	 *
	 * @param admin DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 *
	 * @return true if operation went successful or false if no certificates could be found for
	 *         user, or user already marked.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public boolean markNewestAsRecoverable(Admin admin, String username) {
		debug(">markNewestAsRecoverable(user: " + username + ")");

		boolean returnval = false;
		long newesttime = 0;
		KeyRecoveryDataLocal krd = null;
		KeyRecoveryDataLocal newest = null;
		X509Certificate certificate = null;
		X509Certificate newestcertificate = null;

		if (!isUserMarked(admin, username)) {
			try {
				Collection result = keyrecoverydatahome.findByUsername(username);
				Iterator iter = result.iterator();

				while (iter.hasNext()) {
					krd = (KeyRecoveryDataLocal) iter.next();
					certificate = (X509Certificate) getCertificateStoreSession()
														.findCertificateByIssuerAndSerno(admin,
							krd.getIssuerDN(), krd.getCertificateSN());

					if (certificate != null) {
						if (certificate.getNotBefore().getTime() > newesttime) {
							newesttime = certificate.getNotBefore().getTime();
							newest = krd;
							newestcertificate = certificate;
						}
					}
				}

				if (newest != null) {
					newest.setMarkedAsRecoverable(true);
					returnval = true;
				}

				getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
					username, newestcertificate, LogEntry.EVENT_INFO_KEYRECOVERY,
					"User's newest certificate marked for recovery.");
			} catch (Exception e) {
					getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
						username, null, LogEntry.EVENT_ERROR_KEYRECOVERY,
						"Error when trying to mark users newest certificate for recovery.");
			}
		}

		debug("<markNewestAsRecoverable()");

		return returnval;
	} // markNewestAsRecoverable

	/**
	 * Marks a users certificate for key recovery.
	 *
	 * @param admin DOCUMENT ME!
	 * @param certificate DOCUMENT ME!
	 *
	 * @return true if operation went successful or false if  certificate couldn't be found.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public boolean markAsRecoverable(Admin admin, X509Certificate certificate) {
		debug(">markAsRecoverable(certificatesn: " + certificate.getSerialNumber() + ")");

		boolean returnval = false;

		try {
			String username = null;
			KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(
						certificate.getSerialNumber(), CertTools.getIssuerDN(certificate)));
			username = krd.getUsername();
			krd.setMarkedAsRecoverable(true);
			getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
				certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
				"User's certificate marked for recovery.");
			returnval = true;
		} catch (Exception e) {			
				getLogSession().log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
					certificate, LogEntry.EVENT_ERROR_KEYRECOVERY,
					"Error when trying to mark certificate for recovery.");
		}

		debug("<markAsRecoverable()");

		return returnval;
	} // markAsRecoverable

	/**
	 * Resets keyrecovery mark for a user,
	 *
	 * @param admin DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public void unmarkUser(Admin admin, String username) {
		debug(">unmarkUser(user: " + username + ")");

		KeyRecoveryDataLocal krd = null;

		try {
			Collection result = keyrecoverydatahome.findByUserMark(username);
			Iterator i = result.iterator();

			while (i.hasNext()) {
				krd = (KeyRecoveryDataLocal) i.next();
				krd.setMarkedAsRecoverable(false);
			}
		} catch (Exception e) {
			throw new EJBException(e);
		}

		debug("<unmarkUser()");
	} // unmarkUser

	/**
	 * Returns true if a user is marked for key recovery.
	 *
	 * @param admin DOCUMENT ME!
	 * @param username DOCUMENT ME!
	 *
	 * @return true if user is already marked for key recovery.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public boolean isUserMarked(Admin admin, String username) {
		debug(">isUserMarked(user: " + username + ")");

		boolean returnval = false;
		KeyRecoveryDataLocal krd = null;

		try {
			Collection result = keyrecoverydatahome.findByUserMark(username);
			Iterator i = result.iterator();

			while (i.hasNext()) {
				krd = (KeyRecoveryDataLocal) i.next();

				if (krd.getMarkedAsRecoverable()) {
					returnval = true;

					break;
				}
			}
		} catch (Exception e) {
			throw new EJBException(e);
		}
		debug("<isUserMarked(" + returnval + ")");
		return returnval;
	} // isUserMarked

	/**
	 * Returns true if specified certificates keys exists in database.
	 *
	 * @param admin DOCUMENT ME!
	 * @param certificate DOCUMENT ME!
	 *
	 * @return true if user is already marked for key recovery.
	 *
	 * @throws EJBException if a communication or other error occurs.
	 */
	public boolean existsKeys(Admin admin, X509Certificate certificate) {
		debug(">existsKeys()");

		boolean returnval = false;

		try {
			KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(
						certificate.getSerialNumber(), CertTools.getIssuerDN(certificate)));
			returnval = true;
		} catch (FinderException e) {
		}

		debug("<existsKeys(" + returnval + ")");

		return returnval;
	} // existsKeys
    
}// LocalKeyRecoverySessionBean


