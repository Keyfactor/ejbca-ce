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

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceRequest;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceResponse;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.util.CertTools;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;


/**
 * Stores key recovery data. Uses JNDI name for datasource as defined in env 'Datasource' in
 * ejb-jar.xml.
 *
 * @version $Id: LocalKeyRecoverySessionBean.java,v 1.27 2005-03-07 16:50:28 anatom Exp $
 *
 * @ejb.bean
 *   display-name="Stores key recovery data"
 *   name="KeyRecoverySession"
 *   jndi-name="KeyRecoverySession"
 *   local-jndi-name="KeyRecoverySessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @ejb.permission role-name="InternalUser"
 *
 * @ejb.env-entry
 *   description="JDBC datasource to be used"
 *   name="DataSource"
 *   type="java.lang.String"
 *   value="java:/@datasource.jndi.name@"
 *
 * @ejb.ejb-external-ref
 *   description="The key recovery data entity bean"
 *   view-type="local"
 *   ejb-name="KeyRecoveryDataLocal"
 *   type="Entity"
 *   home="se.anatom.ejbca.keyrecovery.KeyRecoveryDataLocalHome"
 *   business="se.anatom.ejbca.keyrecovery.KeyRecoveryDataLocal"
 *   link="KeyRecoveryData"
 *
 * @ejb.ejb-external-ref
 *   description="The Sign Session Bean"
 *   view-type="local"
 *   ejb-name="RSASignSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ca.sign.ISignSessionLocalHome"
 *   business="se.anatom.ejbca.ca.sign.ISignSessionLocal"
 *   link="RSASignSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Certificate Store session bean"
 *   view-type="local"
 *   ejb-name="CertificateStoreSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome"
 *   business="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref
 *   description="The log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="se.anatom.ejbca.log.ILogSessionLocalHome"
 *   business="se.anatom.ejbca.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocalHome"
 *   remote-class="se.anatom.ejbca.keyrecovery.IKeyRecoverySessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="se.anatom.ejbca.keyrecovery.IKeyRecoverySessionLocal"
 *   remote-class="se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote"
 *
 * @jonas.bean
 *   ejb-name="KeyRecoverySession"
 *
 */
public class LocalKeyRecoverySessionBean extends BaseSessionBean {

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
            keyrecoverydatahome = (KeyRecoveryDataLocalHome) getLocator().getLocalHome(KeyRecoveryDataLocalHome.COMP_NAME);

            ILogSessionLocalHome logHome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
            logsession = logHome.create();

            ICertificateStoreSessionLocalHome storeHome = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
            certificatestoresession = storeHome.create();

            ISignSessionLocalHome signsessionhome = (ISignSessionLocalHome) getLocator().getLocalHome(ISignSessionLocalHome.COMP_NAME);
            signsession = signsessionhome.create();

            debug("<ejbCreate()");
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Adds a certificates keyrecovery data to the database.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keypair.
     * @param username of the administrator
     * @param keypair the actual keypair to save.
     *
     * @return false if the certificates keyrecovery data already exists.
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @ejb.interface-method view-type="both"
     */
    public boolean addKeyRecoveryData(Admin admin, X509Certificate certificate, String username,
                                      KeyPair keypair) {
        debug(">addKeyRecoveryData(user: " + username + ")");

        boolean returnval = false;

        try {
            int caid = CertTools.getIssuerDN(certificate).hashCode();

            KeyRecoveryCAServiceResponse response = (KeyRecoveryCAServiceResponse) signsession.extendedService(admin, caid,
                    new KeyRecoveryCAServiceRequest(KeyRecoveryCAServiceRequest.COMMAND_ENCRYPTKEYS, keypair));

            keyrecoverydatahome.create(certificate.getSerialNumber(),
                    CertTools.getIssuerDN(certificate), username, response.getKeyData());
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
                    certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
                    "Keyrecovery data for certificate with serial number : " +
                    certificate.getSerialNumber().toString(16) + ", " +
                    CertTools.getIssuerDN(certificate) + " added.");
            returnval = true;
        } catch (Exception e) {
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
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
     *
     * @ejb.interface-method view-type="both"
     */
    public boolean changeKeyRecoveryData(Admin admin, X509Certificate certificate,
                                         boolean markedasrecoverable, KeyPair keypair) {
        debug(">changeKeyRecoveryData(certsn: " + certificate.getSerialNumber().toString() + ", " +
                CertTools.getIssuerDN(certificate) + ")");

        boolean returnval = false;
        final String hexSerial = certificate.getSerialNumber().toString(16);
        final String dn = CertTools.getIssuerDN(certificate);
        try {
            KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(hexSerial, dn));
            krd.setMarkedAsRecoverable(markedasrecoverable);

            int caid = dn.hashCode();

            KeyRecoveryCAServiceResponse response = (KeyRecoveryCAServiceResponse) signsession.extendedService(admin, caid,
                    new KeyRecoveryCAServiceRequest(KeyRecoveryCAServiceRequest.COMMAND_ENCRYPTKEYS, keypair));


            krd.setKeyDataFromByteArray(response.getKeyData());
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
                    krd.getUsername(), certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
                    "Keyrecovery data for certificate with serial number : " +
                    hexSerial + ", " +
                    dn + " changed.");
            returnval = true;
        } catch (Exception e) {
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
                    certificate, LogEntry.EVENT_ERROR_KEYRECOVERY,
                    "Error when trying to update keyrecovery data for certificate with serial number : " +
                    hexSerial + ", " +
                    dn + ".");
        }

        debug("<changeKeyRecoveryData()");

        return returnval;
    } // changeKeyRecoveryData

    /**
     * Removes a certificates keyrecovery data from the database.
     *
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keys about to be removed.
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeKeyRecoveryData(Admin admin, X509Certificate certificate) {
        debug(">removeKeyRecoveryData(certificate: " + certificate.getSerialNumber().toString() +
                ")");
        final String hexSerial = certificate.getSerialNumber().toString(16);
        final String dn = CertTools.getIssuerDN(certificate);
        try {
            String username = null;
            KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(hexSerial, dn));
            username = krd.getUsername();
            krd.remove();
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
                    certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
                    "Keyrecovery data for certificate with serial number : " +
                    hexSerial + ", " +
                    dn + " removed.");
        } catch (Exception e) {
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
                    certificate, LogEntry.EVENT_ERROR_KEYRECOVERY,
                    "Error when removing keyrecovery data for certificate with serial number : " +
                    hexSerial + ", " +
                    dn + ".");
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
     *
     * @ejb.interface-method view-type="both"
     */
    public void removeAllKeyRecoveryData(Admin admin, String username) {
        debug(">removeAllKeyRecoveryData(user: " + username + ")");

        try {
            Collection result = keyrecoverydatahome.findByUsername(username);
            Iterator iter = result.iterator();

            while (iter.hasNext()) {
                ((KeyRecoveryDataLocal) iter.next()).remove();
            }

            logsession.log(admin, admin.getCaId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
                    null, LogEntry.EVENT_INFO_KEYRECOVERY,
                    "All keyrecovery data for user: " + username + " removed.");
        } catch (Exception e) {
            logsession.log(admin, admin.getCaId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
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
     *
     * @ejb.interface-method view-type="both"
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
                        int caid = krd.getIssuerDN().hashCode();

                        KeyRecoveryCAServiceResponse response = (KeyRecoveryCAServiceResponse) signsession.extendedService(admin, caid,
                                new KeyRecoveryCAServiceRequest(KeyRecoveryCAServiceRequest.COMMAND_DECRYPTKEYS, krd.getKeyDataAsByteArray()));
                        KeyPair keys = response.getKeyPair();
                        returnval = new KeyRecoveryData(krd.getCertificateSN(), krd.getIssuerDN(),
                                krd.getUsername(), krd.getMarkedAsRecoverable(), keys);
                        certificate = (X509Certificate) certificatestoresession
                                .findCertificateByIssuerAndSerno(admin,
                                        krd.getIssuerDN(), krd.getCertificateSN());
                    }

                    krd.setMarkedAsRecoverable(false);
                }

                logsession.log(admin, admin.getCaId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
                        username, certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
                        "Keydata for user: " + username + " have been sent for key recovery.");
            } catch (Exception e) {
                log.error("-keyRecovery: ", e);
                logsession.log(admin, admin.getCaId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
                        username, null, LogEntry.EVENT_ERROR_KEYRECOVERY,
                        "Error when trying to revover key data.");
            }
        } catch (FinderException e) {
        }

        debug("<keyRecovery()");

        return returnval;
    } // keyRecovery

    /**
     * Marks a users newest certificate for key recovery. Newest means certificate with latest not
     * before date.
     *
     * @param admin the administrator calling the function
     * @param username or the user.
     *
     * @return true if operation went successful or false if no certificates could be found for
     *         user, or user already marked.
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @ejb.interface-method view-type="both"
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
                    certificate = (X509Certificate) certificatestoresession
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

                logsession.log(admin, admin.getCaId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
                        username, newestcertificate, LogEntry.EVENT_INFO_KEYRECOVERY,
                        "User's newest certificate marked for recovery.");
            } catch (Exception e) {
                logsession.log(admin, admin.getCaId(), LogEntry.MODULE_KEYRECOVERY, new java.util.Date(),
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
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keys about to be removed.
     *
     * @return true if operation went successful or false if  certificate couldn't be found.
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @ejb.interface-method view-type="both"
     */
    public boolean markAsRecoverable(Admin admin, X509Certificate certificate) {
        debug(">markAsRecoverable(certificatesn: " + certificate.getSerialNumber() + ")");

        boolean returnval = false;
        final String hexSerial = certificate.getSerialNumber().toString(16);
        final String dn = CertTools.getIssuerDN(certificate);
        try {
            String username = null;
            KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(hexSerial, dn));
            username = krd.getUsername();
            krd.setMarkedAsRecoverable(true);
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), username,
                    certificate, LogEntry.EVENT_INFO_KEYRECOVERY,
                    "User's certificate marked for recovery.");
            returnval = true;
        } catch (Exception e) {
            logsession.log(admin, certificate, LogEntry.MODULE_KEYRECOVERY, new java.util.Date(), null,
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
     *
     * @ejb.interface-method view-type="both"
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
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
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
     * @param admin the administrator calling the function
     * @param certificate the certificate used with the keys about to be removed.
     *
     * @return true if user is already marked for key recovery.
     *
     * @throws EJBException if a communication or other error occurs.
     *
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Supports"
     */
    public boolean existsKeys(Admin admin, X509Certificate certificate) {
        debug(">existsKeys()");

        boolean returnval = false;
        final String hexSerial = certificate.getSerialNumber().toString(16);
        final String dn = CertTools.getIssuerDN(certificate);
        try {
            KeyRecoveryDataLocal krd = keyrecoverydatahome.findByPrimaryKey(new KeyRecoveryDataPK(hexSerial, dn));
            debug("Found key for user: "+krd.getUsername());
            returnval = true;
        } catch (FinderException e) {
        }
        debug("<existsKeys(" + returnval + ")");
        return returnval;
    } // existsKeys

}// LocalKeyRecoverySessionBean


