package se.anatom.ejbca.ca.store;

import java.math.BigInteger;
import java.rmi.*;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.Random;
import java.util.TreeMap;

import javax.ejb.*;
import javax.naming.*;
import javax.sql.DataSource;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.store.certificateprofiles.*;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.StringTools;


/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans. Uses
 * JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalCertificateStoreSessionBean.java,v 1.46 2003-08-24 13:40:22 anatom Exp $
 */
public class LocalCertificateStoreSessionBean extends BaseSessionBean {
    /** Var holding JNDI name of datasource */
    private String dataSource = "";

    /** The home interface of Certificate entity bean */
    private CertificateDataLocalHome certHome = null;

    /** The home interface of Certificate Type entity bean */
    private CertificateProfileDataLocalHome certprofilehome = null;

    /** The home interface of CRL entity bean */
    private CRLDataLocalHome crlHome = null;

    /** The remote interface of the log session bean */
    private ILogSessionRemote logsession;

    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String) lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        crlHome = (CRLDataLocalHome) lookup("java:comp/env/ejb/CRLDataLocal");
        certHome = (CertificateDataLocalHome) lookup("java:comp/env/ejb/CertificateDataLocal");
        certprofilehome = (CertificateProfileDataLocalHome) lookup(
                "java:comp/env/ejb/CertificateProfileDataLocal");

        try {
            ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",
                    ILogSessionHome.class);
            logsession = logsessionhome.create();
        } catch (Exception e) {
            throw new EJBException(e);
        }

        // Check if fixed certificates exists in database.
        try {
            certprofilehome.findByPrimaryKey(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER));
        } catch (FinderException e) {
            certprofilehome.create(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER),
                EndUserCertificateProfile.CERTIFICATEPROFILENAME,
                (CertificateProfile) new EndUserCertificateProfile());
        }

        try {
            certprofilehome.findByPrimaryKey(new Integer(SecConst.CERTPROFILE_FIXED_CA));
        } catch (FinderException e) {
            certprofilehome.create(new Integer(SecConst.CERTPROFILE_FIXED_CA),
                CACertificateProfile.CERTIFICATEPROFILENAME,
                (CertificateProfile) new CACertificateProfile());
        }

        try {
            certprofilehome.findByPrimaryKey(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA));
        } catch (FinderException e) {
            certprofilehome.create(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA),
                RootCACertificateProfile.CERTIFICATEPROFILENAME,
                (CertificateProfile) new RootCACertificateProfile());
        }

        debug("<ejbCreate()");
    }

    /**
     * Gets connection to Datasource used for manual SQL searches
     *
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource) getInitialContext().lookup(dataSource);

        return ds.getConnection();
    }

    //getConnection

    /**
     * Implements ICertificateStoreSession::storeCertificate. Implements a mechanism that uses
     * Certificate Entity Bean.
     *
     * @param admin DOCUMENT ME!
     * @param incert DOCUMENT ME!
     * @param username DOCUMENT ME!
     * @param cafp DOCUMENT ME!
     * @param status DOCUMENT ME!
     * @param type DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean storeCertificate(Admin admin, Certificate incert, String username, String cafp,
        int status, int type) {
        debug(">storeCertificate(" + cafp + ", " + status + ", " + type + ")");

        try {
            // Strip dangerous chars
            username = StringTools.strip(username);

            X509Certificate cert = (X509Certificate) incert;
            CertificateDataPK pk = new CertificateDataPK();
            pk.fingerprint = CertTools.getFingerprintAsString(cert);
            logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username,
                (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE, "");

            CertificateDataLocal data1 = null;
            data1 = certHome.create(cert);
            data1.setUsername(username);
            data1.setCAFingerprint(cafp);
            data1.setStatus(status);
            data1.setType(type);
        } catch (Exception e) {
            error("Error storing certificate: ", e);

            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), username,
                    (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE, "");
            } catch (RemoteException re) {
            }

            throw new EJBException(e);
        }

        debug("<storeCertificate()");

        return true;
    }

    // storeCertificate

    /**
     * Implements ICertificateStoreSession::storeCRL. Implements a mechanism that uses CRL Entity
     * Bean.
     *
     * @param admin DOCUMENT ME!
     * @param incrl DOCUMENT ME!
     * @param cafp DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) {
        debug(">storeCRL(" + cafp + ", " + number + ")");

        try {
            X509CRL crl = CertTools.getCRLfromByteArray(incrl);
            CRLDataLocal data1 = crlHome.create(crl, number);
            data1.setCAFingerprint(cafp);
            logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                LogEntry.EVENT_INFO_STORECRL,
                "Number : " + number + " Fingerprint : " + CertTools.getFingerprintAsString(crl) +
                ".");
        } catch (Exception e) {
            error("Error storing CRL: ", e);

            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_STORECRL, "Number : " + number + ".");
            } catch (RemoteException re) {
            }

            throw new EJBException(e);
        }

        debug("<storeCRL()");

        return true;
    }
     // storeCRL

    /**
     * Implements ICertificateStoreSession::listAlLCertificates. Uses select directly from
     * datasource.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection listAllCertificates(Admin admin) {
        debug(">listAllCertificates()");

        Connection con = null;
        PreparedStatement ps = null;
        ;

        ResultSet result = null;

        try {
            con = getConnection();
            ps = con.prepareStatement(
                    "select fingerprint from CertificateData ORDER BY expireDate DESC");
            result = ps.executeQuery();

            ArrayList vect = new ArrayList();

            while (result.next()) {
                vect.add(result.getString(1));
            }

            debug("<listAllCertificates()");

            return vect;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (result != null) {
                    result.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Error cleaning up: ", se);
            }
        }
    }

    // listAllCertificates

    /**
     * Implements ICertificateStoreSession::listRevokedCertificates. Uses select directly from
     * datasource.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection listRevokedCertificates(Admin admin) {
        debug(">listRevokedCertificates()");

        Connection con = null;
        PreparedStatement ps = null;
        ;

        ResultSet result = null;

        try {
            // TODO:
            // This should only list a few thousend certificates at a time, in case there
            // are really many revoked certificates after some time...
            con = getConnection();
            ps = con.prepareStatement(
                    "select fingerprint from CertificateData where status=? ORDER BY expireDate DESC");
            ps.setInt(1, CertificateData.CERT_REVOKED);
            result = ps.executeQuery();

            ArrayList vect = new ArrayList();

            while (result.next()) {
                vect.add(result.getString(1));
            }

            debug("<listRevokedCertificates()");

            return vect;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (result != null) {
                    result.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Error cleaning up: ", se);
            }
        }
    }

    // listRevokedCertificates

    /**
     * Implements ICertificateStoreSession::findCertificatesBySubject.
     *
     * @param admin DOCUMENT ME!
     * @param subjectDN DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findCertificatesBySubject(Admin admin, String subjectDN) {
        debug(">findCertificatesBySubject(), dn='" + subjectDN + "'");

        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(subjectDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        try {
            Collection coll = certHome.findBySubjectDN(dn);
            Collection ret = new ArrayList();

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret.add(((CertificateDataLocal) iter.next()).getCertificate());
                }
            }

            debug("<findCertificatesBySubject(), dn='" + subjectDN + "'");

            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    }

    //findCertificatesBySubject

    /**
     * Finds certificate which expire within a specified time. Implements
     * ICertificateStoreSession::findCertificatesByExpireTime.
     *
     * @param admin DOCUMENT ME!
     * @param expireTime DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findCertificatesByExpireTime(Admin admin, Date expireTime) {
        debug(">findCertificatesByExpireTime(), time=" + expireTime);

        // First make expiretime in well know format
        debug("Looking for certs that expire before: " + expireTime);

        try {
            Collection coll = certHome.findByExpireDate(expireTime.getTime());
            Collection ret = new ArrayList();

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret.add(((CertificateDataLocal) iter.next()).getCertificate());
                }
            }

            debug("<findCertificatesByExpireTime(), time=" + expireTime);

            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    }

    //findCertificatesByExpireTime

    /**
     * Finds usernames of users having certificate(s) expiring within a specified time and that has
     * status active.
     *
     * @param admin DOCUMENT ME!
     * @param expiretime DOCUMENT ME!
     *
     * @return a collection of usernames (String) Implements
     *         ICertificateStoreSession::findCertificatesByExpireTimeWithLimit.
     */
    public Collection findCertificatesByExpireTimeWithLimit(Admin admin, Date expiretime) {
        debug(">findCertificatesByExpireTimeWithLimit");

        Connection con = null;
        PreparedStatement ps = null;
        ;

        ResultSet result = null;
        ArrayList returnval = new ArrayList();
        long currentdate = new Date().getTime();

        try {
            con = getConnection();
            ps = con.prepareStatement(
                    "SELECT DISTINCT username FROM CertificateData WHERE expireDate >= " +
                    currentdate + " AND expireDate < " + expiretime.getTime() + " AND status = " +
                    CertificateData.CERT_ACTIVE);
            result = ps.executeQuery();

            while (result.next() && (returnval.size() <= (SecConst.MAXIMUM_QUERY_ROWCOUNT + 1))) {
                if ((result.getString(1) != null) && !result.getString(1).equals("")) {
                    returnval.add(result.getString(1));
                }
            }

            debug("<findCertificatesByExpireTimeWithLimit()");

            return returnval;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (result != null) {
                    result.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Error cleaning up: ", se);
            }
        }
    }

    //findCertificatesByExpireTimeWithLimit

    /**
     * Implements ICertificateStoreSession::findCertificateByIssuerAndSerno.
     *
     * @param admin DOCUMENT ME!
     * @param issuerDN DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN,
        BigInteger serno) {
        debug(">findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno);

        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            Certificate ret = null;

            if (coll != null) {
                if (coll.size() > 1) {
                    logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_DATABASE,
                        "Error in database, more than one certificate has the same Issuer : " +
                        issuerDN + " and serialnumber " + serno.toString(16) + ".");
                }

                Iterator iter = coll.iterator();

                if (iter.hasNext()) {
                    ret = ((CertificateDataLocal) iter.next()).getCertificate();
                }
            }

            debug("<findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno);

            return ret;
        } catch (Exception fe) {
            throw new EJBException(fe);
        }
    }

    //findCertificateByIssuerAndSerno

    /**
     * Implements ICertificateStoreSession::findCertificatesBySerno.
     *
     * @param admin DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findCertificatesBySerno(Admin admin, BigInteger serno) {
        debug(">findCertificateBySerno(),  serno=" + serno);

        try {
            Collection coll = certHome.findBySerialNumber(serno.toString());
            ArrayList ret = new ArrayList();

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret.add(((CertificateDataLocal) iter.next()).getCertificate());
                }
            }

            debug("<findCertificateBySerno(), serno=" + serno);

            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    }

    // findCertificateBySerno

    /**
     * Implements ICertificateStoreSession::findUsernameByCertSerno.
     *
     * @param admin DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String findUsernameByCertSerno(Admin admin, BigInteger serno) {
        debug(">findUsernameByCertSerno(),  serno=" + serno);

        try {
            Collection coll = certHome.findBySerialNumber(serno.toString());
            String ret = null;

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret = ((CertificateDataLocal) iter.next()).getUsername();
                }
            }

            debug("<findUsernameByCertSerno(), serno=" + serno);

            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    }

    // findUsernameByCertSerno

    /**
     * Implements ICertificateStoreSession::findCertificatesByUsername.
     *
     * @param admin DOCUMENT ME!
     * @param username DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findCertificatesByUsername(Admin admin, String username) {
        debug(">findCertificateBySerno(),  username=" + username);

        try {
            // Strip dangerous chars
            username = StringTools.strip(username);

            Collection coll = certHome.findByUsername(username);
            ArrayList ret = new ArrayList();

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret.add(((CertificateDataLocal) iter.next()).getCertificate());
                }
            }

            debug("<findCertificateBySerno(), username=" + username);

            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    }

    // findCertificateByUsername

    /**
     * Implements ICertificateStoreSession::findCertificateByFingerprint.
     *
     * @param admin DOCUMENT ME!
     * @param fingerprint DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint) {
        debug(">findCertificateByFingerprint()");

        try {
            CertificateDataLocal res = certHome.findByPrimaryKey(new CertificateDataPK(fingerprint));
            Certificate ret = res.getCertificate();
            debug("<findCertificateByFingerprint()");

            return ret;
        } catch (Exception fe) {
            throw new EJBException(fe);
        }
    }

    // findCertificateByFingerprint

    /**
     * Set the status of certificates of given username to revoked.
     *
     * @param admin DOCUMENT ME!
     * @param username the username of user to revoke certificates.
     * @param reason reason the user is revoked from CRLData
     *
     * @see CRLData
     */
    public void setRevokeStatus(Admin admin, String username, int reason) {
        X509Certificate certificate = null;

        // Strip dangerous chars
        username = StringTools.strip(username);

        try {
            Collection certs = findCertificatesByUsername(admin, username);

            // Revoke all certs
            if (!certs.isEmpty()) {
                Iterator j = certs.iterator();

                while (j.hasNext()) {
                    CertificateDataPK revpk = new CertificateDataPK();
                    certificate = (X509Certificate) j.next();
                    revpk.fingerprint = CertTools.getFingerprintAsString(certificate);

                    CertificateDataLocal rev = certHome.findByPrimaryKey(revpk);

                    if (rev.getStatus() != CertificateData.CERT_REVOKED) {
                        rev.setStatus(CertificateData.CERT_REVOKED);
                        rev.setRevocationDate(new Date());
                        rev.setRevocationReason(reason);

                        try {
                            logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null,
                                certificate, LogEntry.EVENT_INFO_REVOKEDCERT, ("Reason :" + reason));
                        } catch (RemoteException re) {
                            throw new EJBException(re);
                        }
                    }
                }
            }
        } catch (FinderException e) {
            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_REVOKEDCERT,
                    ("Couldn't find certificate with username :" + username));
            } catch (RemoteException f) {
                throw new EJBException(f);
            }

            throw new EJBException(e);
        }
    }

    // setRevokeStatus

    /**
     * Set the status of certificate of serno to revoked.
     *
     * @param admin DOCUMENT ME!
     * @param serno the serial number of the certificate to revoke.
     * @param reason reason the user is revoked from CRLData
     *
     * @see CRLData
     */
    public void setRevokeStatus(Admin admin, BigInteger serno, int reason) {
        X509Certificate certificate = null;

        try {
            Collection certs = findCertificatesBySerno(admin, serno);

            // Revoke all certs
            if (!certs.isEmpty()) {
                Iterator j = certs.iterator();

                while (j.hasNext()) {
                    CertificateDataPK revpk = new CertificateDataPK();
                    certificate = (X509Certificate) j.next();
                    revpk.fingerprint = CertTools.getFingerprintAsString(certificate);

                    CertificateDataLocal rev = certHome.findByPrimaryKey(revpk);

                    if (rev.getStatus() != CertificateData.CERT_REVOKED) {
                        rev.setStatus(CertificateData.CERT_REVOKED);
                        rev.setRevocationDate(new Date());
                        rev.setRevocationReason(reason);

                        try {
                            logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null,
                                certificate, LogEntry.EVENT_INFO_REVOKEDCERT, ("Reason :" + reason));
                        } catch (RemoteException re) {
                            throw new EJBException(re);
                        }
                    }
                }
            }
        } catch (FinderException e) {
            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_REVOKEDCERT,
                    ("Couldn't find certificate with serno :" + serno));
            } catch (RemoteException f) {
                throw new EJBException(f);
            }

            throw new EJBException(e);
        }
    }

    // setRevokeStatus

    /**
     * Revokes a certificate (already revoked by the CA), the Publisher decides what to do, if
     * anything.
     *
     * @param admin DOCUMENT ME!
     * @param cert The DER coded Certificate that has been revoked.
     * @param reason DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void revokeCertificate(Admin admin, Certificate cert, int reason) {
        if (cert instanceof X509Certificate) {
            setRevokeStatus(admin, ((X509Certificate) cert).getSerialNumber(), reason);
        }
    }

    //revokeCertificate

    /**
     * Method that checks if a users all certificates have been revoked.
     *
     * @param admin DOCUMENT ME!
     * @param username the username to check for.
     *
     * @return returns true if all certificates are revoked.
     */
    public boolean checkIfAllRevoked(Admin admin, String username) {
        boolean returnval = true;
        X509Certificate certificate = null;

        // Strip dangerous chars
        username = StringTools.strip(username);

        try {
            Collection certs = findCertificatesByUsername(admin, username);

            // Revoke all certs
            if (!certs.isEmpty()) {
                Iterator j = certs.iterator();

                while (j.hasNext()) {
                    CertificateDataPK revpk = new CertificateDataPK();
                    certificate = (X509Certificate) j.next();
                    revpk.fingerprint = CertTools.getFingerprintAsString(certificate);

                    CertificateDataLocal rev = certHome.findByPrimaryKey(revpk);

                    if (rev.getStatus() != CertificateData.CERT_REVOKED) {
                        returnval = false;
                    }
                }
            }
        } catch (FinderException e) {
            throw new EJBException(e);
        }

        return returnval;
    }

    /**
     * Implements ICertificateStoreSession::isRevoked. Uses select directly from datasource.
     *
     * @param admin DOCUMENT ME!
     * @param issuerDN DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno) {
        debug(">isRevoked(), dn:" + issuerDN + ", serno=" + serno);

        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            Certificate ret = null;

            if (coll != null) {
                if (coll.size() > 1) {
                    logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                        LogEntry.EVENT_ERROR_DATABASE,
                        "Error in database, more than one certificate has the same Issuer : " +
                        issuerDN + " and serialnumber " + serno.toString(16) + ".");
                }

                Iterator iter = coll.iterator();

                if (iter.hasNext()) {
                    RevokedCertInfo revinfo = null;
                    CertificateDataLocal data = (CertificateDataLocal) iter.next();

                    if (data.getStatus() == CertificateData.CERT_REVOKED) {
                        revinfo = new RevokedCertInfo(serno, new Date(data.getRevocationDate()),
                                data.getRevocationReason());
                    }

                    debug("<isRevoked() returned " +
                        ((data.getStatus() == CertificateData.CERT_REVOKED) ? "yes" : "no"));

                    return revinfo;
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }

        return null;
    }
     //isRevoked

    /**
     * Implements ICertificateStoreSession::getLastCRL. Uses select directly from datasource.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public byte[] getLastCRL(Admin admin) {
        debug(">findLatestCRL()");

        try {
            int maxnumber = getLastCRLNumber(admin);
            X509CRL crl = null;

            try {
                CRLDataLocal data = crlHome.findByCRLNumber(maxnumber);
                crl = data.getCRL();
            } catch (FinderException e) {
                crl = null;
            }

            debug("<findLatestCRL()");

            if (crl == null) {
                return null;
            }

            logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                LogEntry.EVENT_INFO_GETLASTCRL, "Number :" + maxnumber);

            return crl.getEncoded();
        } catch (Exception e) {
            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_GETLASTCRL, "Error retrieving last crl.");
            } catch (RemoteException re) {
                throw new EJBException(re);
            }

            throw new EJBException(e);
        }
    }
     //getLastCRL

    /**
     * Implements ICertificateStoreSession::getLastCRLNumber. Uses select directly from datasource.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getLastCRLNumber(Admin admin) {
        debug(">getLastCRLNumber()");

        Connection con = null;
        PreparedStatement ps = null;
        ;

        ResultSet result = null;

        try {
            con = getConnection();
            ps = con.prepareStatement("select MAX(CRLNumber) from CRLData");
            result = ps.executeQuery();

            int maxnumber = 0;

            if (result.next()) {
                maxnumber = result.getInt(1);
            }

            debug("<getLastCRLNumber()");

            return maxnumber;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            try {
                if (result != null) {
                    result.close();
                }

                if (ps != null) {
                    ps.close();
                }

                if (con != null) {
                    con.close();
                }
            } catch (SQLException se) {
                error("Error cleaning up: ", se);
            }
        }
    }
     //getLastCRLNumber

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin administrator performing the task
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile the profile to be added
     *
     * @return true if added succesfully, false if it already exist
     */
    public boolean addCertificateProfile(Admin admin, String certificateprofilename,
        CertificateProfile certificateprofile) {
        return addCertificateProfile(admin, findFreeCertificateProfileId(), certificateprofilename, certificateprofile);
    } // addCertificateProfile

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin administrator performing the task
     * @param certificateprofileid internal ID of new certificate profile, use only if you know it's right.
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile the profile to be added
     *
     * @return true if added succesfully, false if it already exist
     */
    public boolean addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename,
        CertificateProfile certificateprofile) {
        boolean returnval = false;
        
        if (isFreeCertificateProfileId(certificateprofileid) == false) {
            return returnval;
        }
        try {
            certprofilehome.findByCertificateProfileName(certificateprofilename);
        } catch (FinderException e) {
            try {
                certprofilehome.create(new Integer(certificateprofileid), certificateprofilename,
                    certificateprofile);
                returnval = true;
            } catch (Exception f) {
            }
        }

        try {
            if (returnval) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_CERTPROFILE,
                    "New certificateprofile " + certificateprofilename + ".");
            } else {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_CERTPROFILE,
                    "Error adding certificateprofile " + certificateprofilename + ".");
            }
        } catch (RemoteException re) {
            throw new EJBException(re);
        }

        return returnval;
    } // addCertificateProfile

    /**
     * Adds a certificate profile with the same content as the original certificateprofile,
     *
     * @param admin DOCUMENT ME!
     * @param originalcertificateprofilename DOCUMENT ME!
     * @param newcertificateprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean cloneCertificateProfile(Admin admin, String originalcertificateprofilename,
        String newcertificateprofilename) {
        CertificateProfile certificateprofile = null;
        boolean returnval = false;

        try {
            CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(originalcertificateprofilename);
            certificateprofile = (CertificateProfile) pdl.getCertificateProfile().clone();

            returnval = addCertificateProfile(admin, newcertificateprofilename, certificateprofile);
        } catch (FinderException e) {
        } catch (CloneNotSupportedException f) {
        }

        try {
            if (returnval) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_CERTPROFILE,
                    "New certificateprofile " + newcertificateprofilename + " used profile " +
                    originalcertificateprofilename + " as template.");
            } else {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_CERTPROFILE,
                    "Error adding certificaterprofile " + newcertificateprofilename +
                    " using profile " + originalcertificateprofilename + " as template.");
            }
        } catch (RemoteException re) {
            throw new EJBException(re);
        }

        return returnval;
    }
     // cloneCertificateProfile

    /**
     * Removes a certificateprofile from the database.
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeCertificateProfile(Admin admin, String certificateprofilename) {
        try {
            CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(certificateprofilename);
            pdl.remove();
            logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                LogEntry.EVENT_INFO_CERTPROFILE,
                "Removed certificateprofile " + certificateprofilename + ".");
        } catch (Exception e) {
            error("Error removing certificate profile: ", e);

            try {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_CERTPROFILE,
                    "Error removing certificateprofile " + certificateprofilename + ".");
            } catch (RemoteException re) {
            }
        }
    }
     // removeCertificateProfile

    /**
     * Renames a certificateprofile
     *
     * @param admin DOCUMENT ME!
     * @param oldcertificateprofilename DOCUMENT ME!
     * @param newcertificateprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean renameCertificateProfile(Admin admin, String oldcertificateprofilename,
        String newcertificateprofilename) {
        boolean returnvalue = false;

        try {
            certprofilehome.findByCertificateProfileName(newcertificateprofilename);
        } catch (FinderException e) {
            try {
                CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(oldcertificateprofilename);
                pdl.setCertificateProfileName(newcertificateprofilename);
                returnvalue = true;
            } catch (FinderException f) {
            }
        }

        try {
            if (returnvalue) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_CERTPROFILE,
                    "Renamed certificateprofile " + oldcertificateprofilename + " to " +
                    newcertificateprofilename + ".");
            } else {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_CERTPROFILE,
                    "Error renaming certificateprofile " + oldcertificateprofilename + " to " +
                    newcertificateprofilename + ".");
            }
        } catch (RemoteException re) {
            throw new EJBException(re);
        }

        return returnvalue;
    }
     // remameCertificateProfile

    /**
     * Updates certificateprofile data
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     * @param certificateprofile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean changeCertificateProfile(Admin admin, String certificateprofilename,
        CertificateProfile certificateprofile) {
        boolean returnvalue = false;

        try {
            CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(certificateprofilename);
            pdl.setCertificateProfile(certificateprofile);
            returnvalue = true;
        } catch (FinderException e) {
        }

        try {
            if (returnvalue) {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_INFO_CERTPROFILE,
                    "Certificateprofile " + certificateprofilename + " edited.");
            } else {
                logsession.log(admin, LogEntry.MODULE_CA, new java.util.Date(), null, null,
                    LogEntry.EVENT_ERROR_CERTPROFILE,
                    " Error editing certificateprofile " + certificateprofilename + ".");
            }
        } catch (RemoteException re) {
            throw new EJBException(re);
        }

        return returnvalue;
    }
     // changeCertificateProfile

    /**
     * Retrives certificate profile names sorted.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection getCertificateProfileNames(Admin admin) {
        ArrayList returnval = new ArrayList();
        Collection result = null;

        try {
            result = certprofilehome.findAll();

            if (result.size() > 0) {
                Iterator i = result.iterator();

                while (i.hasNext()) {
                    returnval.add(((CertificateProfileDataLocal) i.next()).getCertificateProfileName());
                }
            }

            Collections.sort(returnval);
        } catch (Exception e) {
            error("Error getting certificate profile names: ", e);
        }

        return returnval;
    }
     // getCertificateProfileNames

    /**
     * Retrives certificate profiles sorted by name.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public TreeMap getCertificateProfiles(Admin admin) {
        TreeMap returnval = new TreeMap();
        Collection result = null;

        try {
            result = certprofilehome.findAll();

            if (result.size() > 0) {
                returnval = new TreeMap();

                Iterator i = result.iterator();

                while (i.hasNext()) {
                    CertificateProfileDataLocal pdl = (CertificateProfileDataLocal) i.next();
                    returnval.put(pdl.getCertificateProfileName(), pdl.getCertificateProfile());
                }
            }
        } catch (FinderException e) {
        }

        return returnval;
    }
     // getCertificateProfiles

    /**
     * Retrives a named certificate profile.
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename) {
        CertificateProfile returnval = null;

        try {
            returnval = (certprofilehome.findByCertificateProfileName(certificateprofilename)).getCertificateProfile();
        } catch (FinderException e) {
            // return null if we cant find it
        }

        return returnval;
    }
     //  getCertificateProfile

    /**
     * Finds a certificate profile by id.
     *
     * @param admin DOCUMENT ME!
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile getCertificateProfile(Admin admin, int id) {
        CertificateProfile returnval = null;

        try {
            returnval = (certprofilehome.findByPrimaryKey(new Integer(id))).getCertificateProfile();
        } catch (FinderException e) {
            // return null if we cant find it
        }

        return returnval;
    }
     // getCertificateProfile

    /**
     * Retrives the numbers of certificateprofiles.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getNumberOfCertificateProfiles(Admin admin) {
        int returnval = 0;

        try {
            returnval = (certprofilehome.findAll()).size();
        } catch (FinderException e) {
        }

        return returnval;
    }
     // getNumberOfCertificateProfiles

    /**
     * Returns a certificate profile id, given it's certificate profile name
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     *
     * @return the id or 0 if certificateprofile cannot be found.
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename) {
        int returnval = 0;

        try {
            Integer id = (certprofilehome.findByCertificateProfileName(certificateprofilename)).getId();
            returnval = id.intValue();
        } catch (FinderException e) {
        }

        return returnval;
    }
     // getCertificateProfileId

    /**
     * Returns a certificateprofiles name given it's id.
     *
     * @param admin DOCUMENT ME!
     * @param id DOCUMENT ME!
     *
     * @return certificateprofilename or null if certificateprofile id doesn't exists.
     */
    public String getCertificateProfileName(Admin admin, int id) {
        String returnval = null;

        try {
            returnval = (certprofilehome.findByPrimaryKey(new Integer(id))).getCertificateProfileName();
        } catch (FinderException e) {
        }

        return returnval;
    }
     // getCertificateProfileName

    // Private methods
    private int findFreeCertificateProfileId() {
        Random random = new Random((new Date()).getTime());
        int id = random.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
                    certprofilehome.findByPrimaryKey(new Integer(id));
                } else {
                    id = random.nextInt();
                }
            } catch (FinderException e) {
                foundfree = true;
            }
        }

        return id;
    } // findFreeCertificateProfileId

    private boolean isFreeCertificateProfileId(int id) {
        boolean foundfree = false;
        try {
            if (id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
                certprofilehome.findByPrimaryKey(new Integer(id));
            } 
        } catch (FinderException e) {
            foundfree = true;
        }
        return foundfree;
    } // isFreeCertificateProfileId

}
 // CertificateStoreSessionBean
