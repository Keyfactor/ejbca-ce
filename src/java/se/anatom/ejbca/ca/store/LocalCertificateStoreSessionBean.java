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

package se.anatom.ejbca.ca.store;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CertificateProfileExistsException;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocal;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocalHome;
import se.anatom.ejbca.ca.store.certificateprofiles.CACertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.EndUserCertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.HardTokenAuthCertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.HardTokenAuthEncCertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.HardTokenEncCertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.HardTokenSignCertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.RootCACertificateProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.JDBCUtil;
import se.anatom.ejbca.util.StringTools;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.sql.DataSource;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;


/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalCertificateStoreSessionBean.java,v 1.73 2004-07-23 10:24:41 anatom Exp $
 * @ejb.bean display-name="CertificateStoreSB"
 * name="CertificateStoreSession"
 * view-type="both"
 * type="Stateless"
 * transaction-type="Container"
 * @ejb.permission role-name="InternalUser"
 * @ejb.env-entry description="JDBC datasource to be used"
 * name="Datasource"
 * type="java.lang.String"
 * value="java:/${datasource.jndi-name}"
 * @ejb.ejb-external-ref description="The Certificate entity bean used to store and fetch certificates"
 * view-type="local"
 * ejb-name="CertificateStoreSessionLocal"
 * type="Session"
 * home="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome"
 * business="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal"
 * link="CertificateStoreSession"
 * @ejb.ejb-external-ref description="The Log session bean"
 * view-type="local"
 * ejb-name="LogSessionLocal"
 * type="Session"
 * home="se.anatom.ejbca.log.ILogSessionLocalHome"
 * business="se.anatom.ejbca.log.ILogSessionLocal"
 * link="LogSession"
 * @ejb.ejb-external-ref description="The Authorization session bean"
 * view-type="local"
 * ejb-name="AuthorizationSessionLocal"
 * type="Session"
 * home="se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome"
 * business="se.anatom.ejbca.authorization.IAuthorizationSessionLocal"
 * link="AuthorizationSession"
 * @ejb.ejb-external-ref description="Publishers are configured to store certificates and CRLs in additional places from the main database.
 * Publishers runs as local beans"
 * view-type="local"
 * ejb-name="PublisherSessionLocal"
 * type="Session"
 * home="se.anatom.ejbca.ca.publisher.IPublisherSessionLocalHome"
 * business="se.anatom.ejbca.ca.publisher.IPublisherSessionLocal"
 * link="PublisherSession"
 * @ejb.home extends="javax.ejb.EJBHome"
 * local-extends="javax.ejb.EJBLocalHome"
 * local-class="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome"
 * remote-class="se.anatom.ejbca.ca.store.ICertificateStoreSessionHome"
 * @ejb.interface extends="javax.ejb.EJBObject"
 * local-extends="javax.ejb.EJBLocalObject"
 * local-class="se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal"
 * remote-class="se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote"
 */
public class LocalCertificateStoreSessionBean extends BaseSessionBean {

    /**
     * Var holding JNDI name of datasource
     */
    private String dataSource = "";

    /**
     * The home interface of Certificate entity bean
     */
    private CertificateDataLocalHome certHome = null;

    /**
     * The home interface of Certificate Type entity bean
     */
    private CertificateProfileDataLocalHome certprofilehome = null;

    /**
     * The home interface of CRL entity bean
     */
    private CRLDataLocalHome crlHome = null;

    /**
     * The local interface of the log session bean
     */
    private ILogSessionLocal logsession = null;

    /**
     * The local interface of the authorization session bean
     */
    private IAuthorizationSessionLocal authorizationsession = null;

    /**
     * The local interface of the publisher session bean
     */
    private IPublisherSessionLocal publishersession = null;


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
        certprofilehome = (CertificateProfileDataLocalHome) lookup("java:comp/env/ejb/CertificateProfileDataLocal");

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
    } //getConnection


    /**
     * Gets connection to log session bean
     */
    private ILogSessionLocal getLogSession() {
        if (logsession == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup(ILogSessionLocalHome.COMP_NAME, ILogSessionLocalHome.class);
                logsession = logsessionhome.create();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        return logsession;
    } //getLogSession


    /**
     * Gets connection to authorization session bean
     *
     * @return Connection
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if (authorizationsession == null) {
            try {
                IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) lookup("java:comp/env/ejb/AuthorizationSessionLocal", IAuthorizationSessionLocalHome.class);
                authorizationsession = authorizationsessionhome.create();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        return authorizationsession;
    } //getAuthorizationSession

    /**
     * Gets connection to publisher session bean
     *
     * @return Connection
     */
    private IPublisherSessionLocal getPublisherSession() {
        if (publishersession == null) {
            try {
                IPublisherSessionLocalHome publishersessionhome = (IPublisherSessionLocalHome) lookup("java:comp/env/ejb/PublisherSessionLocal", IPublisherSessionLocalHome.class);
                publishersession = publishersessionhome.create();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        return publishersession;
    } //getPublisherSession


    /**
     * Stores a certificate.
     *
     * @param incert   The certificate to be stored.
     * @param cafp     Fingerprint (hex) of the CAs certificate.
     * @param username username of end entity owning the certificate.
     * @param status   Status of the certificate (from CertificateData).
     * @param type     Type of certificate (CERTTYPE_ENDENTITY etc from CertificateDataBean).
     * @return true if storage was successful.
     * @ejb.interface-method
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
            getLogSession().log(admin, cert, LogEntry.MODULE_CA, new java.util.Date(), username, (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE, "");
            CertificateDataLocal data1 = null;
            data1 = certHome.create(cert);
            data1.setUsername(username);
            data1.setCAFingerprint(cafp);
            data1.setStatus(status);
            data1.setType(type);
        } catch (Exception e) {
            getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), username, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE, "");
            throw new EJBException(e);
        }
        debug("<storeCertificate()");
        return true;
    } // storeCertificate

    /**
     * Stores a CRL
     *
     * @param incrl  The DER coded CRL to be stored.
     * @param cafp   Fingerprint (hex) of the CAs certificate.
     * @param number CRL number.
     * @return true if storage was successful.
     * @ejb.interface-method
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number) {
        debug(">storeCRL(" + cafp + ", " + number + ")");

        try {
            X509CRL crl = CertTools.getCRLfromByteArray(incrl);
            CRLDataLocal data1 = crlHome.create(crl, number);
            data1.setCAFingerprint(cafp);
            getLogSession().log(admin, crl.getIssuerDN().toString().hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_STORECRL, "Number : " + number + " Fingerprint : " + CertTools.getFingerprintAsString(crl) + ".");
        } catch (Exception e) {
            getLogSession().log(admin, ILogSessionLocal.INTERNALCAID, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECRL, "Number : " + number + ".");
            throw new EJBException(e);
        }
        debug("<storeCRL()");

        return true;
    } // storeCRL

    /**
     * Lists fingerprint (primary key) of ALL certificates in the database.
     * NOTE: Caution should be taken with this method as execution may be very
     * heavy indeed if many certificates exist in the database (imagine what happens if
     * there are millinos of certificates in the DB!).
     * Should only be used for testing purposes.
     *
     * @param admin    Administrator performing the operation
     * @param issuerdn the dn of the certificates issuer.
     * @return Collection of fingerprints, i.e. Strings, reverse ordered by expireDate where last expireDate is first in array.
     * @ejb.interface-method
     */
    public Collection listAllCertificates(Admin admin, String issuerdn) {
        debug(">listAllCertificates()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        String dn = CertTools.stringToBCDNString(issuerdn);
        dn = StringTools.strip(dn);
        try {
            con = getConnection();
            ps = con.prepareStatement("select fingerprint from CertificateData where issuerDN=? ORDER BY expireDate DESC");
            ps.setString(1, dn);
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
            JDBCUtil.close(con, ps, result);
        }
    } // listAllCertificates

    /**
     * @ejb.interface-method
     */
    public Collection listRevokedCertificates(Admin admin, String issuerdn) {
        debug(">listRevokedCertificates()");

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        String dn = CertTools.stringToBCDNString(issuerdn);
        dn = StringTools.strip(dn);
        try {
            // TODO:
            // This should only list a few thousend certificates at a time, in case there
            // are really many revoked certificates after some time...
            con = getConnection();
            ps = con.prepareStatement("select fingerprint from CertificateData where status=? and issuerDN=? ORDER BY expireDate DESC");
            ps.setInt(1, CertificateDataBean.CERT_REVOKED);
            ps.setString(2, dn);
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
            JDBCUtil.close(con, ps, result);
        }
    } // listRevokedCertificates

    /**
     * Lists certificates for a given subject signed by the given issuer.
     *
     * @param admin     Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @param issuerDN  the dn of the certificates issuer.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     * @throws EJBException if a communication or other error occurs.
     * @ejb.interface-method
     */
    public Collection findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuerDN) {
        debug(">findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(subjectDN);
        dn = StringTools.strip(dn);
        String issuerdn = CertTools.stringToBCDNString(issuerDN);
        issuerdn = StringTools.strip(issuerdn);
        debug("Looking for cert with (transformed)DN: " + dn);
        try {
            Collection coll = certHome.findBySubjectDNAndIssuerDN(dn, issuerdn);
            Collection ret = new ArrayList();
            if (coll != null) {
                Iterator iter = coll.iterator();
                while (iter.hasNext()) {
                    ret.add(((CertificateDataLocal) iter.next()).getCertificate());
                }
            }
            debug("<findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "' and issuer='" + issuerDN + "'");
            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    } //findCertificatesBySubjectAndIssuer

    /**
     * Lists certificates for a given subject.
     *
     * @param admin     Administrator performing the operation
     * @param subjectDN the DN of the subject whos certificates will be retrieved.
     * @return Collection of Certificates (java.security.cert.Certificate) in no specified order or an empty Collection.
     * @ejb.interface-method
     */
    public Collection findCertificatesBySubject(Admin admin, String subjectDN) {
        debug(">findCertificatesBySubjectAndIssuer(), dn='" + subjectDN + "'");
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(subjectDN);
        dn = StringTools.strip(dn);
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
    } //findCertificatesBySubject

    /**
     * @ejb.interface-method
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
     * @ejb.interface-method
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
            ps = con.prepareStatement("SELECT DISTINCT username FROM CertificateData WHERE expireDate>=? AND expireDate<? AND status=?");
            ps.setLong(1, currentdate);
            ps.setLong(2, expiretime.getTime());
            ps.setInt(3, CertificateDataBean.CERT_ACTIVE);
            result = ps.executeQuery();
            while (result.next() && returnval.size() <= SecConst.MAXIMUM_QUERY_ROWCOUNT + 1) {
                if (result.getString(1) != null && !result.getString(1).equals(""))
                    returnval.add(result.getString(1));
            }
            debug("<findCertificatesByExpireTimeWithLimit()");
            return returnval;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    } //findCertificatesByExpireTimeWithLimit

    /**
     * Finds a certificate specified by issuer DN and serial number.
     *
     * @param admin    Administrator performing the operation
     * @param issuerDN issuer DN of the desired certificate.
     * @param serno    serial number of the desired certificate!
     * @return Certificate if found or null
     * @ejb.interface-method
     */
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) {
        debug(">findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        dn = StringTools.strip(dn);
        debug("Looking for cert with (transformed)DN: " + dn);
        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            Certificate ret = null;
            if (coll != null) {
                if (coll.size() > 1)
                    getLogSession().log(admin, issuerDN.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_DATABASE, "Error in database, more than one certificate has the same Issuer : " + issuerDN + " and serialnumber "
                            + serno.toString(16) + ".");
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
    } //findCertificateByIssuerAndSerno

    /**
     * Implements ICertificateStoreSession::findCertificatesByIssuerAndSernos.
     * <p/>
     * The method retrives all certificates from a specific issuer
     * which are identified by list of serial numbers. The collection
     * will be empty if the issuerDN is <tt>null</tt>/empty
     * or the collection of serial numbers is empty.
     *
     * @param admin
     * @param issuer the subjectDN of a CA certificate
     * @param sernos a collection of certificate serialnumbers
     * @return Collection a list of certificates; never <tt>null</tt>
     * @ejb.interface-method
     */
    public Collection findCertificatesByIssuerAndSernos(Admin admin, String issuerDN, Collection sernos) {
        debug(">findCertificateByIssuerAndSernos()");

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        ArrayList vect = null;

        if (null == admin) {
            throw new IllegalArgumentException();
        }


        if (null == issuerDN || issuerDN.length() <= 0
                || null == sernos || sernos.isEmpty()) {
            return new ArrayList();
        }

        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        try {

            final StringBuffer sb = new StringBuffer();
            /*
             * tmeckel:
             * JBoss seems to have problems loading anoymous classes :(
             * i always get an java.lang.NoClassDefFound exception when
             * i try to use the following code snipped
             *
             * the code in the following block is only a dingy
             * replacement as long as the problem with anonymous
             * classes are solved :)
            CollectionUtils.forAllDo(sernos, new Closure() {
                                                public void execute(Object input) {
                                                    if (null != input) {
                                                        sb.append(", ");
                                                        sb.append(input.toString());
                                                    }
                                                }} );
            */
            {
                Iterator iter = sernos.iterator();
                while (iter.hasNext()) {
                    sb.append(", '");
// Make sure this is really a BigInteger passed in as (untrusted param)
                    BigInteger serno = (BigInteger) iter.next();
                    sb.append(serno.toString());
                    sb.append("'");
                }
            }
            /*
             * to save the repeating if-statement in the above
             * Closure not to add ', ' as the first characters
             * in the StringBuffer we remove the two chars here :)
             */
            sb.delete(0, ", ".length());
            con = getConnection();
            ps = con.prepareStatement("SELECT DISTINCT fingerprint"
                    + " FROM CertificateData WHERE"
                    + " issuerDN = ?"
                    + " AND serialNumber IN (" + sb.toString() + ")");
            ps.setString(1, dn);
            result = ps.executeQuery();

            vect = new ArrayList();
            while (result.next()) {
                Certificate cert = findCertificateByFingerprint(admin, result.getString(1));
                if (cert != null) {
                    vect.add(cert);
                }
            }

            debug("<findCertificateByIssuerAndSernos()");
            return vect;
        } catch (Exception fe) {
            throw new EJBException(fe);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    } // findCertificateByIssuerAndSernos

    /**
     * Finds certificate(s) for a given serialnumber.
     *
     * @param admin Administrator performing the operation
     * @param serno the serialnumber of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     * @ejb.interface-method
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
    } // findCertificateBySerno

    /**
     * Finds username for a given certificate serial number.
     *
     * @param admin Administrator performing the operation
     * @param serno the serialnumber of the certificate to find username for.
     * @return username or null if none found.
     * @ejb.interface-method
     */
    public String findUsernameByCertSerno(Admin admin, BigInteger serno, String issuerdn) {
        debug(">findUsernameByCertSerno(),  serno=" + serno);
        String dn = CertTools.stringToBCDNString(issuerdn);
        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
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
    } // findUsernameByCertSerno

    /**
     * Finds certificate(s) for a given usernaem.
     *
     * @param admin    Administrator performing the operation
     * @param username the usernaem of the certificate(s) that will be retrieved
     * @return Certificate or null if none found.
     * @ejb.interface-method
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
    } // findCertificateByUsername

    /**
     * @ejb.interface-method
     */
    public CertificateInfo getCertificateInfo(Admin admin, String fingerprint) {
        debug(">getCertificateInfo()");
        CertificateInfo ret = null;

        try {
            CertificateDataLocal res = certHome.findByPrimaryKey(new CertificateDataPK(fingerprint));
            ret = new CertificateInfo(res.getFingerprint(), res.getCAFingerprint(),res.getSerialNumber(),res.getIssuerDN(),res.getSubjectDN(),
                    res.getStatus(),res.getType(),res.getExpireDate(),res.getRevocationDate(),res.getRevocationReason());
            debug("<getCertificateInfo()");
        } catch (FinderException fe) {
            // Return null;
        } catch (Exception e) {
            log.error("Error finding certificate with fp: " + fingerprint);
            throw new EJBException(e);
        }
        return ret;
    } // getCertificateInfo

    /**
     * @ejb.interface-method
     */
    public Certificate findCertificateByFingerprint(Admin admin, String fingerprint) {
        debug(">findCertificateByFingerprint()");
        Certificate ret = null;

        try {
            CertificateDataLocal res = certHome.findByPrimaryKey(new CertificateDataPK(fingerprint));
            ret = res.getCertificate();
            debug("<findCertificateByFingerprint()");
        } catch (FinderException fe) {
            // Return null;
        } catch (Exception e) {
            log.error("Error finding certificate with fp: " + fingerprint);
            throw new EJBException(e);
        }
        return ret;
    } // findCertificateByFingerprint

    /**
     * Lists all active (status = 20) certificates of a specific type and if
     * given from a specific issuer.
     * <p/>
     * The type is the bitwise OR value of the types listed
     * int {@link se.anatom.ejbca.ca.store.CertificateDataBean}:<br>
     * <ul>
     * <li><tt>CERTTYPE_ENDENTITY</tt><br>
     * An user or machine certificate, which identifies a subject.
     * </li>
     * <li><tt>CERTTYPE_CA</tt><br>
     * A CA certificate which is <b>not</b> a root CA.
     * </li>
     * <li><tt>CERTTYPE_ROOTCA</tt><br>
     * A Root CA certificate.
     * </li>
     * </ul>
     * <p/>
     * Usage examples:<br>
     * <ol>
     * <li>Get all root CA certificates
     * <p/>
     * <code>
     * ...
     * ICertificateStoreSessionRemote itf = ...
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_ROOTCA,
     * null);
     * ...
     * </code>
     * </li>
     * <li>Get all subordinate CA certificates for a specific
     * Root CA. It is assumed that the <tt>subjectDN</tt> of the
     * Root CA certificate is located in the variable <tt>issuer</tt>.
     * <p/>
     * <code>
     * ...
     * ICertificateStoreSessionRemote itf = ...
     * Certficate rootCA = ...
     * String issuer = rootCA.getSubjectDN();
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_SUBCA,
     * issuer);
     * ...
     * </code>
     * </li>
     * <li>Get <b>all</b> CA certificates.
     * <p/>
     * <code>
     * ...
     * ICertificateStoreSessionRemote itf = ...
     * Collection certs = itf.findCertificatesByType(adm,
     * CertificateDataBean.CERTTYPE_SUBCA
     * + CERTTYPE_ROOTCA,
     * null);
     * ...
     * </code>
     * </li>
     * </ol>
     *
     * @param admin
     * @param issuerDN get all certificates issued by a specific issuer.
     *                 If <tt>null</tt> or empty return certificates regardless of
     *                 the issuer.
     * @param type     CERTTYPE_* types from CertificateDataBean
     * @return Collection Collection of X509Certificate, never <tt>null</tt>
     * @ejb.interface-method
     */
    public Collection findCertificatesByType(Admin admin, int type, String issuerDN) {
        debug(">findCertificatesByType()");
        if (null == admin
                || type <= 0
                || type > CertificateDataBean.CERTTYPE_SUBCA + CertificateDataBean.CERTTYPE_ENDENTITY + CertificateDataBean.CERTTYPE_ROOTCA) {
            throw new IllegalArgumentException();
        }
        StringBuffer ctypes = new StringBuffer();
        if ((type & CertificateDataBean.CERTTYPE_SUBCA) > 0) {
            ctypes.append(CertificateDataBean.CERTTYPE_SUBCA);
        }
        if ((type & CertificateDataBean.CERTTYPE_ENDENTITY) > 0) {
            if (ctypes.length() > 0) {
                ctypes.append(", ");
            }
            ctypes.append(CertificateDataBean.CERTTYPE_ENDENTITY);
        }
        if ((type & CertificateDataBean.CERTTYPE_ROOTCA) > 0) {
            if (ctypes.length() > 0) {
                ctypes.append(", ");
            }
            ctypes.append(CertificateDataBean.CERTTYPE_ROOTCA);
        }

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        try {
            ArrayList vect;
// Status 20 = CertificateDataBean.CERT_ACTIVE
            StringBuffer stmt = new StringBuffer("SELECT DISTINCT fingerprint FROM CertificateData WHERE status = 20 AND ");
            stmt.append(" type IN (");
            stmt.append(ctypes.toString());
            stmt.append(')');
            if (null != issuerDN && issuerDN.length() > 0) {
                String dn = CertTools.stringToBCDNString(issuerDN);
                dn = StringTools.strip(dn);
                if (log.isDebugEnabled()) {
                    debug("findCertificatesByType() : Looking for cert with (transformed)DN: " + dn);
                }
                stmt.append(" AND issuerDN = '");
                stmt.append(dn);
                stmt.append('\'');
            }
            if (log.isDebugEnabled()) {
                debug("findCertificatesByType() : executing SQL statement\n"
                        + stmt.toString());
            }
            con = getConnection();
            ps = con.prepareStatement(stmt.toString());
            result = ps.executeQuery();

            vect = new ArrayList();
            while (result.next()) {
                Certificate cert = findCertificateByFingerprint(admin, result.getString(1));
                if (cert != null) {
                    vect.add(cert);
                }
            }

            debug("<findCertificatesByType()");
            return vect;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    } // findCertificatesByType

    /**
     * Set the status of certificates of given dn to revoked.
     *
     * @param admin      Administrator performing the operation
     * @param username   the username of user to revoke certificates.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @param reason     the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON
     *                   constants.)
     * @ejb.interface-method
     */
    public void setRevokeStatus(Admin admin, String username, Collection publishers, int reason) {
        debug(">setRevokeStatus(),  username=" + username);
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
                    if (rev.getStatus() != CertificateDataBean.CERT_REVOKED) {
                        rev.setStatus(CertificateDataBean.CERT_REVOKED);
                        rev.setRevocationDate(new Date());
                        rev.setRevocationReason(reason);
                        getLogSession().log(admin, certificate, LogEntry.MODULE_CA, new java.util.Date(), null, certificate, LogEntry.EVENT_INFO_REVOKEDCERT, ("Reason :" + reason));
                        // Revoke in all related publishers
                        if (publishers != null) {
                            getPublisherSession().revokeCertificate(admin, publishers, certificate, reason);
                        }
                    }
                }
            }
        } catch (FinderException e) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_REVOKEDCERT, ("Couldn't find certificate with username :" + username));
            throw new EJBException(e);
        }
        debug("<setRevokeStatus(),  username=" + username);
    } // setRevokeStatus

    /**
     * Set the status of certificate with  given serno to revoked.
     *
     * @param admin      Administrator performing the operation
     * @param serno      the serno of certificate to revoke.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @param reason     the reason of the revokation. (One of the RevokedCertInfo.REVOKATION_REASON constants.)
     * @ejb.interface-method
     */
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, Collection publishers, int reason) {
        debug(">setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno);
        X509Certificate certificate = null;
        try {
            certificate = (X509Certificate) this.findCertificateByIssuerAndSerno(admin, issuerdn, serno);
            // Revoke all certs
            if (certificate != null) {
                CertificateDataPK revpk = new CertificateDataPK();
                revpk.fingerprint = CertTools.getFingerprintAsString(certificate);
                CertificateDataLocal rev = certHome.findByPrimaryKey(revpk);
                if (rev.getStatus() != CertificateDataBean.CERT_REVOKED) {
                    rev.setStatus(CertificateDataBean.CERT_REVOKED);
                    rev.setRevocationDate(new Date());
                    rev.setRevocationReason(reason);
                    getLogSession().log(admin, issuerdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, certificate, LogEntry.EVENT_INFO_REVOKEDCERT, ("Reason :" + reason));
                }
                // Revoke in all related publishers
                if (publishers != null) {
                    getPublisherSession().revokeCertificate(admin, publishers, certificate, reason);
                }
            }
        } catch (FinderException e) {
            getLogSession().log(admin, issuerdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_REVOKEDCERT, ("Couldn't find certificate with serno :" + serno));
            throw new EJBException(e);
        }
        debug("<setRevokeStatus(),  issuerdn=" + issuerdn + ", serno=" + serno);
    } // setRevokeStatus

    /**
     * Revokes a certificate (already revoked by the CA), in the database
     *
     * @param cert       The DER coded Certificate that has been revoked.
     * @param publishers and array of publiserids (Integer) of publishers to revoke the certificate in.
     * @ejb.interface-method
     */
    public void revokeCertificate(Admin admin, Certificate cert, Collection publishers, int reason) {
        if (cert instanceof X509Certificate) {
            setRevokeStatus(admin, ((X509Certificate) cert).getIssuerDN().toString(), ((X509Certificate) cert).getSerialNumber(), publishers, reason);
        }
    } //revokeCertificate

    /**
     * Method revoking all certificates generated by the specified issuerdn. Sets revokedate to current time.
     * Should only be called by CAAdminBean when a CA is about to be revoked.
     *
     * @param admin    the administrator performing the event.
     * @param issuerdn the dn of CA about to be revoked
     * @param reason   the reason of revokation.
     * @ejb.interface-method
     */
    public void revokeAllCertByCA(Admin admin, String issuerdn, int reason) {
        Connection con = null;
        PreparedStatement ps = null;
        PreparedStatement ps2 = null;
        int temprevoked = 0;
        int revoked = 0;

        String bcdn = CertTools.stringToBCDNString(issuerdn);

        final String firstsqlstatement = "UPDATE CertificateData SET status=?" +
                " WHERE issuerDN=? AND status = ? ";
        final String secondsqlstatement = "UPDATE CertificateData SET status=?, revocationDate=?, revocationReason=?" +
                " WHERE issuerDN=? AND status <> ?";

        long currentdate = new Date().getTime();

        try {
            // First SQL statement, changing all temporaty revoked certificates to permanently revoked certificates
            con = getConnection();
            ps = con.prepareStatement(firstsqlstatement);
            ps.setInt(1, CertificateDataBean.CERT_REVOKED); // first statusfield
            ps.setString(2, bcdn); // issuerdn field
            ps.setInt(3, CertificateDataBean.CERT_TEMP_REVOKED); // second statusfield
            temprevoked = ps.executeUpdate();

            // Second SQL statement, revoking all non revoked certificates.
            ps2 = con.prepareStatement(secondsqlstatement);
            ps2.setInt(1, CertificateDataBean.CERT_REVOKED); // first statusfield
            ps2.setLong(2, currentdate); // revokedate field
            ps2.setInt(3, reason); // revokation reason
            ps2.setString(4, bcdn); // issuer dn
            ps2.setInt(5, CertificateDataBean.CERT_REVOKED); // second statusfield

            revoked = ps2.executeUpdate();

            getLogSession().log(admin, bcdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_REVOKEDCERT, ("Revoked All CAs certificates successfully. Permantly revoked :" + (revoked + temprevoked) + " Certificates with reason: " + reason));
        } catch (Exception e) {
            getLogSession().log(admin, bcdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_REVOKEDCERT, "Error when trying to revoke a CA's all certificates", e);
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, null);
            JDBCUtil.close(ps2);
        }
    } // revokeAllCertByCA

    /**
     * Method that checks if a users all certificates have been revoked.
     *
     * @param admin    Administrator performing the operation
     * @param username the username to check for.
     * @return returns true if all certificates are revoked.
     * @ejb.interface-method
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
                    if (rev.getStatus() != CertificateDataBean.CERT_REVOKED) {
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
     * The method returns the revocation status for a list or certificate identified
     * by the serialnumber.
     *
     * @param admin
     * @param issuer the subjectDN of a CA certificate
     * @param sernos a collection of certificate serialnumbers
     * @return Collection a collection of {@link RevokedCertInfo} objects which
     *         reflect the revocation status of the given certificates.
     * @ejb.interface-method
     */
    public Collection isRevoked(Admin admin, String issuerDN, Collection sernos) {
        if (log.isDebugEnabled()) {
            debug(">isRevoked(), dn:" + issuerDN + ", no of sernos=" + sernos.size());
        }
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        ArrayList vect = null;

        if (null == admin
                || null == issuerDN || issuerDN.length() <= 0
                || null == sernos) {
            throw new IllegalArgumentException();
        }

        if (sernos.isEmpty()) {
            return new ArrayList();
        }

        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        try {
            final StringBuffer sb = new StringBuffer();

            /*
             * tmeckel:
             * why commented out refer to 'findCertificateByIssuerAndSernos'
            CollectionUtils.forAllDo(sernos, new Closure() {
                                                public void execute(Object input) {
                                                    if (null != input) {
                                                        sb.append(", ");
                                                        sb.append(input.toString());
                                                    }
                                                }} );
            */
            {
                Iterator iter = sernos.iterator();
                while (iter.hasNext()) {
                    sb.append(", '");
// Make sure this is really a BigInteger passed in as (untrusted param)
                    BigInteger serno = (BigInteger) iter.next();
                    sb.append(serno.toString());
                    sb.append("'");
                }
            }
            /*
             * to save the repeating if-statement in the above
             * Closure not to add ', ' as the first characters
             * in the StringBuffer we remove the two chars here :)
             */
            sb.delete(0, ", ".length());
            con = getConnection();
            ps = con.prepareStatement("SELECT DISTINCT serialNumber, revocationDate, revocationReason, status"
                    + " FROM CertificateData WHERE"
                    + " issuerDN = '" + dn + "'"
                    + " AND serialNumber IN (" + sb.toString() + ")");
            result = ps.executeQuery();

            vect = new ArrayList();
            while (result.next()) {
                RevokedCertInfo info = new RevokedCertInfo(new BigInteger(result.getBytes(1)), new Date(result.getLong(2)), result.getInt(3));
                // Backwards compatibility, handle databases that did not have NOT_REVOKED
                if (result.getInt(4) != CertificateDataBean.CERT_REVOKED) {
                    info.setReason(RevokedCertInfo.NOT_REVOKED);
                }
                vect.add(info);
            }

        } catch (Exception e) {
            error("Unable to load revoked certificates for issuer '"
                    + issuerDN
                    + "'"
                    , e);
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
        debug("<isRevoked()");
        return vect;
    } // isRevoked

    /**
     * Checks if a certificate is revoked.
     *
     * @param admin    Administrator performing the operation
     * @param issuerDN the DN of the issuer.
     * @param serno    the serialnumber of the certificate that will be checked
     * @return RevokedCertInfo with revocation information, with reason RevokedCertInfo.NOT_REVOKED if NOT revoked. Returns null if certificate is not found.
     * @ejb.interface-method
     */
    public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno) {
        if (log.isDebugEnabled()) {
            debug(">isRevoked(), dn:" + issuerDN + ", serno=" + serno);
        }
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);

        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            if (coll != null) {
                if (coll.size() > 1)
                    getLogSession().log(admin, issuerDN.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_DATABASE, "Error in database, more than one certificate has the same Issuer : " + issuerDN + " and serialnumber "
                            + serno.toString(16) + ".");
                Iterator iter = coll.iterator();
                if (iter.hasNext()) {
                    RevokedCertInfo revinfo = null;
                    CertificateDataLocal data = (CertificateDataLocal) iter.next();
                    revinfo = new RevokedCertInfo(serno, new Date(data.getRevocationDate()), data.getRevocationReason());
                    // Make sure we have it as NOT revoked if it isn't
                    if (data.getStatus() != CertificateDataBean.CERT_REVOKED) {
                        revinfo.setReason(RevokedCertInfo.NOT_REVOKED);
                    }
                    debug("<isRevoked() returned " + ((data.getStatus() == CertificateDataBean.CERT_REVOKED) ? "yes" : "no"));
                    return revinfo;
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        return null;
    } //isRevoked

    /**
     * Retrieves the latest CRL issued by this CA.
     *
     * @param admin Administrator performing the operation
     * @return X509CRL or null of no CRLs have been issued.
     * @ejb.interface-method
     */
    public byte[] getLastCRL(Admin admin, String issuerdn) {
        debug(">getLastCRL(" + issuerdn + ")");

        try {
            int maxnumber = getLastCRLNumber(admin, issuerdn);
            X509CRL crl = null;
            try {
                CRLDataLocal data = crlHome.findByIssuerDNAndCRLNumber(issuerdn, maxnumber);
                crl = data.getCRL();
            } catch (FinderException e) {
                crl = null;
            }
            debug("<getLastCRL()");
            if (crl == null)
                return null;

            getLogSession().log(admin, crl.getIssuerDN().toString().hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_GETLASTCRL, "Number :" + maxnumber);
            return crl.getEncoded();
        } catch (Exception e) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_GETLASTCRL, "Error retrieving last crl.");
            throw new EJBException(e);
        }
    } //getLastCRL

    /**
     * Retrieves the information about the lastest CRL issued by this CA.
     *
     * @param admin Administrator performing the operation
     * @return CRLInfo of last CRL by CA.
     * @ejb.interface-method
     */
    public CRLInfo getLastCRLInfo(Admin admin, String issuerdn) {
        debug(">getLastCRLInfo(" + issuerdn + ")");
        try {
            int maxnumber = getLastCRLNumber(admin, issuerdn);
            CRLInfo crlinfo = null;
            try {
                CRLDataLocal data = crlHome.findByIssuerDNAndCRLNumber(issuerdn, maxnumber);
                crlinfo = new CRLInfo(data.getIssuerDN(), maxnumber, data.getThisUpdate(), data.getNextUpdate());
            } catch (FinderException e) {
                crlinfo = null;
            }
            debug("<getLastCRLInfo()");
            if (crlinfo == null)
                return null;

            return crlinfo;
        } catch (Exception e) {
            getLogSession().log(admin, issuerdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_GETLASTCRL, "Error retrieving crl info.");
            throw new EJBException(e);
        }
    } //getLastCRL

    /**
     * Retrieves the highest CRLNumber issued by the CA.
     *
     * @param admin    Administrator performing the operation
     * @param issuerdn the subjectDN of a CA certificate
     * @ejb.interface-method
     */
    public int getLastCRLNumber(Admin admin, String issuerdn) {
        debug(">getLastCRLNumber(" + issuerdn + ")");

        Connection con = null;
        PreparedStatement ps = null;
        ;
        ResultSet result = null;
        try {
            con = getConnection();
            ps = con.prepareStatement("select MAX(CRLNumber) from CRLData where issuerDN=?");
            ps.setString(1, issuerdn);
            result = ps.executeQuery();

            int maxnumber = 0;
            if (result.next())
                maxnumber = result.getInt(1);
            debug("<getLastCRLNumber(" + maxnumber + ")");

            return maxnumber;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, result);
        }
    } //getLastCRLNumber

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin                  administrator performing the task
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile     the profile to be added
     * @ejb.interface-method
     */
    public void addCertificateProfile(Admin admin, String certificateprofilename,
                                      CertificateProfile certificateprofile) throws CertificateProfileExistsException {
        addCertificateProfile(admin, findFreeCertificateProfileId(), certificateprofilename, certificateprofile);
    } // addCertificateProfile

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin                  administrator performing the task
     * @param certificateprofileid   internal ID of new certificate profile, use only if you know it's right.
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile     the profile to be added
     * @ejb.interface-method
     */
    public void addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename,
                                      CertificateProfile certificateprofile) throws CertificateProfileExistsException {
        boolean returnval = false;

        if (isCertificateProfileNameFixed(certificateprofilename)) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error adding certificaterprofile " + certificateprofilename);
            throw new CertificateProfileExistsException();
        }

        if (isFreeCertificateProfileId(certificateprofileid)) {
            try {
                certprofilehome.findByCertificateProfileName(certificateprofilename);
                throw new CertificateProfileExistsException("Certificate Profile Name already exists.");
            } catch (FinderException e) {
                try {
                    certprofilehome.create(new Integer(certificateprofileid), certificateprofilename,
                            certificateprofile);
                    getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_CERTPROFILE, "New certificateprofile " + certificateprofilename + " added successfully");
                } catch (Exception f) {
                    getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error when creating new certificateprofile " + certificateprofilename);
                }
            }
        }
    } // addCertificateProfile

    /**
     * Adds a certificateprofile  with the same content as the original certificateprofile,
     *
     * @param admin                          Administrator performing the operation
     * @param originalcertificateprofilename readable name of old certificate profile
     * @param newcertificateprofilename      readable name of new certificate profile
     * @ejb.interface-method
     */
    public void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException {
        CertificateProfile certificateprofile = null;

        if (isCertificateProfileNameFixed(newcertificateprofilename)) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error adding certificaterprofile " + newcertificateprofilename + " using profile " + originalcertificateprofilename + " as template.");
            throw new CertificateProfileExistsException();
        }

        try {
            certificateprofile = (CertificateProfile) getCertificateProfile(admin, originalcertificateprofilename).clone();

            boolean issuperadministrator = false;
            try {
                issuperadministrator = getAuthorizationSession().isAuthorizedNoLog(admin, "/super_administrator");
            } catch (AuthorizationDeniedException ade) {
            }

            if (!issuperadministrator && certificateprofile.isApplicableToAnyCA()) {
                // Not superadministrator, do not use ANYCA;
                Collection authcas = getAuthorizationSession().getAuthorizedCAIds(admin);
                certificateprofile.setAvailableCAs(authcas);
            }

            try {
                certprofilehome.findByCertificateProfileName(newcertificateprofilename);
                getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error adding certificaterprofile " + newcertificateprofilename + " using profile " + originalcertificateprofilename + " as template.");
                throw new CertificateProfileExistsException();
            } catch (FinderException e) {
                try {
                    certprofilehome.create(new Integer(findFreeCertificateProfileId()), newcertificateprofilename, certificateprofile);
                    getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_CERTPROFILE, "New certificateprofile " + newcertificateprofilename + " used profile " + originalcertificateprofilename + " as template.");
                } catch (CreateException f) {
                }
            }
        } catch (CloneNotSupportedException f) {
        }

    } // cloneCertificateProfile

    /**
     * Removes a certificateprofile from the database.
     *
     * @param admin Administrator performing the operation
     * @ejb.interface-method
     */
    public void removeCertificateProfile(Admin admin, String certificateprofilename) {
        try {
            CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(certificateprofilename);
            pdl.remove();
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_CERTPROFILE, "Removed certificateprofile " + certificateprofilename + ".");
        } catch (Exception e) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error removing certificateprofile " + certificateprofilename + ".");
        }
    } // removeCertificateProfile

    /**
     * Renames a certificateprofile
     *
     * @ejb.interface-method
     */
    public void renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException {
        if (isCertificateProfileNameFixed(oldcertificateprofilename) || isCertificateProfileNameFixed(newcertificateprofilename)) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error renaming certificateprofile " + oldcertificateprofilename + " to " + newcertificateprofilename + ".");
            throw new CertificateProfileExistsException("Cannot rename fixed profiles.");
        }

        try {
            certprofilehome.findByCertificateProfileName(newcertificateprofilename);
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error renaming certificateprofile " + oldcertificateprofilename + " to " + newcertificateprofilename + ".");
            throw new CertificateProfileExistsException();
        } catch (FinderException e) {
            try {
                CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(oldcertificateprofilename);
                pdl.setCertificateProfileName(newcertificateprofilename);
                getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_CERTPROFILE, "Renamed certificateprofile " + oldcertificateprofilename + " to " + newcertificateprofilename + ".");
            } catch (FinderException f) {
                getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, "Error renaming certificateprofile " + oldcertificateprofilename + " to " + newcertificateprofilename + ".");
            }
        }
    } // renameCertificateProfile

    /**
     * Updates certificateprofile data
     *
     * @param admin Administrator performing the operation
     * @ejb.interface-method
     */
    public void changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile) {
        try {
            CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(certificateprofilename);
            pdl.setCertificateProfile(certificateprofile);
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_CERTPROFILE, "Certificateprofile " + certificateprofilename + " edited.");
        } catch (FinderException e) {
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_CERTPROFILE, " Error editing certificateprofile " + certificateprofilename + ".");
        }
    }// changeCertificateProfile

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     *
     * @param certprofiletype should be either CertificateDataBean.CERTTYPE_ENDENTITY, CertificateDataBean.CERTTYPE_SUBCA, CertificateDataBean.CERTTYPE_ROOTCA,
     *                        CertificateDataBean.CERTTYPE_HARDTOKEN (i.e EndEntity certificates and Hardtoken fixed profiles) or 0 for all.
     *                        Retrives certificate profile names sorted.
     * @return Collection of id:s (Integer)
     * @ejb.interface-method
     */
    public Collection getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype) {
        ArrayList returnval = new ArrayList();
        Collection result = null;

        HashSet authorizedcaids = new HashSet(getAuthorizationSession().getAuthorizedCAIds(admin));

        // Add fixed certificate profiles.
        if (certprofiletype == 0 || certprofiletype == CertificateDataBean.CERTTYPE_ENDENTITY || certprofiletype == CertificateDataBean.CERTTYPE_HARDTOKEN)
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER));
        if (certprofiletype == 0 || certprofiletype == CertificateDataBean.CERTTYPE_SUBCA)
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_SUBCA));
        if (certprofiletype == 0 || certprofiletype == CertificateDataBean.CERTTYPE_ROOTCA)
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA));

        if (certprofiletype == 0 || certprofiletype == CertificateDataBean.CERTTYPE_HARDTOKEN) {
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENENC));
            returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN));
        }

        try {
            result = certprofilehome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext()) {
                CertificateProfileDataLocal next = (CertificateProfileDataLocal) i.next();
                CertificateProfile profile = next.getCertificateProfile();
                // Check if all profiles available CAs exists in authorizedcaids.
                if (certprofiletype == 0 || certprofiletype == profile.getType()
                        || (profile.getType() == CertificateDataBean.CERTTYPE_ENDENTITY &&
                        certprofiletype == CertificateDataBean.CERTTYPE_HARDTOKEN)) {
                    Iterator availablecas = profile.getAvailableCAs().iterator();
                    boolean allexists = true;
                    while (availablecas.hasNext()) {
                        Integer nextcaid = (Integer) availablecas.next();
                        if (nextcaid.intValue() == CertificateProfile.ANYCA) {
                            allexists = true;
                            break;
                        }

                        if (!authorizedcaids.contains(nextcaid)) {
                            allexists = false;
                            break;
                        }
                    }

                    if (allexists)
                        returnval.add(next.getId());
                }
            }
        } catch (FinderException e) {
        }
        return returnval;
    } // getAuthorizedCertificateProfileNames


    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name (String).
     *
     * @param admin Administrator performing the operation
     * @ejb.interface-method
     */
    public HashMap getCertificateProfileIdToNameMap(Admin admin) {
        HashMap returnval = new HashMap();
        Collection result = null;
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER),
                EndUserCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_SUBCA),
                CACertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA),
                RootCACertificateProfile.CERTIFICATEPROFILENAME);

        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH),
                HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC),
                HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENENC),
                HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME);
        returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN),
                HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME);


        try {
            result = certprofilehome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext()) {
                CertificateProfileDataLocal next = (CertificateProfileDataLocal) i.next();
                returnval.put(next.getId(), next.getCertificateProfileName());
            }
        } catch (FinderException e) {
        }
        return returnval;
    } // getCertificateProfileIdToNameMap


    /**
     * Retrives a named certificate profile.
     *
     * @ejb.interface-method
     */
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename) {
        CertificateProfile returnval = null;

        if (certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME))
            return new EndUserCertificateProfile();

        if (certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME))
            return new CACertificateProfile();

        if (certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME))
            return new RootCACertificateProfile();

        if (certificateprofilename.equals(HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME))
            return new HardTokenAuthCertificateProfile();

        if (certificateprofilename.equals(HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME))
            return new HardTokenAuthEncCertificateProfile();

        if (certificateprofilename.equals(HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME))
            return new HardTokenEncCertificateProfile();

        if (certificateprofilename.equals(HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME))
            return new HardTokenSignCertificateProfile();


        try {
            returnval = (certprofilehome.findByCertificateProfileName(certificateprofilename)).getCertificateProfile();
        } catch (FinderException e) {
            // return null if we cant find it
        }
        return returnval;
    } //  getCertificateProfile

    /**
     * Finds a certificate profile by id.
     *
     * @param admin Administrator performing the operation
     * @ejb.interface-method
     */
    public CertificateProfile getCertificateProfile(Admin admin, int id) {
        CertificateProfile returnval = null;

        if (id < SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            switch (id) {
                case SecConst.CERTPROFILE_FIXED_ENDUSER:
                    returnval = new EndUserCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_SUBCA:
                    returnval = new CACertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_ROOTCA:
                    returnval = new RootCACertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH:
                    returnval = new HardTokenAuthCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC:
                    returnval = new HardTokenAuthEncCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENENC:
                    returnval = new HardTokenEncCertificateProfile();
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN:
                    returnval = new HardTokenSignCertificateProfile();
                    break;
                default:
                    returnval = new EndUserCertificateProfile();
            }
        } else {
            try {
                returnval = (certprofilehome.findByPrimaryKey(new Integer(id))).getCertificateProfile();
            } catch (FinderException e) {
                // return null if we cant find it
            }
        }
        return returnval;
    } // getCertificateProfile


    /**
     * Returns a certificate profile id, given it's certificate profile name
     *
     * @param admin Administrator performing the operation
     * @return the id or 0 if certificateprofile cannot be found.
     * @ejb.interface-method
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename) {
        int returnval = 0;

        if (certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME))
            return SecConst.CERTPROFILE_FIXED_ENDUSER;

        if (certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME))
            return SecConst.CERTPROFILE_FIXED_SUBCA;

        if (certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME))
            return SecConst.CERTPROFILE_FIXED_ROOTCA;

        if (certificateprofilename.equals(HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME))
            return SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH;

        if (certificateprofilename.equals(HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME))
            return SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC;

        if (certificateprofilename.equals(HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME))
            return SecConst.CERTPROFILE_FIXED_HARDTOKENENC;

        if (certificateprofilename.equals(HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME))
            return SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN;

        try {
            Integer id = (certprofilehome.findByCertificateProfileName(certificateprofilename)).getId();
            returnval = id.intValue();
        } catch (FinderException e) {
        }

        return returnval;
    } // getCertificateProfileId

    /**
     * Returns a certificateprofiles name given it's id.
     *
     * @param admin Administrator performing the operation
     * @return certificateprofilename or null if certificateprofile id doesn't exists.
     * @ejb.interface-method
     */
    public String getCertificateProfileName(Admin admin, int id) {
        String returnval = null;

        // Is id a fixed profile
        if (id < SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY) {
            switch (id) {
                case SecConst.CERTPROFILE_FIXED_ENDUSER:
                    returnval = EndUserCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_SUBCA:
                    returnval = CACertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_ROOTCA:
                    returnval = RootCACertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH:
                    returnval = HardTokenAuthCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC:
                    returnval = HardTokenAuthEncCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENENC:
                    returnval = HardTokenEncCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                case SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN:
                    returnval = HardTokenSignCertificateProfile.CERTIFICATEPROFILENAME;
                    break;
                default:
                    returnval = EndUserCertificateProfile.CERTIFICATEPROFILENAME;


            }
        } else {
            try {
                returnval = (certprofilehome.findByPrimaryKey(new Integer(id))).getCertificateProfileName();
            } catch (FinderException e) {
            }
        }

        return returnval;

    } // getCertificateProfileName

    /**
     * Method to check if a CA exists in any of the certificate profiles. Used to avoid desyncronization of CA data.
     *
     * @param admin Administrator performing the operation
     * @param caid  the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     * @ejb.interface-method
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid) {
        Iterator availablecas = null;
        boolean exists = false;
        try {
            Collection result = certprofilehome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext() && !exists) {
                availablecas = ((CertificateProfileDataLocal) i.next()).getCertificateProfile().getAvailableCAs().iterator();
                while (availablecas.hasNext()) {
                    if (((Integer) availablecas.next()).intValue() == caid) {
                        exists = true;
                        break;
                    }
                }
            }
        } catch (FinderException e) {
        }

        return exists;
    } // existsCAInCertificateProfiles

    /**
     * Method to check if a Publisher exists in any of the certificate profiles. Used to avoid desyncronization of publisher data.
     *
     * @param publisherid the publisherid to search for.
     * @return true if publisher exists in any of the certificate profiles.
     * @ejb.interface-method
     */
    public boolean existsPublisherInCertificateProfiles(Admin admin, int publisherid) {
        Iterator availablepublishers = null;
        boolean exists = false;
        try {
            Collection result = certprofilehome.findAll();
            Iterator i = result.iterator();
            while (i.hasNext() && !exists) {
                availablepublishers = ((CertificateProfileDataLocal) i.next()).getCertificateProfile().getPublisherList().iterator();
                while (availablepublishers.hasNext()) {
                    if (((Integer) availablepublishers.next()).intValue() == publisherid) {
                        exists = true;
                        break;
                    }
                }
            }
        } catch (FinderException e) {
        }

        return exists;
    } // existsPublisherInCertificateProfiles

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


    private boolean isCertificateProfileNameFixed(String certificateprofilename) {
        boolean returnval = false;

        if (certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME))
            return true;

        if (certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME))
            return true;

        if (certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME))
            return true;

        return returnval;
    }

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

} // CertificateStoreSessionBean
