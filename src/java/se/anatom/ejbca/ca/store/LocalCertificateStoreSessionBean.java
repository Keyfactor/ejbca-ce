package se.anatom.ejbca.ca.store;

import java.rmi.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;
import java.util.Collection;
import java.util.Iterator;
import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.X509CRL;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Base64;

/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalCertificateStoreSessionBean.java,v 1.20 2002-07-09 15:04:22 anatom Exp $
 */
public class LocalCertificateStoreSessionBean extends BaseSessionBean {

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** The home interface of Certificate entity bean */
    private CertificateDataLocalHome certHome = null;

    /** The home interface of CRL entity bean */
    private CRLDataLocalHome crlHome = null;

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        crlHome = (CRLDataLocalHome)lookup("java:comp/env/ejb/CRLDataLocal");
        certHome = (CertificateDataLocalHome)lookup("java:comp/env/ejb/CertificateDataLocal");
        debug("<ejbCreate()");
    }

    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection

    /**
     * Implements ICertificateStoreSession::storeCertificate.
     * Implements a mechanism that uses Certificate Entity Bean.
     */
    public boolean storeCertificate(Certificate incert, String cafp, int status, int type) {
        debug(">storeCertificate("+cafp+", "+status+", "+type+")");
        try {
            X509Certificate cert = (X509Certificate)incert;
            CertificateDataPK pk = new CertificateDataPK();
            pk.fingerprint = CertTools.getFingerprintAsString(cert);
            info("Storing cert with fp="+pk.fingerprint);
            CertificateDataLocal data1=null;
            data1 = certHome.create(cert);
            data1.setCAFingerprint(cafp);
            data1.setStatus(status);
            data1.setType(type);
        }
        catch (Exception e) {
            error("Storage of cert failed.", e);
            throw new EJBException(e);
        }
        debug("<storeCertificate()");
        return true;
    } // storeCertificate

    /**
     * Implements ICertificateStoreSession::storeCRL.
     * Implements a mechanism that uses CRL Entity Bean.
     */
    public boolean storeCRL(byte[] incrl, String cafp, int number) {
        debug(">storeCRL("+cafp+", "+number+")");
        try {
            X509CRL crl = CertTools.getCRLfromByteArray(incrl);
            CRLDataLocal data1 = crlHome.create(crl, number);
            data1.setCAFingerprint(cafp);
            info("Stored CRL with fp="+CertTools.getFingerprintAsString(crl));
        }
        catch (Exception e) {
            error("Storage of CRL failed.", e);
            throw new EJBException(e);
        }
        debug("<storeCRL()");
        return true;
    } // storeCRL

    /**
     * Implements ICertificateStoreSession::listAlLCertificates.
     * Uses select directly from datasource.
     */
    public Collection listAllCertificates() {
        debug(">listAllCertificates()");
        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            // TODO:
            // This should only list a few thousend certificates at a time, in case there
            con = getConnection();
            ps = con.prepareStatement("select fingerprint from CertificateData ORDER BY expireDate DESC");
            result = ps.executeQuery();
            Vector vect = new Vector();
            while(result.next()){
                vect.addElement(result.getString(1));
            }
            debug("<listAllCertificates()");
            return vect;
        }
        catch (Exception e) {
            throw new EJBException(e);
        }
        finally {
            try {
                if (result != null) result.close();
                if (ps != null) ps.close();
                if (con!= null) con.close();
            } catch(SQLException se) {
                se.printStackTrace();
            }
        }
    } // listAllCertificates

    /**
     * Implements ICertificateStoreSession::listRevokedCertificates.
     * Uses select directly from datasource.
     */
    public Collection listRevokedCertificates() {
        debug(">listRevokedCertificates()");
        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            // TODO:
            // This should only list a few thousend certificates at a time, in case there
            // are really many revoked certificates after some time...
            con = getConnection();
            ps = con.prepareStatement("select fingerprint from CertificateData where status=? ORDER BY expireDate DESC");
            ps.setInt(1, CertificateData.CERT_REVOKED);
            result = ps.executeQuery();
            Vector vect = new Vector();
            while(result.next()) {
                vect.addElement(result.getString(1));
            }
            debug("<listRevokedCertificates()");
            return vect;
        }
        catch (Exception e) {
            throw new EJBException(e);
        }
        finally {
            try {
                if (result != null) result.close();
                if (ps != null) ps.close();
                if (con!= null) con.close();
            } catch(SQLException se) {
                se.printStackTrace();
            }
        }
    } // listRevokedCertificates

    /**
     * Implements ICertificateStoreSession::findCertificatesBySubject.
     */
    public Collection findCertificatesBySubject(String subjectDN) {
        debug(">findCertificatesBySubject(), dn='"+subjectDN+"'");
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(subjectDN);
        debug("Looking for cert with (transformed)DN: " + dn);
        try {
            Collection coll = certHome.findBySubjectDN(dn);
            Collection ret = new Vector();
            if (coll != null) {
                Iterator iter = coll.iterator();
                while (iter.hasNext()) {
                    ret.add( ((CertificateDataLocal)iter.next()).getCertificate() );
                }
            }
            debug("<findCertificatesBySubject(), dn='"+subjectDN+"'");
            return ret;
        } catch (javax.ejb.FinderException fe) {
            cat.error(fe);
            throw new EJBException(fe);
        }
    } //findCertificatesBySubject

    /** Finds certificate which expire within a specified time.
     * Implements ICertificateStoreSession::findCertificatesByExpireTime.
     */
    public Collection findCertificatesByExpireTime(Date expireTime) {
        debug(">findCertificatesByExpireTime(), time="+expireTime);
        // First make expiretime in well know format
        debug("Looking for certs that expire before: " + expireTime);
        try {
            Collection coll = certHome.findByExpireDate(expireTime.getTime());
            Collection ret = new Vector();
            if (coll != null) {
                Iterator iter = coll.iterator();
                while (iter.hasNext()) {
                    ret.add( ((CertificateDataLocal)iter.next()).getCertificate() );
                }
            }
            debug("<findCertificatesByExpireTime(), time="+expireTime);
            return ret;
        } catch (javax.ejb.FinderException fe) {
            cat.error(fe);
            throw new EJBException(fe);
        }
    } //findCertificatesByExpireTime

    /**
     * Implements ICertificateStoreSession::findCertificateByIssuerAndSerno.
     */
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno) {
        debug(">findCertificateByIssuerAndSerno(), dn:"+issuerDN+", serno="+serno);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);
        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            Certificate ret = null;
            if (coll != null) {
                if (coll.size() > 1)
                    cat.error("Error in database, more than one certificate has the same Issuer and SerialNumber!");
                Iterator iter = coll.iterator();
                if (iter.hasNext()) {
                    ret= ((CertificateDataLocal)iter.next()).getCertificate();
                }
            }
            debug("<findCertificateByIssuerAndSerno(), dn:"+issuerDN+", serno="+serno);
            return ret;
        } catch (javax.ejb.FinderException fe) {
            cat.error(fe);
            throw new EJBException(fe);
        }
    } //findCertificateByIssuerAndSerno

    /**
     * Implements ICertificateStoreSession::findCertificatesBySerno.
     */
    public Collection findCertificatesBySerno(BigInteger serno) {
        debug(">findCertificateBySerno(),  serno="+serno);
        try {
            Collection coll = certHome.findBySerialNumber(serno.toString());
            Vector ret = new Vector();
            if (coll != null) {
                Iterator iter = coll.iterator();
                while (iter.hasNext()) {
                    ret.addElement(((CertificateDataLocal)iter.next()).getCertificate());
                }
            }
            debug("<findCertificateBySerno(), serno="+serno);
            return ret;
        } catch (javax.ejb.FinderException fe) {
            cat.error(fe);
            throw new EJBException(fe);
        }
    } // findCertificateBySerno

    /**
     * Implements ICertificateStoreSession::isRevoked.
     * Uses select directly from datasource.
     */
    public RevokedCertInfo isRevoked(String issuerDN, BigInteger serno) {
        debug(">isRevoked(), dn:"+issuerDN+", serno="+serno);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);
        try{
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            Certificate ret = null;
            if (coll != null) {
                if (coll.size() > 1)
                    cat.error("Error in database, more than one certificate has the same Issuer and SerialNumber!");
                Iterator iter = coll.iterator();
                if (iter.hasNext()) {
                    RevokedCertInfo revinfo = null;
                    CertificateDataLocal data = (CertificateDataLocal)iter.next();
                    if (data.getStatus() == CertificateData.CERT_REVOKED) {
                        revinfo = new RevokedCertInfo(serno, new Date(data.getRevocationDate()), data.getRevocationReason());
                    }
                    debug("<isRevoked() returned "+((data.getStatus() == CertificateData.CERT_REVOKED)?"yes":"no"));
                    return revinfo;
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        return null;
    } //isRevoked

    /**
     * Implements ICertificateStoreSession::getLastCRL.
     * Uses select directly from datasource.
     */
    public byte[] getLastCRL() {
        debug(">findLatestCRL()");
        try {
            int maxnumber = getLastCRLNumber();
            X509CRL crl = null;
            try {
                CRLDataLocal data = crlHome.findByCRLNumber(maxnumber);
                crl = data.getCRL();
            } catch (FinderException e) {
                crl = null;
            }
            debug("<findLatestCRL()");
            if (crl == null)
                return null;
            return crl.getEncoded();
        }
        catch (Exception e) {
            throw new EJBException(e);
        }
    } //getLastCRL

    /**
     * Implements ICertificateStoreSession::getLastCRLNumber.
     * Uses select directly from datasource.
     */
    public int getLastCRLNumber() {
        debug(">getLastCRLNumber()");
        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            con = getConnection();
            ps = con.prepareStatement("select MAX(CRLNumber) from CRLData");
            result = ps.executeQuery();
            int maxnumber = 0;
            if (result.next())
                maxnumber = result.getInt(1);
            info("Last CRLNumber="+maxnumber);
            debug("<getLastCRLNumber()");
            return maxnumber;
        }
        catch (Exception e) {
            throw new EJBException(e);
        }
        finally {
            try {
                if (result != null) result.close();
                if (ps != null) ps.close();
                if (con!= null) con.close();
            } catch(SQLException se) {
                se.printStackTrace();
            }
        }
    } //getLastCRLNumber

} // CertificateStoreSessionBean
