
package se.anatom.ejbca.ca.store;

import java.rmi.*;
import java.io.*;
import java.math.BigInteger;

import java.sql.*;
import javax.sql.DataSource;
import java.util.Vector;
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
 * @version $Id: LocalCertificateStoreSessionBean.java,v 1.4 2002-01-08 11:25:24 anatom Exp $
 */
public class LocalCertificateStoreSessionBean extends BaseSessionBean implements ICertificateStoreSession {

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        debug("<ejbCreate()");
    }

   /**
    * Implements ICertificateStoreSession::storeCertificate.
    * Implements a mechanism that uses Certificate Entity Bean.
    */
    public boolean storeCertificate(Certificate incert, String cafp, int status, int type) throws RemoteException {
        debug(">storeCertificate("+cafp+", "+status+", "+type+")");

        try {
            CertificateDataHome home = (CertificateDataHome) lookup("CertificateData", CertificateDataHome.class);

            X509Certificate cert = (X509Certificate)incert;
            CertificateDataPK pk = new CertificateDataPK();
            pk.fp = CertTools.getFingerprintAsString(cert);
            info("Storing cert with fp="+pk.fp);

            CertificateData data1=null;
            data1 = home.create(cert);
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
    public boolean storeCRL(byte[] incrl, String cafp, int number) throws RemoteException {
        debug(">storeCRL("+cafp+", "+number+")");

        try {
            CRLDataHome home = (CRLDataHome) lookup("CRLData", CRLDataHome.class);
            X509CRL crl = CertTools.getCRLfromByteArray(incrl);
            CRLData data1 = home.create(crl, number);
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

    private Connection getConnection() throws SQLException, NamingException {
           DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
           return ds.getConnection();
    } //getConnection

   /**
    * Implements ICertificateStoreSession::listAlLCertificates.
    * Uses select directly from datasource.
    */
    public String[] listAllCertificates() throws RemoteException {
        debug(">listAllCertificates()");

        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            con = getConnection();
            ps = con.prepareStatement("select fp from CertificateData ORDER BY expireDate DESC");
            result = ps.executeQuery();
            Vector vect = new Vector();
            while(result.next()){
                vect.addElement(result.getString(1));
            }
            String[] returnArray = new String[vect.size()];
            vect.copyInto(returnArray);
            debug("<listAllCertificates()");
            return returnArray;
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
    public String[] listRevokedCertificates() throws RemoteException {
        debug(">listRevokedCertificates()");
        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            // TODO:
            // This should only list a few thousend certificates at a time, ni case there
            // are really many revoked certificates after some time...
            con = getConnection();
            ps = con.prepareStatement("select fp from CertificateData where status=? ORDER BY expireDate DESC");
            ps.setInt(1, CertificateData.CERT_REVOKED);
            result = ps.executeQuery();
            Vector vect = new Vector();
            while(result.next()){
                vect.addElement(result.getString(1));
            }
            String[] returnArray = new String[vect.size()];
            vect.copyInto(returnArray);
            debug("<listRevokedCertificates()");
            return returnArray;
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
    * Uses select directly from datasource.
    */
    public Certificate[] findCertificatesBySubject(String subjectDN) {
        debug(">findCertificatesBySubject(), dn="+subjectDN);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(subjectDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        try{
            con = getConnection();
            ps = con.prepareStatement("select b64cert from CertificateData where subjectDN=? ORDER BY expireDate DESC");
            ps.setString(1,dn);
            result = ps.executeQuery();
            Vector vect = new Vector();
            while(result.next()){
                vect.addElement(CertTools.getCertfromByteArray(Base64.decode(result.getString(1).getBytes())));
            }
            debug("found "+vect.size()+" certificate(s) with DN="+dn);
            X509Certificate[] returnArray = new X509Certificate[vect.size()];
            vect.copyInto(returnArray);
            debug("<findCertificatesBySubject()");
            return returnArray;
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

    } //findCertificatesBySubject

   /**
    * Implements ICertificateStoreSession::findCertificateByIssuerAndSerno.
    * Uses select directly from datasource.
    */
    public Certificate findCertificateByIssuerAndSerno(String issuerDN, BigInteger serno) throws RemoteException {
        debug(">findCertificateByIssuerAndSerno(), dn:"+issuerDN+", serno="+serno);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        try{
            con = getConnection();
            ps = con.prepareStatement("select b64cert from CertificateData where issuerDN=? and serno=?");
            ps.setString(1,dn);
            ps.setString(2, serno.toString());
            result = ps.executeQuery();
            Certificate cert = null;
            if (result.next()) {
                cert = CertTools.getCertfromByteArray(Base64.decode(result.getString(1).getBytes()));
                debug("Found cert with serno "+serno.toString()+".");
            } 

            debug("<findCertificateByIssuerAndSerno()");
            return cert;
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
    } //findCertificateByIssuerAndSerno

   /**
    * Implements ICertificateStoreSession::isRevoked.
    * Uses select directly from datasource.
    */
    public RevokedCertInfo isRevoked(String issuerDN, BigInteger serno) throws RemoteException {
        debug(">isRevoked(), dn:"+issuerDN+", serno="+serno);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        Connection con = null;
        PreparedStatement ps = null;
        ResultSet result = null;
        String fp = null;
        try{
            con = getConnection();
            ps = con.prepareStatement("select fp from CertificateData where issuerDN=? and serno=?");
            ps.setString(1,dn);
            ps.setString(2, serno.toString());
            result = ps.executeQuery();
            if (result.next()) {
                fp = result.getString(1);
                debug("Found cert with fingerprint "+fp+".");
            } else {
                throw new Exception("Cannot find certificate with issuer '"+dn+"' and serno '"+serno.toString()+"'.");
            } 
        } catch (Exception e) {
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
        try{
            CertificateDataHome home = (CertificateDataHome)lookup("CertificateData", CertificateDataHome.class);
            CertificateDataPK pk = new CertificateDataPK();
            pk.fp = fp;
            CertificateData data = home.findByPrimaryKey(pk);
            RevokedCertInfo revinfo = null;
            if (data.getStatus() == CertificateData.CERT_REVOKED) {
                revinfo = new RevokedCertInfo(serno, data.getRevocationDate(), data.getRevocationReason());
            }
            debug("<isRevoked() returned "+((data.getStatus() == CertificateData.CERT_REVOKED)?"yes":"no"));
            return revinfo;
        } catch (Exception e) {
            throw new EJBException(e);
        }
    } //isRevoked
    
   /**
    * Implements ICertificateStoreSession::getLastCRL.
    * Uses select directly from datasource.
    */
    public byte[] getLastCRL() {
        debug(">findLatestCRL()");
        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            con = getConnection();
            ps = con.prepareStatement("select MAX(CRLNumber) from CRLData");
            result = ps.executeQuery();
            int maxnumber = -1;
            if (result.next())
                maxnumber = result.getInt(1);
            if (maxnumber == -1)
            {
                debug("No CRLs issued yet");
                return null;
            }
            ps = con.prepareStatement("select b64crl from CRLData where CRLNumber=?");
            ps.setInt(1, maxnumber);
            result = ps.executeQuery();
            X509CRL crl = null;
            if (result.next()) {
                String b64crl = result.getString(1);
                crl = CertTools.getCRLfromByteArray(Base64.decode(b64crl.getBytes()));
            }
            debug("<findLatestCRL()");
            return crl.getEncoded();
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
