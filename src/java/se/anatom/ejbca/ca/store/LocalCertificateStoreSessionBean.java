package se.anatom.ejbca.ca.store;

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

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.sql.DataSource;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.exception.CertificateProfileExistsException;
import se.anatom.ejbca.ca.store.certificateprofiles.CACertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.EndUserCertificateProfile;
import se.anatom.ejbca.ca.store.certificateprofiles.RootCACertificateProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.StringTools;


/**
 * Stores certificate and CRL in the local database using Certificate and CRL Entity Beans.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalCertificateStoreSessionBean.java,v 1.53 2003-10-03 14:34:20 herrvendil Exp $
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

    /** The local interface of the log session bean */
    private ILogSessionLocal logsession = null;

    /** The local interface of the authorization session bean */
    private IAuthorizationSessionLocal authorizationsession = null;
    

    
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        crlHome = (CRLDataLocalHome)lookup("java:comp/env/ejb/CRLDataLocal");
        certHome = (CertificateDataLocalHome)lookup("java:comp/env/ejb/CertificateDataLocal");
        certprofilehome = (CertificateProfileDataLocalHome)lookup("java:comp/env/ejb/CertificateProfileDataLocal");

        debug("<ejbCreate()");
    }

    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection
    
    
    /** Gets connection to log session bean
     */
    private ILogSessionLocal getLogSession() {
        if(logsession == null){
          try{
            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",ILogSessionLocalHome.class);
            logsession = logsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return logsession;
    } //getLogSession
    

    /** Gets connection to authorization session bean
     * @return Connection
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if(authorizationsession == null){
          try{
            IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) lookup("java:comp/env/ejb/AuthorizationSessionLocal",IAuthorizationSessionLocalHome.class);
            authorizationsession = authorizationsessionhome.create();
          }catch(Exception e){
             throw new EJBException(e);
          }
        }
        return authorizationsession;
    } //getAuthorizationSession    
    

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
            getLogSession().log(admin, cert, LogEntry.MODULE_CA, new java.util.Date(), username, (X509Certificate) incert, LogEntry.EVENT_INFO_STORECERTIFICATE,"");
            CertificateDataLocal data1=null;
            data1 = certHome.create(cert);
            data1.setUsername(username);
            data1.setCAFingerprint(cafp);
            data1.setStatus(status);
            data1.setType(type);
        }
        catch (Exception e) {            
           getLogSession().log(admin, (X509Certificate) incert, LogEntry.MODULE_CA, new java.util.Date(), username, (X509Certificate) incert, LogEntry.EVENT_ERROR_STORECERTIFICATE,"");
           throw new EJBException(e);
        }
        debug("<storeCertificate()");
        return true;
    } // storeCertificate

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
          getLogSession().log(admin, crl.getIssuerDN().toString().hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_STORECRL,"Number : " +  number + " Fingerprint : " + CertTools.getFingerprintAsString(crl) + ".");
        }
        catch (Exception e) {
          getLogSession().log(admin, ILogSessionLocal.INTERNALCAID, LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_STORECRL,"Number : " +  number +  ".");
          throw new EJBException(e);
        }
        debug("<storeCRL()");

        return true;
    } // storeCRL

    /**
     * Implements ICertificateStoreSession::listAlLCertificates. Uses select directly from
     * datasource.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection listAllCertificates(Admin admin, String issuerdn) {
        debug(">listAllCertificates()");
        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;

        try {
            con = getConnection();
            ps = con.prepareStatement("select fingerprint from CertificateData where issuerDN=? ORDER BY expireDate DESC");
            ps.setString(1, issuerdn);
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
                if (result != null) result.close();
                if (ps != null) ps.close();
                if (con!= null) con.close();
            } catch(SQLException se) {
                error("Error cleaning up: ", se);
            }
        }
    } // listAllCertificates

    /**
     * Implements ICertificateStoreSession::listRevokedCertificates. Uses select directly from
     * datasource.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection listRevokedCertificates(Admin admin, String issuerdn) {
        debug(">listRevokedCertificates()");

        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            // TODO:
            // This should only list a few thousend certificates at a time, in case there
            // are really many revoked certificates after some time...
            con = getConnection();
            ps = con.prepareStatement("select fingerprint from CertificateData where status=? and issuerDN=? ORDER BY expireDate DESC");
            ps.setInt(1, CertificateData.CERT_REVOKED);
            ps.setString(2, issuerdn);
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
    } // listRevokedCertificates

    /**
     * Implements ICertificateStoreSession::findCertificatesBySubject.
     *
     * @param admin DOCUMENT ME!
     * @param subjectDN DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findCertificatesBySubjectAndIssuer(Admin admin, String subjectDN, String issuer) {
        debug(">findCertificatesBySubjectAndIssuer(), dn='"+subjectDN+"' and issuer='"+issuer+"'");
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(subjectDN);
        String issuerdn = CertTools.stringToBCDNString(issuer);
        debug("Looking for cert with (transformed)DN: " + dn);

        try {
            Collection coll = certHome.findBySubjectDNAndIssuerDN(dn, issuerdn);
            Collection ret = new ArrayList();

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret.add( ((CertificateDataLocal)iter.next()).getCertificate() );
                }
            }
            debug("<findCertificatesBySubjectAndIssuer(), dn='"+subjectDN+"'");
            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    } //findCertificatesBySubject


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
        debug(">findCertificatesByExpireTime(), time="+expireTime);
        // First make expiretime in well know format
        debug("Looking for certs that expire before: " + expireTime);

        try {
            Collection coll = certHome.findByExpireDate(expireTime.getTime());
            Collection ret = new ArrayList();

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret.add( ((CertificateDataLocal)iter.next()).getCertificate() );
                }
            }
            debug("<findCertificatesByExpireTime(), time="+expireTime);
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
        PreparedStatement ps = null;;
        ResultSet result = null;
        ArrayList returnval = new ArrayList();
        long currentdate = new Date().getTime();

        try {
            con = getConnection();
            ps = con.prepareStatement(
				"SELECT DISTINCT username FROM CertificateData WHERE expireDate>=? AND expireDate<? AND status=?"); 
            ps.setLong(1,currentdate);
			ps.setLong(2,expiretime.getTime());
			ps.setInt(3,CertificateData.CERT_ACTIVE);
            result = ps.executeQuery();
            while(result.next() && returnval.size() <= SecConst.MAXIMUM_QUERY_ROWCOUNT +1){
                if(result.getString(1) != null && !result.getString(1).equals(""))
                  returnval.add(result.getString(1));
            }    
            debug("<findCertificatesByExpireTimeWithLimit()");
            return returnval;
        }
        catch (Exception e) {
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
    } //findCertificatesByExpireTimeWithLimit

    /**
     * Implements ICertificateStoreSession::findCertificateByIssuerAndSerno.
     *
     * @param admin DOCUMENT ME!
     * @param issuerDN DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */                           
    public Certificate findCertificateByIssuerAndSerno(Admin admin, String issuerDN, BigInteger serno) {
        debug(">findCertificateByIssuerAndSerno(), dn:"+issuerDN+", serno="+serno);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);
        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            Certificate ret = null;

            if (coll != null) {
                if (coll.size() > 1)
                  getLogSession().log(admin, issuerDN.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_DATABASE,"Error in database, more than one certificate has the same Issuer : " + issuerDN + " and serialnumber "
                                                                                                          + serno.toString(16) + ".");
                Iterator iter = coll.iterator();

                if (iter.hasNext()) {
                    ret= ((CertificateDataLocal)iter.next()).getCertificate();
                }
            }

            debug("<findCertificateByIssuerAndSerno(), dn:" + issuerDN + ", serno=" + serno);

            return ret;
        } catch (Exception fe) {
            throw new EJBException(fe);
        }
    } //findCertificateByIssuerAndSerno

    /**
     * Implements ICertificateStoreSession::findCertificatesBySerno.
     *
     * @param admin DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection findCertificatesBySerno(Admin admin, BigInteger serno) {
        debug(">findCertificateBySerno(),  serno="+serno);
        try {
            Collection coll = certHome.findBySerialNumber(serno.toString());
            ArrayList ret = new ArrayList();

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret.add(((CertificateDataLocal)iter.next()).getCertificate());
                }
            }

            debug("<findCertificateBySerno(), serno=" + serno);

            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    } // findCertificateBySerno

    /**
     * Implements ICertificateStoreSession::findUsernameByCertSerno.
     *
     * @param admin DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String findUsernameByCertSerno(Admin admin, BigInteger serno, String issuerdn){
        debug(">findUsernameByCertSerno(),  serno="+serno);
        String dn = CertTools.stringToBCDNString(issuerdn);
        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            String ret = null;

            if (coll != null) {
                Iterator iter = coll.iterator();

                while (iter.hasNext()) {
                    ret = ((CertificateDataLocal)iter.next()).getUsername();
                }
            }

            debug("<findUsernameByCertSerno(), serno=" + serno);

            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    } // findUsernameByCertSerno

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
                    ret.add(((CertificateDataLocal)iter.next()).getCertificate());
                }
            }

            debug("<findCertificateBySerno(), username="+username);
            return ret;
        } catch (javax.ejb.FinderException fe) {
            throw new EJBException(fe);
        }
    } // findCertificateByUsername

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
            log.error("Error finding certificate with fp: "+fingerprint);            
            throw new EJBException(fe);
        }
    } // findCertificateByFingerprint

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
       try{
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
              getLogSession().log(admin, certificate, LogEntry.MODULE_CA, new java.util.Date(), null, certificate, LogEntry.EVENT_INFO_REVOKEDCERT,("Reason :" + reason));
              
            }
          }
         }

       }catch(FinderException e){
          getLogSession().log(admin, admin.getCAId(),  LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_REVOKEDCERT,("Couldn't find certificate with username :" + username));

          throw new EJBException(e);
       }
    } // setRevokeStatus

    /**
     * Set the status of certificate of serno to revoked.
     *
     * @param admin DOCUMENT ME!
     * @param serno the serial number of the certificate to revoke.
     * @param reason reason the user is revoked from CRLData
     *
     * @see CRLData
     */
    public void setRevokeStatus(Admin admin, String issuerdn, BigInteger serno, int reason) {
       X509Certificate certificate = null;
       try{
         certificate = (X509Certificate) this.findCertificateByIssuerAndSerno(admin, issuerdn, serno);
          // Revoke all certs
         if (certificate != null) {
             CertificateDataPK revpk = new CertificateDataPK();
             revpk.fingerprint = CertTools.getFingerprintAsString(certificate);
             CertificateDataLocal rev = certHome.findByPrimaryKey(revpk);
             if (rev.getStatus() != CertificateData.CERT_REVOKED) {
              rev.setStatus(CertificateData.CERT_REVOKED);
              rev.setRevocationDate(new Date());
              rev.setRevocationReason(reason);
              
              getLogSession().log(admin, issuerdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, certificate, LogEntry.EVENT_INFO_REVOKEDCERT,("Reason :" + reason));

            }
         }

       }catch(FinderException e){          
          getLogSession().log(admin, issuerdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_REVOKEDCERT,("Couldn't find certificate with serno :" + serno));
          
          throw new EJBException(e);
       }
    } // setRevokeStatus

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
             setRevokeStatus(admin, ((X509Certificate)cert).getIssuerDN().toString(), ((X509Certificate)cert).getSerialNumber(), reason);
         }
     } //revokeCertificate
     
     /**
      * Method revoking all certificates generated by the specified issuerdn. Sets revokedate to current time.
      * Should only be called by CAAdminBean when a CA is about to be revoked.
      *  
      * @param admin the administrator performing the event.
      * @param issuerdn the dn of CA about to be revoked
      * @param reason the reason of revokation.
      * 
      */
     public void revokeAllCertByCA(Admin admin, String issuerdn, int reason){
		Connection con = null;
    	PreparedStatement ps = null;
		int temprevoked = 0;
		int revoked = 0;
		
		String bcdn = CertTools.stringToBCDNString(issuerdn);
     	
     	final String firstsqlstatement = "UPDATE CertificateData SET status=?" +                                                 " WHERE issuerDN=? AND status = ? ";
		final String secondsqlstatement = "UPDATE CertificateData SET status=?, revocationDate=?, revocationReason=?" +
												 " WHERE issuerDN=? AND status <> ?";
												 
		long currentdate = new Date().getTime();												 
        	
		try {
			// First SQL statement, changing all temporaty revoked certificates to permanently revoked certificates                			
			con = getConnection();
			ps = con.prepareStatement(firstsqlstatement);		  							  
			ps.setInt(1, CertificateData.CERT_REVOKED); // first statusfield
			ps.setString(2, bcdn); // issuerdn field
			ps.setInt(3, CertificateData.CERT_TEMP_REVOKED); // second statusfield
		    temprevoked = ps.executeUpdate();

            // Second SQL statement, revoking all non revoked certificates.
			ps = con.prepareStatement(secondsqlstatement);				
			ps.setInt(1, CertificateData.CERT_REVOKED); // first statusfield
			ps.setLong(2, currentdate); // revokedate field
			ps.setInt(3, reason); // revokation reason
			ps.setString(4, bcdn); // issuer dn
			ps.setInt(5, CertificateData.CERT_REVOKED); // second statusfield
			
			revoked = ps.executeUpdate();
			
			getLogSession().log(admin, bcdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_REVOKEDCERT,("Revoked All CAs certificates successfully. Permantly revoked :" + (revoked + temprevoked) + "Certificates with reason: " + reason));
		 } catch (Exception e) {
			 getLogSession().log(admin, bcdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_REVOKEDCERT,"Error when trying to revoke a CA's all certificates", e);		 	
			 throw new EJBException(e);
		 } finally {
			 try {				 
				 if (ps != null) ps.close();
				 if (con!= null) con.close();
			 } catch(SQLException se) {
				 error("Error cleaning up: ", se);
			 }
		 }                       		               
     } // revokeAllCertByCA

    /**
     *  Method that checks if a users all certificates have been revoked.
     *
     * @param admin DOCUMENT ME!
     * @param username the username to check for.
     *
     * @return returns true if all certificates are revoked.
     */
    public boolean checkIfAllRevoked(Admin admin, String username){
       boolean returnval = true;
       X509Certificate certificate = null;
       // Strip dangerous chars
       username = StringTools.strip(username);
       try{
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
                returnval=false;

            }
          }
         }

       }catch(FinderException e){
          throw new EJBException(e);
       }

       return returnval;
    }


    /**
     * Implements ICertificateStoreSession::isRevoked.
     *
     * @param admin DOCUMENT ME!
     * @param issuerDN DOCUMENT ME!
     * @param serno DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public RevokedCertInfo isRevoked(Admin admin, String issuerDN, BigInteger serno) {
        debug(">isRevoked(), dn:"+issuerDN+", serno="+serno);
        // First make a DN in our well-known format
        String dn = CertTools.stringToBCDNString(issuerDN);
        debug("Looking for cert with (transformed)DN: " + dn);

        try {
            Collection coll = certHome.findByIssuerDNSerialNumber(dn, serno.toString());
            if (coll != null) {
                if (coll.size() > 1)
                  getLogSession().log(admin, issuerDN.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_DATABASE,"Error in database, more than one certificate has the same Issuer : " + issuerDN + " and serialnumber "
                                                                                                          + serno.toString(16) + ".");
                Iterator iter = coll.iterator();
                if (iter.hasNext()) {
                    RevokedCertInfo revinfo = null;
                    CertificateDataLocal data = (CertificateDataLocal)iter.next();
                    revinfo = new RevokedCertInfo(serno, new Date(data.getRevocationDate()), data.getRevocationReason());
                    // Make sure we have it as NOT revoked if it isn't
                    if (data.getStatus() != CertificateData.CERT_REVOKED) {
                        revinfo.setReason(RevokedCertInfo.NOT_REVOKED);
                    }
                    debug("<isRevoked() returned " + ((data.getStatus() == CertificateData.CERT_REVOKED) ? "yes" : "no"));
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
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public byte[] getLastCRL(Admin admin, String issuerdn) {
        debug(">findLatestCRL()");

        try {
            int maxnumber = getLastCRLNumber(admin, issuerdn);
            X509CRL crl = null;
            try {
                CRLDataLocal data = crlHome.findByIssuerDNAndCRLNumber(issuerdn, maxnumber);
                crl = data.getCRL();
            } catch (FinderException e) {
                crl = null;
            }
            debug("<findLatestCRL()");
            if (crl == null)
                return null;

            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_INFO_GETLASTCRL,"Number :" + maxnumber);
            return crl.getEncoded();
        }
        catch (Exception e) {            
            getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_GETLASTCRL,"Error retrieving last crl.");            
            throw new EJBException(e);
        }
    } //getLastCRL

    /**
     * Implements ICertificateStoreSession::getLastCRLInfo.
     */
    public CRLInfo getLastCRLInfo(Admin admin, String issuerdn) {
        debug(">findLatestCRL()");
        try {
            int maxnumber = getLastCRLNumber(admin, issuerdn);
            CRLInfo crlinfo = null;
            try {
                CRLDataLocal data = crlHome.findByIssuerDNAndCRLNumber(issuerdn, maxnumber);
                crlinfo = new CRLInfo(data.getIssuerDN(), maxnumber, data.getThisUpdate(), data.getNextUpdate());
            } catch (FinderException e) {
                crlinfo = null;
            }
            debug("<findLatestCRL()");
            if (crlinfo == null)
                return null;
            
            return crlinfo;
        }
        catch (Exception e) {            
            getLogSession().log(admin, issuerdn.hashCode(), LogEntry.MODULE_CA, new java.util.Date(), null, null, LogEntry.EVENT_ERROR_GETLASTCRL,"Error retrieving crl info.");            
            throw new EJBException(e);
        }
    } //getLastCRL    
    
    /**
     * Implements ICertificateStoreSession::getLastCRLNumber.
     * Uses select directly from datasource.
     */
    public int getLastCRLNumber(Admin admin, String issuerdn) {
        debug(">getLastCRLNumber()");

        Connection con = null;
        PreparedStatement ps = null;;
        ResultSet result = null;
        try {
            con = getConnection();
            ps = con.prepareStatement("select MAX(CRLNumber) from CRLData where issuerDN=?");
            ps.setString(1,issuerdn);
            result = ps.executeQuery();

            int maxnumber = 0;
            if (result.next())
                maxnumber = result.getInt(1);
            debug("<getLastCRLNumber()");

            return maxnumber;
        }
        catch (Exception e) {
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
    } //getLastCRLNumber

    /**
     * Adds a certificate profile to the database.
     *
     * @param admin administrator performing the task
     * @param certificateprofilename readable name of new certificate profile
     * @param certificateprofile the profile to be added
     *
     * @return true if added succesfully, false if it already exist
     */
    public void addCertificateProfile(Admin admin, String certificateprofilename,
        CertificateProfile certificateprofile) throws CertificateProfileExistsException{
        addCertificateProfile(admin, findFreeCertificateProfileId(), certificateprofilename, certificateprofile);
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
    public void addCertificateProfile(Admin admin, int certificateprofileid, String certificateprofilename,
        CertificateProfile certificateprofile)throws CertificateProfileExistsException {
        boolean returnval = false;

		if(isCertificateProfileNameFixed(certificateprofilename)){
		  getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error adding certificaterprofile " + certificateprofilename);  
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
				  getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_CERTPROFILE,"New certificateprofile " + certificateprofilename +  " added successfully");                  
              } catch (Exception f) {
				 getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error when creating new certificateprofile " + certificateprofilename);
              }
           }
        }  
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
    public void cloneCertificateProfile(Admin admin, String originalcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException{
       CertificateProfile certificateprofile = null;
       
       if(isCertificateProfileNameFixed(newcertificateprofilename)){
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error adding certificaterprofile " + newcertificateprofilename +  " using profile " + originalcertificateprofilename + " as template.");  
         throw new CertificateProfileExistsException();  
       }
                            
       try{         
         certificateprofile = (CertificateProfile)  getCertificateProfile(admin, originalcertificateprofilename).clone();
         
          boolean issuperadministrator= false; 
          try{
            issuperadministrator = getAuthorizationSession().isAuthorizedNoLog(admin, "/super_administrator");
          }catch(AuthorizationDeniedException ade){}
        
          if(!issuperadministrator && certificateprofile.isApplicableToAnyCA()){
             // Not superadministrator, do not use ANYCA;
             Collection authcas = getAuthorizationSession().getAuthorizedCAIds(admin);
             certificateprofile.setAvailableCAs(authcas);
          }        	
                  
         try{
           certprofilehome.findByCertificateProfileName(newcertificateprofilename);
           getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error adding certificaterprofile " + newcertificateprofilename +  " using profile " + originalcertificateprofilename + " as template.");  
           throw new CertificateProfileExistsException();  
         }catch(FinderException e){
           try{
             certprofilehome.create(new Integer(findFreeCertificateProfileId()),newcertificateprofilename,certificateprofile);
             getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_CERTPROFILE,"New certificateprofile " + newcertificateprofilename +  " used profile " + originalcertificateprofilename + " as template.");
           }catch(Exception f){}
         }
       }catch(CloneNotSupportedException f){}

    } // cloneCertificateProfile

     /**
     * Removes a certificateprofile from the database.
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeCertificateProfile(Admin admin, String certificateprofilename) {
      try{
        CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(certificateprofilename);
        pdl.remove();
        getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_CERTPROFILE,"Removed certificateprofile " + certificateprofilename + ".");
      }catch(Exception e){
        getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error removing certificateprofile " + certificateprofilename + ".");
      }
    } // removeCertificateProfile

     /**
     * Renames a certificateprofile
     *
     * @param admin DOCUMENT ME!
     * @param oldcertificateprofilename DOCUMENT ME!
     * @param newcertificateprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public void renameCertificateProfile(Admin admin, String oldcertificateprofilename, String newcertificateprofilename) throws CertificateProfileExistsException{
       if(isCertificateProfileNameFixed(oldcertificateprofilename) || isCertificateProfileNameFixed(newcertificateprofilename)){
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error renaming certificateprofile " + oldcertificateprofilename +  " to " + newcertificateprofilename + ".");
         throw new CertificateProfileExistsException("Cannot rename fixed profiles.");
       }
        
       try{
          certprofilehome.findByCertificateProfileName(newcertificateprofilename);
          getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error renaming certificateprofile " + oldcertificateprofilename +  " to " + newcertificateprofilename + ".");
          throw new CertificateProfileExistsException();
       }catch(FinderException e){
         try{
           CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(oldcertificateprofilename);
           pdl.setCertificateProfileName(newcertificateprofilename);
           getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_CERTPROFILE,"Renamed certificateprofile " + oldcertificateprofilename +  " to " + newcertificateprofilename + ".");
         }catch(FinderException f){
           getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE,"Error renaming certificateprofile " + oldcertificateprofilename +  " to " + newcertificateprofilename + ".");
         }
       }
    } // renameCertificateProfile

    /**
     * Updates certificateprofile data
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     * @param certificateprofile DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */

    public void changeCertificateProfile(Admin admin, String certificateprofilename, CertificateProfile certificateprofile){
       try{
         CertificateProfileDataLocal pdl = certprofilehome.findByCertificateProfileName(certificateprofilename);
         pdl.setCertificateProfile(certificateprofile);
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_INFO_CERTPROFILE,"Certificateprofile " + certificateprofilename +  " edited.");
       }catch(FinderException e){
         getLogSession().log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CERTPROFILE," Error editing certificateprofile " + certificateprofilename + ".");       
       }
    }// changeCertificateProfile
    
    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     *
     * @param certprofiletype should be either SecConst.CERTTYPE_ENDENTITY, SecConst.CERTTYPE_SUBCA, SecConst.CERTTYPE_ROOTCA or 0 for all. 
     * Retrives certificate profile names sorted.
     *
     * @param admin DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public Collection getAuthorizedCertificateProfileIds(Admin admin, int certprofiletype){
      ArrayList returnval = new ArrayList();
      Collection result = null;
      
      HashSet authorizedcaids = new HashSet(getAuthorizationSession().getAuthorizedCAIds(admin));

      // Add fixed certificate profiles. 
      if(certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ENDENTITY)
        returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER));
      if(certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_SUBCA)
        returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_SUBCA));
      if(certprofiletype == 0 || certprofiletype == SecConst.CERTTYPE_ROOTCA)
        returnval.add(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA));
      
      try{
        result = certprofilehome.findAll();
        Iterator i = result.iterator();
        while(i.hasNext()){
          CertificateProfileDataLocal next = (CertificateProfileDataLocal) i.next();
          CertificateProfile profile = next.getCertificateProfile();
          // Check if all profiles available CAs exists in authorizedcaids.
          if(certprofiletype == 0 || certprofiletype == profile.getType()){
            Iterator availablecas = profile.getAvailableCAs().iterator();
            boolean allexists = true;
            while(availablecas.hasNext()){
              Integer nextcaid = (Integer) availablecas.next();
              if(nextcaid.intValue() == CertificateProfile.ANYCA){
                allexists=true;
                break;
              }
                
              if(!authorizedcaids.contains(nextcaid)){
                allexists = false;
                break;
              }
            }
          
            if(allexists)
              returnval.add(next.getId());
          }
        }  
      }catch(Exception e){}
      return returnval;
    } // getAuthorizedEndEntityProfileNames    
    
    
    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name (String).
     */    
    public HashMap getCertificateProfileIdToNameMap(Admin admin){
      HashMap returnval = new HashMap();
      Collection result = null;
      returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_ENDUSER),
                    EndUserCertificateProfile.CERTIFICATEPROFILENAME);
      returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_SUBCA),
                    CACertificateProfile.CERTIFICATEPROFILENAME);
      returnval.put(new Integer(SecConst.CERTPROFILE_FIXED_ROOTCA),
                    RootCACertificateProfile.CERTIFICATEPROFILENAME);
            
      try{
        result = certprofilehome.findAll();
        Iterator i = result.iterator();
        while(i.hasNext()){
          CertificateProfileDataLocal next = (CertificateProfileDataLocal) i.next();    
          returnval.put(next.getId(),next.getCertificateProfileName());
        }
      }catch(FinderException e){}
      return returnval;
    } // getCertificateProfileIdToNameMap


    /**
     * Retrives a named certificate profile.
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile getCertificateProfile(Admin admin, String certificateprofilename){
       CertificateProfile returnval=null;
       
      if(certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME))
        return new EndUserCertificateProfile(); 
     
      if(certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME))
        return new CACertificateProfile(); 

      if(certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME))
        return new RootCACertificateProfile();        
       
       try{
         returnval = (certprofilehome.findByCertificateProfileName(certificateprofilename)).getCertificateProfile();
       } catch(FinderException e){
           // return null if we cant find it
       }
       return returnval;
    } //  getCertificateProfile

     /**
     * Finds a certificate profile by id.
     *
     * @param admin DOCUMENT ME!
     * @param id DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public CertificateProfile getCertificateProfile(Admin admin, int id){
       CertificateProfile returnval=null;
       
       if(id < SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY){
         switch(id){
            case SecConst.CERTPROFILE_FIXED_ENDUSER :
              returnval = new EndUserCertificateProfile();         
              break;
            case SecConst.CERTPROFILE_FIXED_SUBCA :
              returnval = new CACertificateProfile();         
              break;  
            case SecConst.CERTPROFILE_FIXED_ROOTCA :
              returnval = new RootCACertificateProfile();         
              break;    
            default:
              returnval = new EndUserCertificateProfile();           
         }         
       }else{
         try{
           returnval = (certprofilehome.findByPrimaryKey(new Integer(id))).getCertificateProfile();
         } catch(FinderException e){
             // return null if we cant find it
         }
       }  
       return returnval;
    } // getCertificateProfile


     /**
     * Returns a certificate profile id, given it's certificate profile name
     *
     * @param admin DOCUMENT ME!
     * @param certificateprofilename DOCUMENT ME!
     *
     * @return the id or 0 if certificateprofile cannot be found.
     */
    public int getCertificateProfileId(Admin admin, String certificateprofilename){
      int returnval = 0;
      
      if(certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME))
        return SecConst.CERTPROFILE_FIXED_ENDUSER; 
     
      if(certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME))
        return SecConst.CERTPROFILE_FIXED_SUBCA; 

      if(certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME))
        return SecConst.CERTPROFILE_FIXED_ROOTCA; 
      
      try{
        Integer id = (certprofilehome.findByCertificateProfileName(certificateprofilename)).getId();
        returnval = id.intValue();
      }catch(FinderException e){}
           
      return returnval;
    } // getCertificateProfileId

     /**
     * Returns a certificateprofiles name given it's id.
     *
     * @param admin DOCUMENT ME!
     * @param id DOCUMENT ME!
     *
     * @return certificateprofilename or null if certificateprofile id doesn't exists.
     */
    public String getCertificateProfileName(Admin admin, int id){
      String returnval = null;
      
      // Is id a fixed profile
      if(id < SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY){
        switch(id){
            case SecConst.CERTPROFILE_FIXED_ENDUSER :
              returnval = EndUserCertificateProfile.CERTIFICATEPROFILENAME;         
              break;
            case SecConst.CERTPROFILE_FIXED_SUBCA :
              returnval = CACertificateProfile.CERTIFICATEPROFILENAME;         
              break;  
            case SecConst.CERTPROFILE_FIXED_ROOTCA :
              returnval = RootCACertificateProfile.CERTIFICATEPROFILENAME;         
              break;    
            default:
              returnval = EndUserCertificateProfile.CERTIFICATEPROFILENAME;           
        }  
      }else{
        try{
          returnval = (certprofilehome.findByPrimaryKey(new Integer(id))).getCertificateProfileName();
        }catch(FinderException e){}
      }
      
      return returnval;      
      
    } // getCertificateProfileName
    
     /**
     * Method to check if a CA exists in any of the certificate profiles. Used to avoid desyncronization of CA data.
     *
     * @param caid the caid to search for.
     * @return true if ca exists in any of the certificate profiles.
     */
    public boolean existsCAInCertificateProfiles(Admin admin, int caid){
      Iterator availablecas=null;
      boolean exists = false;
      try{
        Collection result = certprofilehome.findAll();
        Iterator i = result.iterator();
        while(i.hasNext() && !exists){
          availablecas = ((CertificateProfileDataLocal) i.next()).getCertificateProfile().getAvailableCAs().iterator();
          while(availablecas.hasNext()){
            if(((Integer) availablecas.next()).intValue() == caid){
              exists=true;
              break;
            }
          }
        }
      }catch(Exception e){}

      return exists;
    } // existsCAInCertificateProfiles     

    // Private methods

    private int findFreeCertificateProfileId(){
      Random random = new Random((new Date()).getTime());
      int id = random.nextInt();
      boolean foundfree = false;

      while(!foundfree){
        try{
          if(id > SecConst.FIXED_CERTIFICATEPROFILE_BOUNDRY){
            certprofilehome.findByPrimaryKey(new Integer(id));
          }else{
            id = random.nextInt();
          }
        }catch(FinderException e){
           foundfree = true;
        }
      }
      return id;
    } // findFreeCertificateProfileId
    
    
    private boolean isCertificateProfileNameFixed(String certificateprofilename){
       boolean returnval = false;
       
       if(certificateprofilename.equals(EndUserCertificateProfile.CERTIFICATEPROFILENAME))
          return true; 
     
       if(certificateprofilename.equals(CACertificateProfile.CERTIFICATEPROFILENAME))
         return true; 

       if(certificateprofilename.equals(RootCACertificateProfile.CERTIFICATEPROFILENAME))
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
