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

package org.ejbca.core.model.ca.publisher;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;

/**
 * @author lars
 * @version $Id: ExternalOCSPPublisher.java,v 1.6 2006-02-11 11:31:38 anatom Exp $
 *
 */
public class ExternalOCSPPublisher implements ICustomPublisher {

    private static Logger log = Logger.getLogger(ExternalOCSPPublisher.class);
    private String dataSource;

    /**
     * 
     */
    public ExternalOCSPPublisher() {
        super();
    }

    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    public void init(Properties properties) {
        dataSource = properties.getProperty("dataSource");
        log.debug("dataSource='"+dataSource+"'.");
    }

    private interface Preparer {
        void prepare(PreparedStatement ps) throws Exception;
        String getInfoString();
    }
    private void execute(String sqlCommandTemplate, Preparer preparer) throws PublisherException {
        if ( sqlCommandTemplate!=null ) {
            Connection connection = null;
            ResultSet result = null;
            PreparedStatement ps = null;
            try {
                connection = ServiceLocator.getInstance().getDataSource(dataSource).getConnection();
                ps = connection.prepareStatement(sqlCommandTemplate);
                preparer.prepare(ps);
                if ( ps.execute() )
                    result = ps.getResultSet();
            } catch (Exception e) {
                log.error("EXTERNAL OCSP ERROR, publishing is not working for - "+preparer.getInfoString()+": ", e);
                PublisherException pe = new PublisherException("EXTERNAL OCSP ERROR, publishing is not working");
                pe.initCause(e);
                throw pe;
            } finally {
                JDBCUtil.close(connection, ps, result);
            }
        }
    }

    private class StoreCertPreparer implements Preparer {
        final Certificate incert;
        final String username;
        final String cafp;
        final int status;
        final int type;
        StoreCertPreparer(Certificate ic,
                          String un, String cf, int s, int t) {
            super();
            incert = ic;
            username = un;
            cafp = cf;
            status = s;
            type = t;
        }
        public void prepare(PreparedStatement ps) throws Exception {
            ps.setString(1,CertTools.getFingerprintAsString((X509Certificate)incert));
            ps.setString(2, new String(Base64.encode(incert.getEncoded(), true)));
            ps.setString(3, CertTools.getSubjectDN((X509Certificate)incert));
            ps.setString(4, CertTools.getIssuerDN((X509Certificate)incert));
            ps.setString(5, cafp);
            ps.setString(6, ((X509Certificate)incert).getSerialNumber().toString());
            ps.setInt(7, status);
            ps.setInt(8, type);
            ps.setString(9, username);
            ps.setLong(10, ((X509Certificate)incert).getNotAfter().getTime());
            ps.setLong(11, -1);
            ps.setInt(12, -1);
        }
        public String getInfoString() {
        	return "Store:, Username: "+username+", Issuer:"+CertTools.getIssuerDN((X509Certificate)incert)+", Serno: "+((X509Certificate)incert).getSerialNumber().toString()+", Subject: "+CertTools.getSubjectDN((X509Certificate)incert);
        }
    }
    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#storeCertificate(se.anatom.ejbca.log.Admin, java.security.cert.Certificate, java.lang.String, java.lang.String, java.lang.String, int, int, se.anatom.ejbca.ra.ExtendedInformation)
     */
    public boolean storeCertificate(Admin admin, Certificate incert,
                                    String username, String password,
                                    String cafp, int status, int type,
                                    ExtendedInformation extendedinformation)
                                                                            throws PublisherException {
        execute( "INSERT INTO CertificateData (fingerprint,base64Cert,subjectDN,issuerDN,cAFingerprint,serialNumber,status,type,username,expireDate,revocationDate,revocationReason) VALUES (?,?,?,?,?,?,?,?,?,?,?,?);",
                 new StoreCertPreparer(incert, username, cafp, status, type) );
        return true;
    }

    /* Does nothing, this publisher only publishes Certificates.
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#storeCRL(se.anatom.ejbca.log.Admin, byte[], java.lang.String, int)
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number)
    throws PublisherException {
        return true;
    }

    class RevokePreparer implements Preparer {
        final Certificate cert;
        final int reason;
        RevokePreparer(Certificate c, int r) {
            cert = c;
            reason = r;
        }
        public void prepare(PreparedStatement ps) throws Exception {
            ps.setInt(1, 40);
            ps.setLong(2, System.currentTimeMillis());
            ps.setInt(3, reason);
            ps.setString(4, CertTools.getFingerprintAsString((X509Certificate)cert));
        }
        public String getInfoString() {
        	return "Revoke:, Issuer:"+CertTools.getIssuerDN((X509Certificate)cert)+", Serno: "+((X509Certificate)cert).getSerialNumber().toString()+", Subject: "+CertTools.getSubjectDN((X509Certificate)cert);
        	
        }
    }
    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#revokeCertificate(se.anatom.ejbca.log.Admin, java.security.cert.Certificate, int)
     */
    public void revokeCertificate(Admin admin, Certificate cert, int reason)
                                                                            throws PublisherException {
        execute( "UPDATE CertificateData SET status=?, revocationDate=?, revocationReason=? WHERE fingerprint=?;",
                 new RevokePreparer(cert, reason));
    }

    private class DoNothingPreparer implements Preparer {
        public void prepare(PreparedStatement ps) {
        }
        public String getInfoString() {
        	return null;
        }
    }
    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#testConnection(se.anatom.ejbca.log.Admin)
     */
    public void testConnection(Admin admin) throws PublisherConnectionException {
        try {
            execute("UNLOCK TABLES;", new DoNothingPreparer());
        } catch (PublisherException e) {
            final PublisherConnectionException pce = new PublisherConnectionException("Connection in init failed: "+e.getMessage());
            pce.initCause(e);
            throw pce;
        }
    }
}
