/**
 * 
 */
package org.ejbca.core.model.ca.publisher;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * @author lars
 *
 */
public class ExternalOCSPPublisher implements ICustomPublisher {

    private Connection connection;
    private PublisherException savedException;
    private static Logger log = Logger.getLogger(ExternalOCSPPublisher.class);

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
        try {
            if ( connection!=null )
                connection.close();
            connection = DriverManager.getConnection(properties.getProperty("url"),
                                                     properties.getProperty("name"),
                                                     properties.getProperty("password"));
            savedException = null;
        } catch (SQLException e) {
            connection = null;
            savedException = new PublisherException("Exception during initialization caused by "+e.getMessage());
            savedException.initCause(e);
            log.error("not possible to get sql coennection", e);
        }
        if ( connection!=null && savedException==null ) {
            final String sqlCommand  =
                "CREATE TABLE CertificateData ( "+
                "fingerprint varchar(250) binary NOT NULL default '', "+
                "base64Cert text, "+
                "subjectDN varchar(250) binary default NULL, "+
                "issuerDN varchar(250) binary default NULL, "+
                "cAFingerprint varchar(250) binary default NULL, "+
                "serialNumber varchar(250) binary default NULL, "+
                "status int(11) NOT NULL default '0', "+
                "type int(11) NOT NULL default '0', "+
                "username varchar(250) binary default NULL, "+
                "expireDate bigint(20) NOT NULL default '0', "+
                "revocationDate bigint(20) NOT NULL default '0', "+
                "revocationReason int(11) NOT NULL default '0', "+
                "PRIMARY KEY  (fingerprint) ) TYPE=MyISAM;";
            try {
                execute(sqlCommand);
            } catch (PublisherException e) {
                log.debug("Table allready created.",e);
            }
        }
    }

    private void execute(String sqlCommand) throws PublisherException {
        if ( sqlCommand!=null ) {
            Statement statement = null;
            try {
                statement = connection.createStatement();
                statement.execute(sqlCommand);
            } catch (SQLException e) {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                pw.println("Exception during execution of:");
                pw.println("  "+sqlCommand);
                pw.println("See cause of exception.");
                pw.flush();
                PublisherException pe = new PublisherException(sw.toString());
                pe.initCause(e);
                log.debug("execute error cause:", e);
                throw pe;
            } finally {
                try {
                    if ( statement!=null )
                        statement.close();
                } catch (SQLException e) {
                    log.debug("error when closing", e);
                }
            }
        }
    }
    void check() throws PublisherException {
        if ( savedException!=null )
            throw savedException;
        if ( connection==null )
            throw new PublisherException("not initialized");
    }
    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#storeCertificate(se.anatom.ejbca.log.Admin, java.security.cert.Certificate, java.lang.String, java.lang.String, java.lang.String, int, int, se.anatom.ejbca.ra.ExtendedInformation)
     */
    public boolean storeCertificate(Admin admin, Certificate incert,
                                    String username, String password,
                                    String cafp, int status, int type,
                                    ExtendedInformation extendedinformation)
                                                                            throws PublisherException {
        check();
        final String sqlCommand;
        try {
            sqlCommand =
                "INSERT INTO CertificateData VALUES ('" +
                CertTools.getFingerprintAsString((X509Certificate)incert) + "','" +
                new String(Base64.encode(incert.getEncoded(), true)) + "','" +
                CertTools.getSubjectDN((X509Certificate)incert) + "','" +
                CertTools.getIssuerDN((X509Certificate)incert) + "','" +
                cafp + "','" +
                ((X509Certificate)incert).getSerialNumber() + "'," +
                status + "," +
                type + ",'" +
                username + "'," +
                ((X509Certificate)incert).getNotAfter().getTime() +",-1,-1);";
        } catch (CertificateEncodingException e) {
            PublisherException pe = new PublisherException("Encoding error. See cause.");
            savedException.initCause(e);
            throw pe;
        }
        execute(sqlCommand);
        return true;
    }

    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#storeCRL(se.anatom.ejbca.log.Admin, byte[], java.lang.String, int)
     */
    public boolean storeCRL(Admin admin, byte[] incrl, String cafp, int number)
                                                                               throws PublisherException {
        return false;
    }

    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#revokeCertificate(se.anatom.ejbca.log.Admin, java.security.cert.Certificate, int)
     */
    public void revokeCertificate(Admin admin, Certificate cert, int reason)
                                                                            throws PublisherException {
        check();
        String sqlCommand =
            "UPDATE CertificateData SET status=40, revocationDate=" +
            System.currentTimeMillis() + ", revocationReason=" +
            reason + " WHERE fingerprint='" +
            CertTools.getFingerprintAsString((X509Certificate)cert) + "';";
        execute(sqlCommand);
    }

    /* (non-Javadoc)
     * @see se.anatom.ejbca.ca.publisher.ICustomPublisher#testConnection(se.anatom.ejbca.log.Admin)
     */
    public void testConnection(Admin admin) throws PublisherConnectionException {
        try {
            check();
        } catch (PublisherException e) {
            final PublisherConnectionException pce = new PublisherConnectionException("Connection in init failed: "+e.getMessage());
            pce.initCause(e);
            throw pce;
        }
    }
    protected void finalize() throws Throwable {
        if ( connection!=null )
            connection.close();
        super.finalize();
    }

}
