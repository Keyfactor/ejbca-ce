/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.ca.publisher.custpubl1;

import java.io.UnsupportedEncodingException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;
import java.util.SimpleTimeZone;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.util.TCPTool;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPConstraints;
import com.novell.ldap.LDAPDN;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.novell.ldap.LDAPJSSESecureSocketFactory;
import com.novell.ldap.LDAPSearchConstraints;
import javax.security.auth.x500.X500Principal;

/**
 * This publisher publishes end entity certificates and CRLs according to the
 * customer specific schema based on the schema defined by ICAO for uploading to
 * PKD but with customer-specific extensions added.
 * 
 * Certificates:
 * DN: CN=[issuerDN of the certificate]+sn=[hex encoded cert serial no], ou=staging, [base DN]
 * Objectclass: inetOrgPerson; icaoExtendedInfo 
 * Attributes:
 *   cn: the issuer DN of the certificate
 *   sn: the certificate serial number in hex encoding
 *   userCertificate:binary: DER encoded certificate (standard LDAP)
 *   checksum (customer specific): SHA1 checksum in hex encoding of the data field (certificate)
 * 
 * CRLs:
 * DN: CN=[issuerDN of the CRL], ou=staging, [base DN]
 * Objectclass (standard LDAP): cRLDistributionPoint; icaoExtendedInfo
 * Attributes:
 *   cn: the issuer DN of the CRL
 *   certificateRevocationList; binary: DER encoded CRL (standard LDAP)
 *   checksum (customer specific): SHA1 checksum in hex encoding of the data field (crl)
 * 
 * The DN is a bit special, since the "CN" of the LDAP DN is the whole DN from the certificate. The commas needs to be escaped.
 * 
 * Logs:
 * DN: logTime=[YYYYMMDDHHMM.nnnZ],cn=log, [base DN]
 * Objectclass: top; logObject
 * Attributes:
 *   logTime: Generalized Time with milliseconds and UTC time.
 *   objectCreator: EJBCA
 *   logInfo: [Log line 1]
 *   logInfo: [Log line 2]
 *   logInfo: [Log line 3]
 *   logInfo: [Log line n]
 * 
 * Each log line is formatted as follows:
 * time:[Generalized Time] sqn:[number] stage:objectimport level:[Level] msgid: [nnn] msg: [message] pid: msgext: [extended extra info]
 *
 * 
 * Example cert entry:
 * <pre>
 * dn: CN=CN\=MyCSCA\,O\=My Gov\,C\=SE+sn=74F9C50AC1514A9,ou=staging,dc=example,dc=com
 * checksum: f7f7cf62726678837f4e05c83499379e26ff9c58
 * cn: CN=MyCSCA,O=My Gov,C=SE
 * objectClass: person
 * objectClass: organizationalPerson
 * objectClass: inetOrgPerson
 * objectClass: top
 * objectClass: Icaoextendedinfo
 * sn: 74F9C50AC1514A9
 * userCertificate;binary:: MIIEnTCCAlGgAwIBAgIIB0+cUKwVFKkwQQYJKoZIhvcNAQEKM...
 * </pre>
 * 
 * Example CRL entry:
 * <pre>
 * dn: CN=CN\=MyCSCA\,O\=My Gov\,C\=SE,ou=staging,dc=example,dc=com
 * certificateRevocationList;binary:: MIIDETCBxgIBATBBBgkqhkiG9w0BAQowNKAPMA0...
 * checksum: cbc0b8a00899edc3da3344eeb2a8075f7960970f
 * cn: CN=MyCSCA,O=My Gov,C=SE
 * objectClass: cRLDistributionPoint
 * objectClass: top
 * objectClass: Icaoextendedinfo
 * </pre>
 * 
 * Example log entry:
 * <pre>
 * dn: logTime=20130415121356.184Z,cn=log,dc=example,dc=com
 * description: test
 * logInfo:  time:20130415121356.184Z sqn:1 stage:objectupload level:info msgid: msg:Successfully published CRL 26 msgext:
 * logTime: 20130415121356.184Z
 * objectClass: logObject
 * objectClass: top
 * objectCreator: EJBCA
 * </pre>
 * 
 * If an log entry with the same name already exists it is retried one time with time +1 ms in DN.
 * 
 * Note the escaping of commas in the DN, this is needed since the "CN" of the LDAP DN contains commas (CN=C=SE\,O=foo\,CN=cscav1).
 * OpenLDAP implement very old escaping rules and will replace = with \3D and things like that. Better to use OpenDJ, easy to install and run, and works correctly.
 * 
 * Version: 0.9.2
 *
 * @version $Id$
 */
public class CustomerLdapPublisher1 implements ICustomPublisher {

    private static final Logger log = Logger.getLogger(CustomerLdapPublisher1.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    // Object classes
    private static final String INETORGPERSON = "inetOrgPerson";
    private static final String CRLDISTRIBUTIONPOINT = "cRLDistributionPoint";
    private static final String ICAOEXTENDEDINFO = "icaoExtendedInfo";
    private static final String TOP = "top";
    private static final String LOGOBJECT = "logObject";   
    private static final String[] DSC_OBJECTCLASSES = new String[] {INETORGPERSON, ICAOEXTENDEDINFO};
    private static final String[] CRL_OBJECTCLASSES = new String[] {CRLDISTRIBUTIONPOINT, ICAOEXTENDEDINFO};
    private static final String[] LOG_OBJECTCLASSES = new String[] {TOP, LOGOBJECT};
 
    // Groups
    private static final String PUBLISH_GROUP = "ou=staging";
    private static final String LOG_GROUP = "cn=log";
    
    // Attributes
    private static final String CHECKSUM_ATTRIBUTE = "checksum";
    private static final String CERTIFICATE_ATTRIBUTE = "userCertificate;binary";
    private static final String CRL_ATTRIBUTE = "certificateRevocationList;binary";
    
    // Properties
    private static final String PROPERTY_HOSTNAMES = "hostnames";
    private static final String PROPERTY_USESSL = "usessl";
    private static final String PROPERTY_PORT = "port";
    private static final String PROPERTY_BASEDN = "basedn";
    private static final String PROPERTY_LOGINDN = "logindn";
    private static final String PROPERTY_LOGINPASSWORD = "loginpassword";
    private static final String PROPERTY_CONNECTIONTIMEOUT = "connectiontimeout";
    private static final String PROPERTY_READTIMEOUT = "readtimeout";
    private static final String PROPERTY_STORETIMEOUT = "storetimeout";
    private static final String PROPERTY_LOGCONNECTIONTESTS = "logconnectiontests";
    
    // Default values
    public static final String DEFAULT_PORT = "389";
    public static final String DEFAULT_SSLPORT = "636";
    public static final String DEFAULT_TIMEOUT = "5000"; // 5 seconds
    public static final String DEFAULT_READTIMEOUT = "30000"; // 30 seconds
    public static final String DEFAULT_STORETIMEOUT = "60000"; // 1 minute
    
    /** Flag indicating if the publisher has been initialized. */
    private boolean inited;
    
    // Fields
    private List<String> hostnames;
    private boolean useSSL;
    private String port;
    private String baseDN;
    private String loginDN;
    private String loginPassword;
    private boolean logConnectionTests;
    
    private int timeout;

    private LDAPConstraints ldapConnectionConstraints = new LDAPConstraints();
    private LDAPConstraints ldapBindConstraints = new LDAPConstraints();
    private LDAPConstraints ldapStoreConstraints = new LDAPConstraints();
    private LDAPConstraints ldapDisconnectConstraints = new LDAPConstraints();
    private LDAPSearchConstraints ldapSearchConstraints = new LDAPSearchConstraints();

    /**
     * Called by CustomPublisherContainer to initialize a newly created instance
     * of this custom publisher with its properties.
     *
     * @param properties The properties entered in the GUI
     */
    @Override
    public void init(Properties properties) {
        this.hostnames = Arrays.asList(properties.getProperty(PROPERTY_HOSTNAMES, "").split(";"));
        this.useSSL = Boolean.parseBoolean(properties.getProperty(PROPERTY_USESSL, Boolean.TRUE.toString()));
        this.port = properties.getProperty(PROPERTY_PORT, DEFAULT_SSLPORT);
        this.baseDN = properties.getProperty(PROPERTY_BASEDN, "");
        this.loginDN = properties.getProperty(PROPERTY_LOGINDN, "");
        this.loginPassword = properties.getProperty(PROPERTY_LOGINPASSWORD, "");
        this.logConnectionTests = Boolean.parseBoolean(properties.getProperty(PROPERTY_LOGCONNECTIONTESTS, Boolean.FALSE.toString()));
        this.timeout = Integer.parseInt(properties.getProperty(PROPERTY_CONNECTIONTIMEOUT, String.valueOf(DEFAULT_TIMEOUT)));
        int readTimeout = Integer.parseInt(properties.getProperty(PROPERTY_READTIMEOUT, String.valueOf(DEFAULT_TIMEOUT)));
        int storeTimeout = Integer.parseInt(properties.getProperty(PROPERTY_STORETIMEOUT, String.valueOf(DEFAULT_TIMEOUT)));
        
        ldapBindConstraints.setTimeLimit(timeout);
        ldapConnectionConstraints.setTimeLimit(timeout);
        ldapDisconnectConstraints.setTimeLimit(timeout);
        ldapSearchConstraints.setTimeLimit(readTimeout);
        ldapStoreConstraints.setTimeLimit(storeTimeout);
        
        if (log.isDebugEnabled()) {
            log.debug(new StringBuilder()
                    .append("Initialized publisher with config:").append("\n")
                    .append(PROPERTY_HOSTNAMES).append(": \"").append(hostnames).append("\"\n")
                    .append(PROPERTY_USESSL).append(": \"").append(useSSL).append("\"\n")
                    .append(PROPERTY_PORT).append(": \"").append(port).append("\"\n")
                    .append(PROPERTY_BASEDN).append(": \"").append(baseDN).append("\"\n")
                    .append(PROPERTY_LOGINDN).append(": \"").append(loginDN).append("\"\n")
                    .append(PROPERTY_LOGINPASSWORD).append(": ").append(loginPassword.length()).append(" characters").append("\n")
                    .append(PROPERTY_LOGCONNECTIONTESTS).append(": \"").append(logConnectionTests).append("\"\n")
                    .append(PROPERTY_CONNECTIONTIMEOUT).append(": \"").append(timeout).append("\"\n")
                    .append(PROPERTY_READTIMEOUT).append(": \"").append(readTimeout).append("\"\n")
                    .append(PROPERTY_STORETIMEOUT).append(": \"").append(storeTimeout).append("\"\n")
                    .toString());
        }

        inited = true;
    }

    @Override
    public boolean storeCertificate(final AuthenticationToken admin, final Certificate incert, final String username, final String password, final String userDN, final String cafp, final int status, final int type, final long revocationDate, final int revocationReason, final String tag, final int certificateProfileId, final long lastUpdate, final ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCertificate(username=" + username + ")");
        }
        if (!inited) {
            throw new IllegalStateException("Publisher not initialized");
        }

        // Only bother with active end entity certificates
        if (status == CertificateConstants.CERT_ACTIVE && type == CertificateConstants.CERTTYPE_ENDENTITY) {
            final String serial = CertTools.getSerialNumberAsString(incert);
            try {
                doStoreCertificate(incert, username, password, userDN, extendedinformation);
                try {
                    storeLog(LogInfo.LEVEL_INFO, true, "Successfully published certificate " + serial, null);
                } catch (PublisherException ex) {
                    // Catching the log failure as we don't want the entry to be republished just because we could not log the success
                    log.error("Failed to log the successful publishing for certiciate " + serial, ex);
                }
            } catch (PublisherException pex) {
                PublisherException pex2 = new PublisherException(pex.getMessage());
                pex2.initCause(pex);

                // Try to log the exception to LDAP
                try {
                    storeLog(LogInfo.LEVEL_ERROR, false, "Publishing of certificate " + serial + " failed", pex);
                } catch (PublisherException ex) {
                    log.error("Failed to log the failed publishing for certificate " + serial, ex);
                }

                // Pass through the exception so that the failed publising can be put in the publishing queue
                throw pex2;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("This publisher only stores active end entity certificates.");
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<storeCertificate()");
        }
        return true;
    }

    @Override
    public boolean storeCRL(final AuthenticationToken admin, final byte[] incrl, final String cafp, final int number, final String userDN) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCRL");
        }
        if (!inited) {
            throw new IllegalStateException("Publisher not initialized");
        }

        try {
            doStoreCRL(incrl);
            try {
                storeLog(LogInfo.LEVEL_INFO, true, "Successfully published CRL " + number, null);
            } catch (PublisherException ex) {
                // Catching the log failure as we don't want the entry to be republished just because we could not log the success
                log.error("Failed to log the successful publishing for CRL" + number, ex);
            }
            return true;
        } catch (PublisherException pex) {
            PublisherException pex2 = new PublisherException(pex.getMessage());
            pex2.initCause(pex);

            // Try to log the exception to LDAP
            try {
                storeLog(LogInfo.LEVEL_ERROR, false, "Publishing of CRL " + number + " failed", pex);
            } catch (PublisherException ex) {
                log.error("Failed to log the failed publishing for CRL " + number, ex);
            }

            // Pass through the exception so that the failed publishing can be put in the publishing queue
            throw pex2;
        }
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        if (!inited) {
            throw new IllegalStateException("Publisher not initialized");
        }
        try {
            doTestConnection();
            if (logConnectionTests) {
                try {
                    storeLog(LogInfo.LEVEL_DEBUG, true, "Successfully tested connection to LDAP", null);
                } catch (PublisherException ex) {
                    log.error("Failed to log the successful connection test", ex);
                }
            }
        } catch (PublisherConnectionException pex) {
            PublisherConnectionException pex2 = new PublisherConnectionException(pex.getMessage());
            pex2.initCause(pex);

            if (logConnectionTests) {
                // Try to log the exception to LDAP
                try {
                    storeLog(LogInfo.LEVEL_ERROR, false, "Failed testing of connection to LDAP ", pex);
                } catch (PublisherException ex) {
                    log.error("Failed to log the failed connection test ", ex);
                }
            }
            throw pex2;
        }
    }

    protected boolean doStoreCertificate(final Certificate incert, String username, String password, String userDN, ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">doStoreCertificate(username=" + username + ")");
        }
        final LDAPConnection lc = createLdapConnection();

        final String ldapDN;
        try {
            // Extract the CAs DN from the cert, the DN should be in reversed order (RFC2253)
            // In ICAO PKD certs are stored with issuerDN+serialNo in the LDAP
            final String dn = ((X509Certificate) incert).getIssuerX500Principal().getName(X500Principal.RFC2253);
            if (log.isDebugEnabled()) {
                log.debug("DN in certificate '" + dn + "'.");
            }
            
            // Publishing of certificate, we must append the cert serial number to the DN
            ldapDN = new StringBuilder()
                    .append("CN=").append(LDAPDN.escapeRDN(dn))
                    .append("+sn=").append(CertTools.getSerialNumberAsString(incert))
                    .append(",").append(PUBLISH_GROUP)
                    .append(",").append(baseDN)
                    .toString();
            
            if (log.isDebugEnabled()) {
                log.debug("LDAP DN for user " + username + " is '" + ldapDN + "'");
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "certificate");
            log.error(msg, e);
            throw new PublisherException(msg);
        }

        // Check for old entry
        final LDAPEntry oldEntry = searchOldEntity(lc, ldapDN);
        if (oldEntry != null) {
            log.debug("Old entry exists and will be delete first");
        }

        // Attributs
        final LDAPAttributeSet attributeSet = new LDAPAttributeSet();
        attributeSet.add(new LDAPAttribute("objectclass", DSC_OBJECTCLASSES));
        attributeSet.add(new LDAPAttribute("sn", CertTools.getSerialNumberAsString(incert)));
        final String checksum = CertTools.getFingerprintAsString(incert);
        if (log.isDebugEnabled()) {
            log.debug("Adding checksum: " + checksum);
        }
        attributeSet.add(new LDAPAttribute(CHECKSUM_ATTRIBUTE, checksum));
        try {
            attributeSet.add(new LDAPAttribute(CERTIFICATE_ATTRIBUTE, incert.getEncoded()));
        } catch (CertificateEncodingException e) {
            String msg = intres.getLocalizedMessage("publisher.errorldapencodestore", "certificate");
            log.error(msg, e);
            throw new PublisherException(msg);
        }
        
        // Finally write the object
        if (log.isDebugEnabled()) {
            log.debug("Adding certificate to user entry: " + username + ": " + ldapDN);
        }
        final LDAPEntry newEntry = new LDAPEntry(ldapDN, attributeSet);
        writeCertEntryToLDAP(lc, oldEntry, newEntry, checksum);

        if (log.isTraceEnabled()) {
            log.trace("<doStoreCertificate()");
        }
        return true;
    }

    protected void doStoreCRL(final byte[] incrl) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">doStoreCRL");
        }

        final LDAPConnection lc = createLdapConnection();
        
        final String ldapDN;
        try {
            // Extract the users DN from the crl. The DN should be in reversed order (RFC2253)
            final X509CRL crl = CertTools.getCRLfromByteArray(incrl);
            final String crlDN = crl.getIssuerX500Principal().getName(X500Principal.RFC2253);
            ldapDN = new StringBuilder()
                    .append("CN=").append(LDAPDN.escapeRDN(crlDN))
                    .append(",").append(PUBLISH_GROUP)
                    .append(",").append(baseDN)
                    .toString();
        } catch (CRLException e) {
            String msg = intres.getLocalizedMessage("publisher.errorldapdecode", "CRL");
            log.error(msg, e);
            throw new PublisherException(msg);
        }

        // Check if the entry is already present, we will update it with the new CRL.
        final LDAPEntry oldEntry = searchOldEntity(lc, ldapDN);

        // Attributes
        final LDAPAttributeSet attributeSet = new LDAPAttributeSet();
        attributeSet.add(new LDAPAttribute("objectclass", CRL_OBJECTCLASSES));
        final String checksum = CertTools.getFingerprintAsString(incrl);
        if (log.isDebugEnabled()) {
            log.debug("Adding checksum: " + checksum);
        }
        attributeSet.add(new LDAPAttribute(CHECKSUM_ATTRIBUTE, checksum));
        attributeSet.add(new LDAPAttribute(CRL_ATTRIBUTE, incrl));

        // Finally write the object
        final LDAPEntry newEntry = new LDAPEntry(ldapDN, attributeSet);
        writeCrlEntryToLDAP(lc, oldEntry, newEntry);
        if (log.isTraceEnabled()) {
            log.trace("<doStoreCRL");
        }
    }

    protected void doTestConnection() throws PublisherConnectionException {
        final LDAPConnection lc = createLdapConnection();
        final LDAPEntry entry = executeLDAPAction(lc, new LDAPConnectionAction<LDAPEntry, PublisherConnectionException>() {
            @Override
            public LDAPEntry performAction(final LDAPConnection lc) throws LDAPException {
                // try to read the base object
                if (log.isDebugEnabled()) {
                    log.debug("Trying to read top node '" + baseDN + "'");
                }
                final LDAPEntry entry = lc.read(baseDN, ldapSearchConstraints);
                return entry;
            }
            @Override
            public void failed(final LDAPException ex) throws PublisherConnectionException {
                String msg = intres.getLocalizedMessage("publisher.errorldapbind", ex.getMessage());
                log.error(msg, ex);
                throw new PublisherConnectionException(msg);
            }
        });
        
        if (entry == null) {
            String msg = intres.getLocalizedMessage("publisher.errornobinddn");
            throw new PublisherConnectionException(msg);
        }
        if (log.isDebugEnabled()) {
            log.debug("Entry" + entry.toString());
        }
    }

    protected void storeLog(final String level, final boolean success, final String message, Exception exception) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeLog");
        }
        if (log.isDebugEnabled()) {
            log.debug("Publishing was successful: " + success);
        }

        // Construct LogInfo lines
        final Date now = getCurrentTime();
        try {
            doStoreLog(level, success, message, exception, now, now);
        } catch (PublisherException ex) {
            if (ex.getCause() instanceof LDAPException) {
                final LDAPException le = (LDAPException) ex.getCause();
                // If entry already exists, retry one time with time +1 ms
                if (le.getResultCode() == LDAPException.ENTRY_ALREADY_EXISTS) {
                    log.info("Log entry already exists, retrying with time +1 ms");
                    doStoreLog(level, success, message, exception, new Date(now.getTime() + 1), now);
                }
            } else {
                throw ex;
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("<storeLog");
        }
    }
    
    protected void doStoreLog(final String level, final boolean success, final String message, Exception exception, final Date dnTime, final Date logTime) throws PublisherException {
        final String generalizedTimeDN = LogInfo.toGeneralizedTime(dnTime);
        final String generalizedTimeLog = LogInfo.toGeneralizedTime(logTime);
        final LinkedList<String> logEntries = new LinkedList<String>();
        final StringBuilder buff = new StringBuilder();
        buff.append(message);
        if (!success) {
            buff.append(": ").append(exception.getLocalizedMessage());
        }
        logEntries.add(new LogInfo(logTime, 1, "objectupload", level, null, buff.toString(), null, null).getEncoded());

        // Connect
        final LDAPConnection lc = createLdapConnection();

        // Attributes
        final LDAPAttributeSet attributeSet = new LDAPAttributeSet();
        attributeSet.add(new LDAPAttribute("objectclass", LOG_OBJECTCLASSES));
        attributeSet.add(new LDAPAttribute("objectCreator", "EJBCA"));
        attributeSet.add(new LDAPAttribute("logTime", generalizedTimeLog));
        attributeSet.add(new LDAPAttribute("logInfo", logEntries.toArray(new String[logEntries.size()])));
        final String dn = "logTime=" + generalizedTimeDN + "," + LOG_GROUP + "," + baseDN;

        // Finally write the object
        final LDAPEntry newEntry = new LDAPEntry(dn, attributeSet);
        writeLogEntryToLDAP(lc, newEntry);
    }

    protected Date getCurrentTime() {
        return new Date();
    }
    
    interface LDAPConnectionAction<T, E extends Throwable> {
        T performAction(LDAPConnection lc) throws LDAPException;
        void failed(LDAPException ex) throws E;
    }
    
    private<T extends Object, E extends Throwable> T executeLDAPAction(final LDAPConnection lc, final LDAPConnectionAction<T,E> action) throws E {
        T result = null;
        // Try all the listed servers
        final Iterator<String> servers = hostnames.iterator();
        boolean connectionFailed;
        do {
            connectionFailed = false;
            final String currentServer = servers.next();
            if (log.isDebugEnabled()) {
                log.debug("Current server is: " + currentServer);
            }
            
            try {
                TCPTool.probeConnectionLDAP(currentServer, Integer.parseInt(port), timeout);    // Avoid waiting for halfdead-servers
                // connect to the server
                lc.connect(currentServer, Integer.parseInt(port));
                // authenticate to the server
                lc.bind(LDAPConnection.LDAP_V3, loginDN, loginPassword.getBytes("UTF8"), ldapBindConstraints);
                
                // Perform the action
                result = action.performAction(lc);
            } catch (LDAPException e) {
                connectionFailed = true;
                if (servers.hasNext()) {
                    log.warn("Failed to publish to " + currentServer + ". Trying next in list.");
                } else {
                    action.failed(e);
                }
            } catch (UnsupportedEncodingException e) {
                String msg = intres.getLocalizedMessage("publisher.errorpassword", loginPassword);
                throw new RuntimeException(msg);
            } finally {
                // disconnect with the server
                try {
                    lc.disconnect(ldapDisconnectConstraints);
                } catch (LDAPException e) {
                    String msg = intres.getLocalizedMessage("publisher.errordisconnect");
                    log.error(msg, e);
                }
            }
        } while (connectionFailed && servers.hasNext());
        return result;
    }

    protected LDAPEntry searchOldEntity(final LDAPConnection lc, final String ldapDN) throws PublisherException {
        return executeLDAPAction(lc, new LDAPConnectionAction<LDAPEntry,PublisherException>() {
            @Override
            public LDAPEntry performAction(final LDAPConnection lc) throws LDAPException {
                LDAPEntry result = null;
                try {
                    // try to read the old object
                    if (log.isDebugEnabled()) {
                        log.debug("Searching for old entry with DN '" + ldapDN + "'");
                    }
                    result = lc.read(ldapDN, ldapSearchConstraints);
                    if (log.isDebugEnabled()) {
                        if (result != null) {
                            log.debug("Found an old entry with DN '" + ldapDN + "'");
                        } else {
                            log.debug("Did not find an old entry with DN '" + ldapDN + "'");
                        }
                    }
                } catch (LDAPException ex) {
                    if (ex.getResultCode() == LDAPException.NO_SUCH_OBJECT) {
                        if (log.isDebugEnabled()) {
                            log.debug("No old entry exist for '" + ldapDN + "'.");
                        }
                    } else {
                        throw ex;
                    }
                }
                return result;
            }
            @Override
            public void failed(final LDAPException ex) throws PublisherException {
                final String msg = intres.getLocalizedMessage("publisher.errorldapbind", ex.getMessage());
                log.error(msg, ex);
                throw new PublisherException(msg);
            }
        });
    }
    
    private LDAPConnection createLdapConnection() {
        final LDAPConnection result;
        if (useSSL) {
            result = new LDAPConnection(new LDAPJSSESecureSocketFactory());
        } else {
            result = new LDAPConnection();
        }
        result.setConstraints(ldapConnectionConstraints);
        return result;
    }

    protected void writeCertEntryToLDAP(final LDAPConnection lc, final LDAPEntry oldEntry, final LDAPEntry newEntry, final String certFingerprint) throws PublisherException {
        executeLDAPAction(lc, new LDAPConnectionAction<Void,PublisherException>() {
            @Override
            public Void performAction(final LDAPConnection lc) throws LDAPException {
                try {
                    // Delete old entry if existing
                    if (oldEntry != null) {
                        lc.delete(oldEntry.getDN(), ldapStoreConstraints);
                        String msg = intres.getLocalizedMessage("publisher.ldapremove", oldEntry.getDN());
                        log.info(msg);
                    }
                    
                    // Add the entry
                    if (log.isDebugEnabled()) {
                        log.debug("Adding DN: " + newEntry.getDN());
                    }
                    lc.add(newEntry, ldapStoreConstraints);
                    String msg = intres.getLocalizedMessage("publisher.ldapadd", "CERT", newEntry.getDN());
                    log.info(msg);
                } catch (LDAPException ex) {
                    if (ex.getResultCode() == LDAPException.ATTRIBUTE_OR_VALUE_EXISTS) {
                        final String msg = intres.getLocalizedMessage("publisher.certalreadyexists", certFingerprint, newEntry.getDN(), ex.getMessage());
                        log.info(msg);
                    } else {
                        throw ex;
                    }
                }
                return null;
            }
            @Override
            public void failed(final LDAPException ex) throws PublisherException {
                String msg = intres.getLocalizedMessage("publisher.errorldapstore", "certificate", CERTIFICATE_ATTRIBUTE, Arrays.toString(DSC_OBJECTCLASSES), newEntry.getDN(), ex.getMessage());
                log.error(msg, ex);
                throw new PublisherException(msg);
            }
        });
    }

    protected void writeCrlEntryToLDAP(final LDAPConnection lc, final LDAPEntry oldEntry, final LDAPEntry newEntry) throws PublisherException {
        executeLDAPAction(lc, new LDAPConnectionAction<Void,PublisherException>() {
            @Override
            public Void performAction(final LDAPConnection lc) throws LDAPException {
                // Delete old entry if existing
                if (oldEntry != null) {
                    lc.delete(oldEntry.getDN(), ldapStoreConstraints);
                    String msg = intres.getLocalizedMessage("publisher.ldapremove", oldEntry.getDN());
                    log.info(msg);
                }

                // Add new entry
                lc.add(newEntry, ldapStoreConstraints);
                String msg = intres.getLocalizedMessage("publisher.ldapadd", "CRL", newEntry.getDN());
                log.info(msg);
                return null;
            }
            @Override
            public void failed(final LDAPException ex) throws PublisherException {
                String msg = intres.getLocalizedMessage("publisher.errorldapstore", "CRL", CRL_ATTRIBUTE, Arrays.toString(CRL_OBJECTCLASSES), newEntry.getDN(), ex.getMessage());
                log.error(msg, ex);
                throw new PublisherException(msg);
            }
        });
    }
    
    protected void writeLogEntryToLDAP(final LDAPConnection lc, final LDAPEntry newEntry) throws PublisherException {
        executeLDAPAction(lc, new LDAPConnectionAction<Void,PublisherException>() {
            @Override
            public Void performAction(final LDAPConnection lc) throws LDAPException {
                // Add the entry
                lc.add(newEntry, ldapStoreConstraints);
                String msg = intres.getLocalizedMessage("publisher.ldapadd", "log", newEntry.getDN());
                log.info(msg);
                return null;
            }
            @Override
            public void failed(final LDAPException ex) throws PublisherException {
                String msg = intres.getLocalizedMessage("publisher.errorldapstore", "log", newEntry.getAttributeSet(), newEntry.getAttribute("objectclass"), newEntry.getDN(), ex.getMessage());
                log.error(msg, ex);
                final PublisherException pe = new PublisherException();
                pe.initCause(ex);
                throw pe;
            }
        });
    }

    protected boolean isInited() {
        return inited;
    }

    protected List<String> getHostnames() {
        return hostnames;
    }

    protected boolean isUseSSL() {
        return useSSL;
    }

    protected String getPort() {
        return port;
    }

    protected String getBaseDN() {
        return baseDN;
    }

    protected String getLoginDN() {
        return loginDN;
    }

    protected String getLoginPassword() {
        return loginPassword;
    }

    protected boolean isLogConnectionTests() {
        return logConnectionTests;
    }

    protected int getTimeout() {
        return timeout;
    }

    protected LDAPConstraints getLdapConnectionConstraints() {
        return ldapConnectionConstraints;
    }

    protected LDAPConstraints getLdapBindConstraints() {
        return ldapBindConstraints;
    }

    protected LDAPConstraints getLdapStoreConstraints() {
        return ldapStoreConstraints;
    }

    protected LDAPConstraints getLdapDisconnectConstraints() {
        return ldapDisconnectConstraints;
    }

    protected LDAPSearchConstraints getLdapSearchConstraints() {
        return ldapSearchConstraints;
    }
    
    static class LogInfo {

        public static final String LEVEL_INFO = "info";
        public static final String LEVEL_ERROR = "err";
        public static final String LEVEL_DEBUG = "debug";
        private static final SimpleDateFormat SDF = new SimpleDateFormat("yyyyMMddHHmmss.SSS'Z'");

        static {
            SDF.setTimeZone(new SimpleTimeZone(0, "Z"));
        }

        public static String toGeneralizedTime(final Date date) {
            return SDF.format(date);
        }
        private final Date time;
        private final Integer sqn;
        private final String stage;
        private final String level;
        private final String msgid;
        private final String msg;
        private final String pid;
        private final String msgext;

        public LogInfo(Date time, String level, String msg) {
            this.time = time;
            this.sqn = null;
            this.stage = null;
            this.level = level;
            this.msgid = null;
            this.msg = msg;
            this.pid = null;
            this.msgext = null;
        }

        public LogInfo(Date time, Integer sqn, String stage, String level,
                String msgid, String msg, String pid, String msgext) {
            super();
            this.time = time;
            this.sqn = sqn;
            this.stage = stage;
            this.level = level;
            this.msgid = msgid;
            this.msg = msg;
            this.pid = pid;
            this.msgext = msgext;

            if (msgid != null && msgid.length() != 3) {
                throw new IllegalArgumentException("If specified msgid must be 3 characters in length");
            }
        }

        /*<time:[Generalized Time]> <sqn:[\d+]> <stage:[Named stage]> <level:[Level]> <msgid:
         [nnn]> <msg: [message]> <msgext: [extended extra info]>*/
        public String getEncoded() {
            return new StringBuilder()
                    .append(" ").append("time:").append(toGeneralizedTime(time))
                    .append(" ").append("sqn:").append(unlessNull(sqn))
                    .append(" ").append("stage:").append(unlessNull(stage))
                    .append(" ").append("level:").append(level)
                    .append(" ").append("msgid:").append(unlessNull(msgid))
                    .append(" ").append("msg:").append(msg)
                    .append(" ").append("pid:").append(unlessNull(pid))
                    .append(" ").append("msgext:").append(unlessNull(msgext))
                    .toString();
        }

        private String unlessNull(final Integer s) {
            return s == null ? "" : String.valueOf(s);
        }

        private String unlessNull(final String s) {
            return s == null ? "" : s;
        }

        public Date getTime() {
            return time;
        }

        public Integer getSqn() {
            return sqn;
        }

        public String getStage() {
            return stage;
        }

        public String getLevel() {
            return level;
        }

        public String getMsgid() {
            return msgid;
        }

        public String getMsg() {
            return msg;
        }

        public String getPid() {
            return pid;
        }

        public String getMsgext() {
            return msgext;
        }

        @Override
        public String toString() {
            return getEncoded();
        }
    }
}
