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
package org.ejbca.scp.publisher;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.ExternalScriptsAllowlist;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.CustomPublisherProperty;
import org.ejbca.core.model.ca.publisher.CustomPublisherUiSupport;
import org.ejbca.core.model.ca.publisher.ICustomPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.util.EjbLocalHelper;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

/**
 * This class is used for publishing certificates and CRLs to a remote destination over scp. 
 */
public class ScpPublisher extends CustomPublisherContainer implements ICustomPublisher, CustomPublisherUiSupport {

    private static final long serialVersionUID = 1L;
    private static Logger log = Logger.getLogger(ScpPublisher.class);
    public static final String ANONYMIZE_CERTIFICATES_PROPERTY_NAME = "anonymize.certificates";

    public static final String SIGNING_CA_PROPERTY_NAME = "signing.ca.id";
    public static final String SSH_USERNAME = "ssh.username";
    public static final String SSH_PORT = "ssh.port";
    public static final String CRL_SCP_DESTINATION_PROPERTY_NAME = "crl.scp.destination";
    public static final String CERT_SCP_DESTINATION_PROPERTY_NAME = "cert.scp.destination";
    public static final String SCP_PRIVATE_KEY_PASSWORD_NAME = "scp.privatekey.password";
    public static final String SCP_PRIVATE_KEY_PROPERTY_NAME = "scp.privatekey";
    public static final String SCP_KNOWN_HOSTS_PROPERTY_NAME = "scp.knownhosts";
    public static final int DEFAULT_SSH_PORT_NUMBER = 22;

    private static final String EKU_PKIX_OCSPSIGNING = "1.3.6.1.5.5.7.3.9";

    private int signingCaId = -1;

    private boolean anonymizeCertificates;

    private String crlSCPDestination = null;
    private String certSCPDestination = null;
    private String scpPrivateKey = null;
    private String scpKnownHosts = null;
    private String sshUsername = null;
    private Integer sshPort = null;
    private String privateKeyPassword = null;
    
    private  Map<String, CustomPublisherProperty> properties = new LinkedHashMap<>();


    public ScpPublisher() {
    }

    /**
     * Load used properties.
     * 
     * @param properties
     *            The properties to load.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    @Override
    public void init(Properties properties) {
        if (log.isTraceEnabled()) {
            log.trace(">init");
        }
        signingCaId = getIntProperty(properties, SIGNING_CA_PROPERTY_NAME);
        anonymizeCertificates = getBooleanProperty(properties, ANONYMIZE_CERTIFICATES_PROPERTY_NAME);
        crlSCPDestination = getProperty(properties, CRL_SCP_DESTINATION_PROPERTY_NAME);
        certSCPDestination = getProperty(properties, CERT_SCP_DESTINATION_PROPERTY_NAME);
        scpPrivateKey = getProperty(properties, SCP_PRIVATE_KEY_PROPERTY_NAME);
        scpKnownHosts = getProperty(properties, SCP_KNOWN_HOSTS_PROPERTY_NAME);
        sshUsername = getProperty(properties, SSH_USERNAME);
        try {
            sshPort = parsePort(getProperty(properties, SSH_PORT));
        } catch (PublisherException e) {
            sshPort = null;
        }
        try {
            privateKeyPassword = decryptPassword(getProperty(properties, SCP_PRIVATE_KEY_PASSWORD_NAME));
        } catch (PublisherException e) {
            // TODO: could go for passing with `privateKeyPassword = null` if validation was in place
            //       telling that password being stored is wrong; but that needs a little bit more work
            throw new IllegalStateException("Could not decrypt encoded private key password.", e);
        }

        this.properties.put(SIGNING_CA_PROPERTY_NAME, new CustomPublisherProperty(SIGNING_CA_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, null,
                null, Integer.valueOf(signingCaId).toString()));
        this.properties.put(ANONYMIZE_CERTIFICATES_PROPERTY_NAME, new CustomPublisherProperty(ANONYMIZE_CERTIFICATES_PROPERTY_NAME,
                CustomPublisherProperty.UI_BOOLEAN, Boolean.valueOf(anonymizeCertificates).toString()));
        this.properties.put(SSH_USERNAME, new CustomPublisherProperty(SSH_USERNAME, CustomPublisherProperty.UI_TEXTINPUT, sshUsername));
        this.properties.put(SSH_PORT, new CustomPublisherProperty(SSH_PORT, CustomPublisherProperty.UI_TEXTINPUT, sshPort != null ? Integer.toString(sshPort) : ""));
        this.properties.put(CRL_SCP_DESTINATION_PROPERTY_NAME,
                new CustomPublisherProperty(CRL_SCP_DESTINATION_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, crlSCPDestination));
        this.properties.put(CERT_SCP_DESTINATION_PROPERTY_NAME,
                new CustomPublisherProperty(CERT_SCP_DESTINATION_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, certSCPDestination));
        this.properties.put(SCP_PRIVATE_KEY_PROPERTY_NAME,
                new CustomPublisherProperty(SCP_PRIVATE_KEY_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, scpPrivateKey));
        this.properties.put(SCP_PRIVATE_KEY_PASSWORD_NAME,
                new CustomPublisherProperty(SCP_PRIVATE_KEY_PASSWORD_NAME, CustomPublisherProperty.UI_TEXTINPUT_PASSWORD, privateKeyPassword));
        this.properties.put(SCP_KNOWN_HOSTS_PROPERTY_NAME,
                new CustomPublisherProperty(SCP_KNOWN_HOSTS_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, scpKnownHosts));

    }

    @Override
    public Set<String> getDeclaredPropertyNames() {
        return Set.of(
                SIGNING_CA_PROPERTY_NAME,
                ANONYMIZE_CERTIFICATES_PROPERTY_NAME,
                SSH_USERNAME,
                SSH_PORT,
                CRL_SCP_DESTINATION_PROPERTY_NAME,
                CERT_SCP_DESTINATION_PROPERTY_NAME,
                SCP_PRIVATE_KEY_PROPERTY_NAME,
                SCP_PRIVATE_KEY_PASSWORD_NAME,
                SCP_KNOWN_HOSTS_PROPERTY_NAME
        );
    }


    private String decryptPassword(String encryptedPassword) throws PublisherException {
        // Password is encrypted on the database, using the key password.encryption.key
        if (StringUtils.isNotEmpty(encryptedPassword)) {
            try {
                return StringTools.pbeDecryptStringWithSha256Aes192(encryptedPassword);
            } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException |
                     InvalidKeySpecException e) {
                throw new PublisherException("Could not decrypt encoded private key password.", e);
            }
        }
        return "";
    }

    @Override
    public List<CustomPublisherProperty> getCustomUiPropertyList(AuthenticationToken authenticationToken) {
        List<CustomPublisherProperty> customProperties = new ArrayList<>();
        
        CaSessionLocal caSession = new EjbLocalHelper().getCaSession();
        List<String> authorizedCaIds = new ArrayList<>();
        List<String> authorizedCaNames = new ArrayList<>();
        final Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        authorizedCaIds.add("-1");
        authorizedCaNames.add("None");
        for(Integer caId : caSession.getAuthorizedCaIds(authenticationToken)) {
            authorizedCaIds.add(caId.toString());
            authorizedCaNames.add(caIdToNameMap.get(caId));
        }
        for(final String key : properties.keySet()) {
            if(key.equals(SIGNING_CA_PROPERTY_NAME)) {
                customProperties.add(new CustomPublisherProperty(SIGNING_CA_PROPERTY_NAME, CustomPublisherProperty.UI_SELECTONE, authorizedCaIds, authorizedCaNames,
                        Integer.valueOf(signingCaId).toString()));
            } else {
                customProperties.add(properties.get(key));
            }
        }     
        return customProperties;
    }

    @Override
    public List<String> getCustomUiPropertyNames() {
        return new ArrayList<>(properties.keySet());
    }

    @Override
    public void validateProperty(String name, String value) throws PublisherException {
        validate(name, value);
    }

    public static void validate(String name, String value) throws PublisherException {
        if (SSH_PORT.equals(name)) {
            parsePort(value);
        }
    }

    @Override
    public int getPropertyType(String label) {
        CustomPublisherProperty property = properties.get(label);
        if(property == null) {
            return -1;
        } else {
            return property.getType();
        }
    }


    private String getProperty(Properties properties, String propertyName) {
        String property = properties.getProperty(propertyName);
        if (property == null) {
            return "";
        } else {
            return property;
        }
    }

    private boolean getBooleanProperty(Properties properties, String propertyName) {
        String property = getProperty(properties, propertyName);
        if (property.equalsIgnoreCase("true")) {
            return true;
        } else {
            return false;
        }
    }
    
    private int getIntProperty(Properties properties, String propertyName) {
        String property = getProperty(properties, propertyName);
        if (StringUtils.isEmpty(property)) {
            return -1;
        } else {
            return Integer.valueOf(property);
        }
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCertificate, Storing Certificate for user: " + username);
        }
        if ((status == CertificateConstants.CERT_REVOKED) || (status == CertificateConstants.CERT_ACTIVE)) {
            // Don't publish non-active certificates
            try {
                byte[] certBlob = incert.getEncoded();
                X509Certificate x509cert = (X509Certificate) incert;
                String issuerDN = CertTools.getIssuerDN(incert);
                boolean redactInformation = anonymizeCertificates && type == CertificateConstants.CERTTYPE_ENDENTITY;
                if (redactInformation) {
                    List<String> ekus = x509cert.getExtendedKeyUsage();
                    if (ekus != null) {
                        for (String eku : ekus) {
                            if (eku.equals(EKU_PKIX_OCSPSIGNING)) {
                                redactInformation = false;
                            }
                        }
                    }
                }
                // @formatter:off
                ScpContainer scpContainer = new ScpContainer()
                        .setCertificateStatus(status)
                        .setIssuer(issuerDN)
                        .setRevocationDate(revocationDate)
                        .setRevocationReason(revocationReason)
                        .setSerialNumber(x509cert.getSerialNumber());
                // If we don't redact information, add in the certificate itself, as well as any other interesting info. 
                if (!redactInformation) {
                    scpContainer.setCertificate(incert)
                    .setUsername(username)
                    .setCertificateType(type)
                    .setCertificateProfile(certificateProfileId)
                    .setUpdateTime(lastUpdate);
                }         
                // @formatter:on
                byte[] encodedObject = scpContainer.getEncoded();              
                final String fileName = CertTools.getFingerprintAsString(certBlob);
                performScp(signingCaId, fileName, sshUsername, sshPort, encodedObject, certSCPDestination, scpPrivateKey, privateKeyPassword, scpKnownHosts);
            } catch (GeneralSecurityException | IOException | JSchException e) {
                String msg = e.getMessage();
                log.error(msg);
                throw new PublisherException(msg, e);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<storeCertificate");
        }
        return true;
    }

    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCRL, Storing CRL");
        }
        String fileName = CertTools.getFingerprintAsString(incrl) + ".crl";
        try {
            // No use in signing a CRL - it's already signed - just write it in cleartext.
            performScp(-1, fileName, sshUsername, sshPort, incrl, crlSCPDestination, scpPrivateKey, privateKeyPassword, scpKnownHosts);
        } catch (JSchException | IOException e) {
            String msg = e.getMessage();
            log.error(msg == null ? "Unknown error" : msg, e);
            throw new PublisherException(msg);
        }

        if (log.isTraceEnabled()) {
            log.trace("<storeCRL");
        }
        return true;
    }

    /**
     * 
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection()
     */
    @Override
    public void testConnection() throws PublisherConnectionException {
        if (StringUtils.isBlank(certSCPDestination) && StringUtils.isBlank(crlSCPDestination)){
            throw new PublisherConnectionException("Neither Certificate nor CRL destination URLs are configured.");
        }
        final JSch jsch = new JSch();
        try {
            if (privateKeyPassword != null) {
                jsch.addIdentity(scpPrivateKey, privateKeyPassword);
            } else {
                jsch.addIdentity(scpPrivateKey);
            }
        } catch (JSchException e) {
            final String msg = "Could not access private key. ";
            log.info(msg + e.getMessage());
            throw new PublisherConnectionException(msg, e);
        }
        try {
            jsch.setKnownHosts(scpKnownHosts);
        } catch (JSchException e) {
            final String msg = "Could not access known_hosts file. ";
            log.info(msg + e.getMessage());
            throw new PublisherConnectionException(msg, e);
        }

        final List<PublisherConnectionException> caughtExceptions = new ArrayList<>();
        if (StringUtils.isNotEmpty(certSCPDestination)) {
            Session session = null;
            try {
                final Destination destination = buildDestination(certSCPDestination, sshPort);
                session = destination.port != null
                    ? jsch.getSession(sshUsername, destination.host, destination.port)
                    : jsch.getSession(sshUsername, destination.host);
                session.connect();
            } catch (JSchException e) {
                String msg = "Could not connect to certificate destination.";
                if(e.getMessage().contains("USERAUTH fail")) {
                    msg += "Private key file could not be accessed.";
                }
                log.info(msg + e.getMessage());
                caughtExceptions.add(new PublisherConnectionException(msg, e));
            } catch (PublisherException e) {
                caughtExceptions.add(new PublisherConnectionException(e.getMessage(), e.getCause()));
            } finally {
                if (session != null) {
                    session.disconnect();
                }
            }
        }
        if (StringUtils.isNotEmpty(crlSCPDestination)) {
            Session session = null;
            try {
                final Destination destination = buildDestination(crlSCPDestination, sshPort);
                session = destination.port != null
                    ? jsch.getSession(sshUsername, destination.host, destination.port)
                    : jsch.getSession(sshUsername, destination.host);
                session.connect();
            } catch (JSchException e) {
                String msg = "Could not connect to CRL destination. ";
                if(e.getMessage().contains("USERAUTH fail")) {
                    msg += "Private key file could not be accessed.";
                } 
                log.info(msg + e.getMessage());
                caughtExceptions.add(new PublisherConnectionException(msg, e));
            } catch (PublisherException e) {
                caughtExceptions.add(new PublisherConnectionException(e.getMessage(), e.getCause()));
            } finally {
                if (session != null) {
                    session.disconnect();
                }
            }
        }

        if (!caughtExceptions.isEmpty()) {
            final StringBuilder msg = new StringBuilder("Could not connect to destination(s). Reasons: ");
            for (PublisherConnectionException e : caughtExceptions) {
                msg.append("\n");
                msg.append(e.getMessage());
            }
            throw new PublisherConnectionException(msg.toString());
        }
    }

    @Override
    public boolean willPublishCertificate(int status, long revocationDate) {
        return true;
    }

    @Override
    public boolean isReadOnly() {
        return false;
    }

    @Override
    public boolean isCallingExternalScript() {
        return false;        
    }

    @Override
    public void setExternalScriptsAllowlist(ExternalScriptsAllowlist allowList) {
        // Method not applicable for this publisher type!        
    }

    /**
     * Copies the given file to the destination over SCP 
     * 
     * @param signingCaId The signing CA ID. May be -1 if no signing is required. 
     * @param destinationFileName The filename at the destination
     * @param username the username connected to the private key
     * @param port the port to be used for given host
     * @param data a byte array containing the data to be written
     * @param destinationPath the full path to the destination in the format host[:path]
     * @param privateKeyPassword the password required to unlock the private key. May be null if the private key is not locked.
     * @param privateKeyPath path to the local private key. This is also used as the identifying name of the key. The corresponding public key is 
     *  assumed to be in a file with the same name with suffix .pub.
     * @param knownHostsFile the path to the .hosts file in the system
     * @throws JSchException if an SSH connection could not be established
     * @throws IOException if the file could not be written over the channel 
     * @throws PublisherException is signing was required by failed for whatever reason
     */
    private void performScp(final int signingCaId, final String destinationFileName,
            final String username, final Integer port, final byte[] data, String destinationPath, final String privateKeyPath, final String privateKeyPassword,
            final String knownHostsFile) throws JSchException, IOException, PublisherException {
        if(!(new File(privateKeyPath)).exists()) {
            throw new IllegalArgumentException("Private key file " + privateKeyPath + " was not found");
        }
        if(!(new File(knownHostsFile)).exists()) {
            throw new IllegalArgumentException("Hosts file " + knownHostsFile + " was not found");
        }
        
        byte[] signedBytes;
        if (signingCaId != -1) {
            if(log.isDebugEnabled()) {
                log.debug("Signing payload with signing key from CA with ID " + signingCaId);
            }
            try {
                signedBytes = new EjbLocalHelper().getSignSession().signPayload(data, signingCaId);
            } catch (CryptoTokenOfflineException | CADoesntExistsException | SignRequestSignatureException | AuthorizationDeniedException e) {
                if(log.isDebugEnabled()) {
                    log.debug("Could not sign certificate", e);
                }
                throw new PublisherException("Could not sign certificate", e);
            }
        } else {
            if(log.isDebugEnabled()) {
                log.debug("Signing CA not defined, publishing raw certificate.");
            }
            // If no signing CA is defined, just publish the ScpContainer in its raw form
            signedBytes = data;
        }
        Destination destination = buildDestination(destinationPath, port);
        JSch jsch = new JSch();
        if (privateKeyPassword != null) {
            jsch.addIdentity(privateKeyPath, privateKeyPassword);
        } else {
            jsch.addIdentity(privateKeyPath);
        }
        jsch.setKnownHosts(knownHostsFile);
        Session session = null;
        Channel channel = null;
        OutputStream out = null;
        try {
            session = destination.port != null
                ? jsch.getSession(username, destination.host, destination.port)
                : jsch.getSession(username, destination.host);
            session.connect();
            // exec 'scp [-P port] -t path' remotely
            String command = destination.port != null
                ? String.format("scp -P %d -p -t %s", destination.port, destination.path)
                : String.format("scp -p -t %s", destination.path);
            channel = session.openChannel("exec");
            ((ChannelExec) channel).setCommand(command);
            // get I/O streams for remote scp
            out = channel.getOutputStream();
            InputStream in = channel.getInputStream();
            channel.connect();
            checkAck(in);
            // send "C0644 filesize filename", where filename should not include '/'
            long filesize = signedBytes.length;
            command = "C0644 " + filesize + " " + destinationFileName + "\n";
            out.write(command.getBytes());
            out.flush();
            checkAck(in);
            out.write(signedBytes);
            // send '\0'
            byte[] buf = new byte[1];
            buf[0] = 0;
            out.write(buf, 0, 1);
            out.flush();
            checkAck(in);
        } finally {
            if (out != null) {
                out.close();
            }
            if (channel != null) {
                channel.disconnect();
            }
            if (session != null) {
                session.disconnect();
            }
        }
    }

    private void checkAck(InputStream in) throws IOException {
        int b = in.read();
        // b may be 0 for success,
        // 1 for error,
        // 2 for fatal error,
        // -1
        if (b <= 0) {
            return;
        }
        StringBuffer sb = new StringBuffer();
        int c;
        do {
            c = in.read();
            sb.append((char) c);
        } while (c != '\n');
        throw new IOException("SCP error: " + sb.toString());
    }

    private Destination buildDestination(String destination, Integer port) throws PublisherException {
        // clean out any usernames which may have been added to the destination by mistake
        destination = destination.substring(destination.indexOf('@') + 1);
        int firstColonIndex = destination.indexOf(':');
        String host = firstColonIndex < 0 ? destination : destination.substring(0, firstColonIndex);
        String path = firstColonIndex < 0 ? "" : destination.substring(firstColonIndex + 1);

        return new Destination(host, path, port);
    }

    // used in ConfigDump
    public Integer getSshPort() {
        return sshPort;
    }

    private static Integer parsePort(String portInput) throws PublisherException {
        if (portInput.matches("0*\\d{1,5}")) {
            int port = Integer.parseInt(portInput);

            if (port > 0 && port < 65536) {
                return port;
            }

        } else if (portInput.isBlank()) {
            return null;
        }

        throw new PublisherException("Port needs to be a whole number between 1 and 65535");
    }

    // TODO: use the following instead when possible (Java 14+/17) or apply for Lombok:
    //   private record Destination(String host, String path, int port) {}
    private static final class Destination {

        private final String host;
        private final String path;
        private final Integer port;

        private Destination(String host, String path, Integer port) {
            this.host = host;
            this.path = path;
            this.port = port;
        }
    }

}
