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

package org.ejbca.core.protocol.scep;

import java.io.IOException;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;

/**
 * 
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "ScepMessageDispatcherSessionRemote")
public class ScepMessageDispatcherSessionBean implements ScepMessageDispatcherSessionLocal, ScepMessageDispatcherSessionRemote {

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    private static final Logger log = Logger.getLogger(ScepMessageDispatcherSessionBean.class);
    
    private static final String SCEP_RA_MODE_EXTENSION_CLASSNAME = "org.ejbca.core.protocol.scep.ScepRaModeExtension";
    private static final String SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME = "org.ejbca.core.protocol.scep.ClientCertificateRenewalExtension";
    
    private transient ScepOperationPlugin scepRaModeExtension = null;
    private transient ScepResponsePlugin scepClientCertificateRenewal = null;
    
    @EJB
    private GlobalConfigurationSessionLocal globalConfigSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private CaSessionLocal caSession;
    
    
    @PostConstruct
    public void postConstruct() {
        try {
            @SuppressWarnings("unchecked")
            Class<? extends ScepOperationPlugin> extensionClass = (Class<? extends ScepOperationPlugin>) Class.forName(SCEP_RA_MODE_EXTENSION_CLASSNAME);
            scepRaModeExtension = extensionClass.newInstance();
        } catch (ClassNotFoundException e) {
            scepRaModeExtension = null;
        } catch (InstantiationException e) {
            scepRaModeExtension = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        } catch (IllegalAccessException e) {
            scepRaModeExtension = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        }
        
        try {
            @SuppressWarnings("unchecked")
            Class<ScepResponsePlugin> extensionClass = (Class<ScepResponsePlugin>) Class.forName(SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME);
            scepClientCertificateRenewal = extensionClass.newInstance();
        } catch (ClassNotFoundException e) {
            scepClientCertificateRenewal = null;
        } catch (InstantiationException e) {
            scepClientCertificateRenewal = null;
            log.error(SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        } catch (IllegalAccessException e) {
            scepClientCertificateRenewal = null;
            log.error(SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        }
    }
    
    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public byte[] dispatchRequest(final AuthenticationToken authenticationToken, final String operation, final String message, final String scepConfigurationAlias) 
            throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException, NoSuchEndEntityException, CustomCertificateSerialNumberException, 
            CryptoTokenOfflineException, IllegalKeyException, SignRequestException, SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, 
            CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, 
            SignatureException, CertificateException, CertificateExtensionException, CertificateRenewalException {
        
        ScepConfiguration scepConfig = (ScepConfiguration) this.globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        if(!scepConfig.aliasExists(scepConfigurationAlias)) {
            throw new NoSuchAliasException();
        }
        
        if (operation.equals("PKIOperation")) {
            byte[] scepmsg = Base64.decode(message.getBytes());
            // Read the message and get the certificate, this also checks authorization
            return scepCertRequest(authenticationToken, scepmsg, scepConfigurationAlias, scepConfig);
        } else if (operation.equals("GetCACert")) {
            // CA_IDENT is the message for this request to indicate which CA we are talking about
            final String caname = getCAName(message, scepConfig, scepConfigurationAlias);
            if (log.isDebugEnabled()) {
                log.debug("Got SCEP cert request for CA '" + caname + "'");
            }
            Collection<Certificate> certs = null;
            CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
            if (cainfo != null) {
                certs = cainfo.getCertificateChain();
            }
            if ((certs != null) && (certs.size() > 0)) {
                // CAs certificate is in the first position in the Collection
                X509Certificate cert = (X509Certificate) certs.iterator().next();
                if (log.isDebugEnabled()) {
                    log.debug("Sent certificate for CA '" + caname + "' to SCEP client.");
                }
                return cert.getEncoded();
            } else {
                return null;
            }
        } else if (operation.equals("GetCACertChain")) {
            // CA_IDENT is the message for this request to indicate which CA we are talking about
            final String caname = getCAName(message, scepConfig, scepConfigurationAlias);
            log.debug("Got SCEP pkcs7 request for CA '" + caname + "'. Old client using SCEP draft 18?");

            CAInfo cainfo = caSession.getCAInfo(authenticationToken, caname);
            byte[] pkcs7 = signSession.createPKCS7(authenticationToken, cainfo.getCAId(), true);
            if ((pkcs7 != null) && (pkcs7.length > 0)) {
                return pkcs7;
            } else {
                return null;
            }
        } else if (operation.equals("GetNextCACert")) {
            final String caname = getCAName(message, scepConfig, scepConfigurationAlias);
            if (log.isDebugEnabled()) {
                log.debug("Got SCEP next cert request for CA '" + caname + "'");
            }
            final CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
            if (cainfo == null) {
                String errMsg = intres.getLocalizedMessage("scep.errorunknownca", "GetNextCACert", caname);
                log.info(errMsg);
                throw new CADoesntExistsException(errMsg);
            } else {
                if (caSession.getFutureRolloverCertificate(cainfo.getCAId()) != null) {
                    // Send full certificate chain of next CA, in SCEP-PKCS7 format 
                    if (log.isDebugEnabled()) {
                        log.debug("Sending next certificate chain for CA '" + caname + "' to SCEP client.");
                    }
                    return signSession.createPKCS7Rollover(authenticationToken, cainfo.getCAId());
                } else {
                    return null;
                }
            }
        } else if (operation.equals("GetCACaps")) {
            final String caname = getCAName(message, scepConfig, scepConfigurationAlias);
            final CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
            if (cainfo != null) {
                final boolean hasRolloverCert = (caSession.getFutureRolloverCertificate(cainfo.getCAId()) != null);
                // SCEP draft 23, "4.6.1.  Get Next CA Response Message Format". 
                // It SHOULD also remove the GetNextCACert setting from the capabilities until it does have rollover certificates.            
                return  hasRolloverCert ?
                        "POSTPKIOperation\nGetNextCACert\nRenewal\nSHA-1".getBytes() :
                        "POSTPKIOperation\nRenewal\nSHA-1".getBytes();
            } else {
                final String msg = "CA was not found: "+caname;
                log.debug(msg);
                throw new CADoesntExistsException(msg);
            }
        } else {
            log.error("Invalid parameter '" + operation);
        }
        return null;
    }
    
    /**
     * Fetches the name of the CA to use for the SCEP response, as defined by the alias, the message provided in the
     * SCEP request and default CA defined by the property <code>scep.defaultca</code> in <code>ejbca.properties</code>.
     * 
     * <p>This function implements the requirements specified in section 5.2.1 of draft-nourse-scep-23.
     * 
     * <p>
     * <code>
     *   The OPERATION MUST be set to "GetCACert".<br>
     *   The MESSAGE MAY be omitted, or it MAY be a string that represents the<br>
     *   certification authority issuer identifier.  A CA Administrator<br>
     *   defined string allows for multiple CAs supported by one SCEP server.<br>
     * </code>
     * 
     * <p>The function returns the CA name specified in the message. If the message is empty and the alias is operating 
     * in RA mode, it returns the CA name specified by the alias. If the alias is operating in CA mode, it returns the
     * name of the default SCEP CA defined by the property <code>scep.defaultca</code>. If no such property is defined
     * an exception is thrown with a user-friendly error message.
     * 
     * @param caName the name of the CA as indicated by the message sent by the SCEP client.
     * @param scepConfiguration the SCEP configuration of this EJBCA instance
     * @param alias the alias being used by the SCEP client
     * @return the name of the CA which should be used to serve this request, never null
     * @throws CADoesntExistsException if CA mode if being used for the alias, no message is provided and the default SCEP CA is undefined.
     */
    private String getCAName(final String caName, final ScepConfiguration scepConfiguration, final String alias) throws CADoesntExistsException {
        if (!StringUtils.isEmpty(caName)) {
            // Use the CA defined by the message if present
            return caName;
        }
        if (scepConfiguration.getRAMode(alias)) {
            // When in RA mode, use the CA defined by the alias
            return scepConfiguration.getRADefaultCA(alias);
        }
        // Use the CA defined by the property scep.defaultca in CA mode. If not defined, throw an error.
        final String defaultCa = EjbcaConfiguration.getScepDefaultCA();
        if (StringUtils.isEmpty(defaultCa)) {
            throw new CADoesntExistsException("The SCEP alias " + alias
                    + " is in CA mode, the message parameter in the GET request is empty, and no default "
                    + "CA has been defined for SCEP. Either switch to RA mode, provide the name of the CA "
                    + "in the message, or specify the default CA using the scep.defaultca property.");
        }
        return defaultCa;
    }
    
    /**
     * Handles SCEP certificate request
     *
     * @param msg buffer holding the SCEP-request (DER encoded).
     * @param alias the alias of the SCEP configuration
     * @param scepConfig The SCEP configuration
     *
     * @return byte[] containing response to be sent to client.
     * @throws AuthorizationDeniedException 
     * @throws CertificateExtensionException if msg specified invalid extensions
     * @throws InvalidAlgorithmException 
     * @throws CAOfflineException 
     * @throws IllegalValidityException 
     * @throws CertificateSerialNumberException 
     * @throws CertificateRevokeException 
     * @throws CertificateCreateException 
     * @throws IllegalNameException 
     * @throws AuthLoginException 
     * @throws AuthStatusException 
     * @throws SignRequestSignatureException 
     * @throws SignRequestException 
     * @throws CADoesntExistsException 
     * @throws IllegalKeyException 
     * @throws CryptoTokenOfflineException 
     * @throws CustomCertificateSerialNumberException 
     * @throws CertificateRenewalException if an error occurs during Client Certificate Renewal
     * @throws SignatureException if a Client Certificate Renewal request was badly signed. 
     * @throws CertificateException 
     * @throws {@link NoSuchEndEntityException} if end entity wasn't found, and RA mode isn't available. 
     */
    private byte[] scepCertRequest(AuthenticationToken administrator, byte[] msg, final String alias, final ScepConfiguration scepConfig)
            throws AuthorizationDeniedException, CertificateExtensionException, NoSuchEndEntityException, CustomCertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException,
            AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            CertificateRenewalException, SignatureException, CertificateException {
      byte[] ret = null;
        if (log.isTraceEnabled()) {
            log.trace(">getRequestMessage(" + msg.length + " bytes)");
        }
        
        try {
            boolean includeCACert = scepConfig.getIncludeCA(alias);
            final ScepRequestMessage reqmsg = new ScepRequestMessage(msg, includeCACert);        
            boolean isRAModeOK = scepConfig.getRAMode(alias);

            if (reqmsg.getErrorNo() != 0) {
                log.error("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
                return null;
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
                if (isRAModeOK && scepRaModeExtension == null) {
                    // Fail nicely
                    log.warn("SCEP RA mode is enabled, but not included in the community version of EJBCA. Unable to continue.");
                    return null;
                } else if (isRAModeOK) {
                    if (log.isDebugEnabled()) {
                        log.debug("SCEP is operating in RA mode: " + isRAModeOK);
                    }
                    if (!scepRaModeExtension.performOperation(administrator, reqmsg, scepConfig, alias)) {
                        String errmsg = "Error. Failed to add or edit user: " + reqmsg.getUsername();
                        log.error(errmsg);
                        return null;
                    }
                }
                if (scepClientCertificateRenewal != null && scepConfig.getClientCertificateRenewal(alias)) {
                    if (log.isDebugEnabled()) {
                        log.debug("SCEP client certificate renewal/enrollment with alias '"+alias+"'");
                    }
                    ResponseMessage resp = scepClientCertificateRenewal.performOperation(administrator, reqmsg, scepConfig, alias);
                    if (resp != null) {
                        ret = resp.getResponseMessage();
                    }
                } else {                
                    // Get the certificate 
                    if (log.isDebugEnabled()) {
                        log.debug("SCEP certificate enrollment with alias '"+alias+"'");
                    }
                    ResponseMessage resp = signSession.createCertificate(administrator, reqmsg, ScepResponseMessage.class, null);
                    if (resp != null) {
                        ret = resp.getResponseMessage();
                    }
                }
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
                // create the stupid encrypted CRL message, the below can actually only be made 
                // at the CA, since CAs private key is needed to decrypt
                ResponseMessage resp = signSession.getCRL(administrator, reqmsg, ScepResponseMessage.class);
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ", e);
        } 
        if (log.isTraceEnabled()) {
            log.trace("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));
        }
        return ret;
    }
}
