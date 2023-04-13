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
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.azure.AzureException;
import org.cesecore.azure.IntuneRestApi;
import org.cesecore.azure.IntuneRestApi.Builder;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.FailInfo;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityApprovalRequest;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.impl.AuthenticationKeyBinding;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.ScepResponseInfo;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.NoSuchAliasException;
import org.ejbca.ui.web.protocol.CertificateRenewalException;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

import static org.apache.commons.lang.StringUtils.isNotBlank;

/** Implements processing of SCEP requests.
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

    private static final Random secureRandom = new SecureRandom();

    @EJB
    private ApprovalSessionLocal approvalSession;
    @EJB
    private ApprovalProfileSessionLocal approvalProfileSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CryptoTokenSessionLocal cryptoTokenSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @PostConstruct
    public void postConstruct() {
        try {
            @SuppressWarnings("unchecked")
            Class<? extends ScepOperationPlugin> extensionClass = (Class<? extends ScepOperationPlugin>) Class
                    .forName(SCEP_RA_MODE_EXTENSION_CLASSNAME);
            Constructor<? extends ScepOperationPlugin> extensionConstructor = extensionClass.getDeclaredConstructor();
            scepRaModeExtension = extensionConstructor.newInstance();
        } catch (ClassNotFoundException e) {
            scepRaModeExtension = null;
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            scepRaModeExtension = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        } 

        try {
            @SuppressWarnings("unchecked")
            Class<ScepResponsePlugin> extensionClass = (Class<ScepResponsePlugin>) Class.forName(SCEP_CLIENT_CERTIFICATE_RENEWAL_CLASSNAME);
            Constructor<? extends ScepResponsePlugin> extensionConstructor = extensionClass.getDeclaredConstructor();
            scepClientCertificateRenewal = extensionConstructor.newInstance();
        } catch (ClassNotFoundException e) {
            scepClientCertificateRenewal = null;
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            scepRaModeExtension = null;
            log.error(SCEP_RA_MODE_EXTENSION_CLASSNAME + " was found, but could not be instanced. " + e.getMessage());
        } 
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public byte[] dispatchRequest(final AuthenticationToken authenticationToken, final String operation, final String message,
            final String scepConfigurationAlias) throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException,
            NoSuchEndEntityException, CustomCertificateSerialNumberException, CryptoTokenOfflineException, IllegalKeyException, SignRequestException,
            SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException,
            CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            SignatureException, CertificateException, CertificateExtensionException, CertificateRenewalException {

        // call the Intune version, which contains additional fields, but only return the SCEP response
        final ScepResponseInfo response = dispatchRequestIntune(authenticationToken, operation, message, scepConfigurationAlias);
        if (response == null) {
            return null;
        } else {
            return response.getPkcs7Response();
        }
    }

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public ScepResponseInfo dispatchRequestIntune(final AuthenticationToken authenticationToken, final String operation, final String message,
            final String scepConfigurationAlias) throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException,
            NoSuchEndEntityException, CustomCertificateSerialNumberException, CryptoTokenOfflineException, IllegalKeyException, SignRequestException,
            SignRequestSignatureException, AuthStatusException, AuthLoginException, IllegalNameException, CertificateCreateException,
            CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException,
            SignatureException, CertificateException, CertificateExtensionException, CertificateRenewalException {

        ScepConfiguration scepConfig = (ScepConfiguration) this.globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        if (!scepConfig.aliasExists(scepConfigurationAlias)) {
            throw new NoSuchAliasException();
        }

        if (operation.equals("PKIOperation")) {
            byte[] scepmsg = Base64.decode(message.getBytes());
            // Read the message and get the certificate, this also checks authorization
            return scepCertRequest(authenticationToken, scepmsg, scepConfigurationAlias, scepConfig);
        } else if (operation.equals("GetCACert")) {
            // CA_IDENT is the message for this request to indicate which CA we are talking about
            final String caname = getCaName(message, scepConfig, scepConfigurationAlias);
            if (log.isDebugEnabled()) {
                log.debug("Got SCEP cert request for CA '" + caname + "'");
            }
            Collection<Certificate> certs = null;
            CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
            if (cainfo != null) {
                certs = cainfo.getCertificateChain();
            }
            if (certs == null) {
                return null;
            } else if (certs.size() == 1 || (!scepConfig.getReturnCaChainInGetCaCert(scepConfigurationAlias) && certs.size() > 1)) {
                if (log.isDebugEnabled()) {
                    log.debug("Returning X.509 certificate as response for GetCACert for single CA: " + caname);
                }
                // CAs certificate is in the first position in the Collection
                X509Certificate cert = (X509Certificate) certs.iterator().next();
                if (log.isDebugEnabled()) {
                    log.debug("Sent certificate for CA '" + caname + "' to SCEP client.");
                }
                return ScepResponseInfo.onlyResponseBytes(cert.getEncoded());
            } else if (certs.size() > 1 && scepConfig.getReturnCaChainInGetCaCert(scepConfigurationAlias)) {
                try {
                    if (log.isDebugEnabled()) {
                        log.debug("Creating certs-only CMS message as response for GetCACert for CA chain: " + caname);
                    }
                    List<X509Certificate> certList = CertTools.convertCertificateChainToX509Chain(certs);
                    // TODO: test workaround for certificate order, MS likes it reverse?
                    Collections.reverse(certList);
                    final byte[] resp = CertTools.createCertsOnlyCMS(certList);
                    if (log.isDebugEnabled()) {
                        log.debug("Sent certificates-only CMS for CA '" + caname + "' to SCEP client.");
                    }
                    return ScepResponseInfo.onlyResponseBytes(resp);
                } catch (ClassCastException | CMSException e) {
                    log.info("Error creating certs-only CMS message as response for GetCACert for CA: " + caname);
                    return null;
                }
            }
        } else if (operation.equals("GetCACertChain")) {
            // CA_IDENT is the message for this request to indicate which CA we are talking about
            final String caname = getCaName(message, scepConfig, scepConfigurationAlias);
            log.debug("Got SCEP pkcs7 request for CA '" + caname + "'. Old client using SCEP draft 18?");

            CAInfo cainfo = caSession.getCAInfo(authenticationToken, caname);
            byte[] pkcs7 = signSession.createPKCS7(authenticationToken, cainfo.getCAId(), true);
            if ((pkcs7 != null) && (pkcs7.length > 0)) {
                return ScepResponseInfo.onlyResponseBytes(pkcs7);
            } else {
                return null;
            }
        } else if (operation.equals("GetNextCACert")) {
            final String caname = getCaName(message, scepConfig, scepConfigurationAlias);
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
                    return ScepResponseInfo.onlyResponseBytes(signSession.createPKCS7Rollover(authenticationToken, cainfo.getCAId()));
                } else {
                    return null;
                }
            }
        } else if (operation.equals("GetCACaps")) {
            final String caname = getCaName(message, scepConfig, scepConfigurationAlias);
            final CAInfo cainfo = caSession.getCAInfoInternal(-1, caname, true);
            if (cainfo != null) {
                final boolean hasRolloverCert = (caSession.getFutureRolloverCertificate(cainfo.getCAId()) != null);
                // SCEP draft 23, "4.6.1.  Get Next CA Response Message Format". 
                // It SHOULD also remove the GetNextCACert setting from the capabilities until it does have rollover certificates.            
                return hasRolloverCert
                        ? ScepResponseInfo.onlyResponseBytes("POSTPKIOperation\nGetNextCACert\nRenewal\nSHA-512\nSHA-256\nSHA-1\nDES3\nAES\nSCEPStandard".getBytes())
                        : ScepResponseInfo.onlyResponseBytes("POSTPKIOperation\nRenewal\nSHA-512\nSHA-256\nSHA-1\nDES3\nAES\nSCEPStandard".getBytes());
            } else {
                final String msg = "CA was not found: " + caname;
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
    private String getCaName(final String caName, final ScepConfiguration scepConfiguration, final String alias) throws CADoesntExistsException {
        if (scepConfiguration.getUseIntune(alias)) {
            //Always return the scep
            return scepConfiguration.getRADefaultCA(alias);
        }

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
            throw new CADoesntExistsException(
                    "The SCEP alias " + alias + " is in CA mode, the message parameter in the GET request is empty, and no default "
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
    private ScepResponseInfo scepCertRequest(AuthenticationToken administrator, byte[] msg, final String alias, final ScepConfiguration scepConfig)
            throws AuthorizationDeniedException, CertificateExtensionException, NoSuchEndEntityException, CustomCertificateSerialNumberException,
            CryptoTokenOfflineException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException,
            AuthLoginException, IllegalNameException, CertificateCreateException, CertificateRevokeException, CertificateSerialNumberException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException, CertificateRenewalException, SignatureException,
            CertificateException {
        byte[] ret = null;
        IntuneScepData intuneData = null;

        if (log.isTraceEnabled()) {
            log.trace(">getRequestMessage(" + msg.length + " bytes)");
        }

        boolean includeCACert = scepConfig.getIncludeCA(alias);
        ScepRequestMessage reqmsg;
        try {
            reqmsg = new ScepRequestMessage(msg, includeCACert);
        } catch (IOException e) {
            log.info("Error receiving ScepMessage: ", e);
            return null;
        }

        boolean isRAModeOK = scepConfig.getRAMode(alias);

        if (reqmsg.getErrorNo() != 0) {
            log.info("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
            return null;
        }
        if (scepConfig.getAllowLegacyDigestAlgorithm(alias)) {
            reqmsg.setPreferredDigestAlg(reqmsg.getOriginalDigestAlgorithm());
            log.debug("Allow Legacy Digest Algorithm is configured for this SCEP alias, setting response digest algorithm to "
                    + reqmsg.getOriginalDigestAlgorithm());
        }
        if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
            if (isRAModeOK && scepRaModeExtension == null) {
                // Fail nicely
                log.warn("SCEP RA mode is enabled, but not included in the community version of EJBCA. Unable to continue.");
                return null;
            } else if (isRAModeOK) {
                if (log.isDebugEnabled()) {
                    log.debug("Received a SCEP PKCSREQ message, operating in RA mode: " + isRAModeOK);
                }
                try {
                    if (!scepRaModeExtension.performOperation(administrator, reqmsg, scepConfig, alias)) {
                        String errmsg = "Error. Failed to add or edit user: " + reqmsg.getUsername();
                        log.info(errmsg);
                        return null;
                    }
                } catch (WaitingForApprovalException e) {
                    //Return a pending response message, because this request is now waiting to be approved
                    if (log.isDebugEnabled()) {
                        log.debug("Returning a PENDING message to PKCSREQ request for end entity '" + reqmsg.generateUsername(scepConfig, alias)
                                + "' to SCEP alias '" + alias + "'");
                    }
                    X509CAInfo cainfo = (X509CAInfo) caSession.getCAInfoInternal(-1, scepConfig.getRADefaultCA(alias), true);
                    ResponseMessage resp = createPendingResponseMessage(reqmsg, cainfo);
                    return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
                }
            }
            try {
                if (scepClientCertificateRenewal != null && scepConfig.getClientCertificateRenewal(alias)) {
                    if (log.isDebugEnabled()) {
                        log.debug("SCEP client certificate renewal/enrollment with alias '" + alias + "'");
                    }
                    ResponseMessage resp = scepClientCertificateRenewal.performOperation(administrator, reqmsg, scepConfig, alias);
                    if (resp != null) {
                        ret = resp.getResponseMessage();
                    }
                } else {

                    // Get the certificate 
                    if (log.isDebugEnabled()) {
                        log.debug("SCEP certificate enrollment with alias '" + alias + "'");
                    }
                    ResponseMessage resp = signSession.createCertificate(administrator, reqmsg, ScepResponseMessage.class, null);
                    if (resp != null) {
                        ret = resp.getResponseMessage();
                        ScepResponseMessage scepResponseMessage = (ScepResponseMessage) resp;
                        if (scepResponseMessage.getStatus() == ResponseStatus.SUCCESS) {
                            intuneData = new IntuneScepData(scepResponseMessage.getIssuer(), scepResponseMessage.getSerialNumber(),
                                    scepResponseMessage.getNotAfter(), scepResponseMessage.getThumbprint());
                        } else {
                            intuneData = new IntuneScepData(scepResponseMessage.getFailInfo(), scepResponseMessage.getFailText());
                        }
                        intuneData.addOriginalRequestIfPresent(reqmsg.getCertificationRequest());
                        log.debug("Adding Intune fields to SCEP response: " + intuneData);
                    }
                }
            } catch (AuthStatusException e) {
                String failMessage = "Attempted to enroll on an end entity (username: " + reqmsg.getUsername() + ", alias: " + alias
                        + ") with incorrect status: " + e.getLocalizedMessage();
                log.info(failMessage, e);
                CA ca = signSession.getCAFromRequest(administrator, reqmsg, false);
                ResponseMessage resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failMessage);
                return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
            }
        } else if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCERTINITIAL) {
            //Only works in RA mode
            if (!isRAModeOK || scepRaModeExtension == null) {
                // Fail nicely
                log.warn(
                        "GETCERTINITIAL was called but only works in SCEP RA mode, which is not included in the community version of EJBCA. Unable to continue.");
                return null;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Received a SCEP GETCERTINITIAL message, operating in RA mode: " + isRAModeOK);
                }
                final CA ca = signSession.getCAFromRequest(administrator, reqmsg, false);
                final String keyAlias = ca.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
                final X509Certificate cacert = (X509Certificate) ca.getCACertificate();
                final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(ca.getCAToken().getCryptoTokenId());
                reqmsg.setKeyInfo(cacert, cryptoToken.getPrivateKey(keyAlias), cryptoToken.getSignProviderName());
                //Retrieve the original request and transaction ID based on the username 
                final String username = reqmsg.generateUsername(scepConfig, alias);
                final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(scepConfig.getRACertProfile(alias));
                final String approvalProfileName = approvalProfileSession
                        .getApprovalProfileForAction(ApprovalRequestType.ADDEDITENDENTITY, ca.getCAInfo(), certificateProfile).getProfileName();
                //We need to divine if the initial request was for an enrollment, issuance, renewal or a new attempt from a failed request
                int approvalId;
                EndEntityInformation endEntityInformation = endEntityAccessSession.findUser(username);
                if (endEntityInformation == null) {
                    //Enrollment
                    approvalId = AddEndEntityApprovalRequest.generateAddEndEntityApprovalId(username, approvalProfileName);
                    if (log.isDebugEnabled()) {
                        log.debug("Generated an AddEndEntityApprovalId: " + approvalId);
                    }
                } else {
                    Class<? extends EndEntityApprovalRequest> cachedApprovalType = endEntityInformation.getExtendedInformation()
                            .getCachedApprovalType();
                    if (cachedApprovalType == null) {
                        // Likely Renewal prior to approval
                        approvalId = EditEndEntityApprovalRequest.generateEditEndEntityApprovalId(username, approvalProfileName);
                        if (log.isDebugEnabled()) {
                            log.debug("Generated an EditEndEntityApprovalId: " + approvalId);
                        }
                    } else if (cachedApprovalType.equals(AddEndEntityApprovalRequest.class)) {
                        //Issuance
                        approvalId = AddEndEntityApprovalRequest.generateAddEndEntityApprovalId(username, approvalProfileName);
                        if (log.isDebugEnabled()) {
                            log.debug("Generated an AddEndEntityApprovalId: " + approvalId);
                        }
                    } else {
                        //Renewal post approval or new attempt from a failed request
                        approvalId = EditEndEntityApprovalRequest.generateEditEndEntityApprovalId(username, approvalProfileName);
                        if (log.isDebugEnabled()) {
                            log.debug("Generated an EditEndEntityApprovalId: " + approvalId);
                        }
                    }
                }
                List<ApprovalDataVO> approvals = approvalSession.findApprovalDataVO(approvalId);
                if (log.isDebugEnabled()) {
                    log.debug("Found " + approvals.size() + " approvals with approvalID: " + approvalId);
                }
                ApprovalDataVO approval = null;
                if (approvals.size() > 0) {
                    // Sort the list, find the last approval available. We don't care if it's expired in this context.
                    Collections.sort(approvals, new Comparator<ApprovalDataVO>() {
                        @Override
                        public int compare(ApprovalDataVO vo1, ApprovalDataVO vo2) {
                            return vo1.getRequestDate().compareTo(vo2.getRequestDate());
                        }
                    });
                    // The last one should be our latest registered approval from the sorting above
                    approval = approvals.get(approvals.size() - 1);
                }
                ResponseMessage resp;
                if (approval != null) {
                    //Approval is still around - which either means that it's been approved but not removed, rejected or is still waiting approval
                    //Verify that the transaction ID in the request is correct
                    endEntityInformation = ((EndEntityApprovalRequest) approval.getApprovalRequest()).getEndEntityInformation();
                    if (log.isDebugEnabled()) {
                        log.debug("Found an existing approval of type " + approval.getApprovalType() + " with requestDate "
                                + approval.getRequestDate() + " for end entity '" + endEntityInformation.getUsername() + "', with approval status "
                                + approval.getStatus());
                    }
                    final ScepRequestMessage originalRequest = ScepRequestMessage
                            .instance(endEntityInformation.getExtendedInformation().getCachedScepRequest());
                    //Verify that the correct transaction ID has been used, as per section 3.2.3 of the draft. Authentication will be handled later
                    if (originalRequest == null) {
                        final String failText = "SCEP request was not stored in for end entity '" + reqmsg.getUsername()
                                + "', cannot continue with issuance.";
                        log.info(failText);
                        resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                        return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
                    }
                    if (!originalRequest.getTransactionId().equalsIgnoreCase(reqmsg.getTransactionId())) {
                        final String failText = "Failure to process GETCERTINITIAL message. Transaction ID " + reqmsg.getTransactionId()
                                + " did not match up with the one (" + originalRequest.getTransactionId()
                                + ") used during initial PKCSREQ for end entity '" + endEntityInformation.getUsername() + "'.";
                        log.info(failText);
                        resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                        return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
                    }

                    String failText;
                    switch (approval.getStatus()) {
                    case ApprovalDataVO.STATUS_EXECUTED:
                        //Now go ahead and process the cached certificate request     
                        try {
                            try {
                                resp = signSession.createCertificate(administrator, originalRequest, ScepResponseMessage.class, null);
                            } finally {
                                //That done, let's erase the cached request from the end entity                              
                                try {
                                    eraseCachedEnrollmentValue(administrator, username);
                                } catch (CADoesntExistsException | ApprovalException | CertificateSerialNumberException | IllegalNameException
                                        | NoSuchEndEntityException | CustomFieldException | AuthorizationDeniedException
                                        | EndEntityProfileValidationException | WaitingForApprovalException e) {
                                    failText = "Failed to erase cached SCEP enrollment value for end entity with username: '" + username + "',  "
                                            + e.getLocalizedMessage();
                                    log.info(failText);
                                    resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                                    return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
                                }
                            }
                        } catch (AuthStatusException e) {
                            failText = "Attempted to enroll on an end entity (username: " + reqmsg.getUsername() + ", SCEP alias: " + alias
                                    + ") with incorrect status: " + e.getLocalizedMessage();
                            log.info(failText, e);
                            resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                            return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
                        }
                        if (resp != null) {
                            //Since the client will be expecting the nonce to be that of the poll request instead of the original request, set it here. 
                            resp.setRecipientNonce(reqmsg.getSenderNonce());
                            try {
                                resp.create();
                            } catch (InvalidKeyException | CertificateEncodingException | NoSuchAlgorithmException | NoSuchProviderException
                                    | CRLException e) {
                                throw new IllegalStateException("Could not recreate response with proper recipient nonce.", e);
                            }
                            ret = resp.getResponseMessage();
                        }

                        break;
                    case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                        //Still waiting for approval
                        resp = createPendingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo());
                        ret = resp.getResponseMessage();
                        break;
                    case ApprovalDataVO.STATUS_EXPIRED:
                    case ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED:
                    case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                    case ApprovalDataVO.STATUS_REJECTED:
                        // All cases where approval did not happen, and will never happen, i.e. either explicitly rejected or implicitly by letting the request expire
                        try {
                            eraseCachedEnrollmentValue(administrator, username);
                        } catch (CADoesntExistsException | ApprovalException | CertificateSerialNumberException | IllegalNameException
                                | NoSuchEndEntityException | CustomFieldException | AuthorizationDeniedException | EndEntityProfileValidationException
                                | WaitingForApprovalException e) {
                            failText = "Failed to erase cached SCEP enrollment value for end entity with username: '" + username + "',  "
                                    + e.getLocalizedMessage();
                            log.info(failText);
                            resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                            return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
                        }
                        failText = "Could not process GETCERTINITIAL request with transaction ID " + reqmsg.getTransactionId() + " for username '"
                                + username + "'. Enrollment was not approved by administrator.";
                        log.info(failText);
                        resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                        ret = resp.getResponseMessage();
                        break;
                    case ApprovalDataVO.STATUS_EXECUTIONFAILED:
                        try {
                            eraseCachedEnrollmentValue(administrator, username);
                        } catch (CADoesntExistsException | ApprovalException | CertificateSerialNumberException | IllegalNameException
                                | NoSuchEndEntityException | CustomFieldException | AuthorizationDeniedException | EndEntityProfileValidationException
                                | WaitingForApprovalException e) {
                            failText = "Failed to erase cached SCEP enrollment value for end entity with username: '" + username + "',  "
                                    + e.getLocalizedMessage();
                            log.info(failText);
                            resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                            return ScepResponseInfo.onlyResponseBytes(resp.getResponseMessage());
                        }
                        failText = "Could not process GETCERTINITIAL request for username '" + username + "'. Enrollment execution failed.";
                        log.info(failText);
                        resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                        ret = resp.getResponseMessage();
                        break;
                    default:
                        failText = "Approval state was unknown for this request.";
                        resp = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText);
                        ret = resp.getResponseMessage();
                        break;
                    }
                } else {
                    String failText = "GETCERTINITIAL was called on user with name '" + username + "' using transaction ID "
                            + reqmsg.getTransactionId() + ", but no waiting approval request for an end entity with that name exists";
                    log.info(failText);
                    ret = createFailingResponseMessage(reqmsg, (X509CAInfo) ca.getCAInfo(), FailInfo.BAD_REQUEST, failText).getResponseMessage();
                }
            }
        } else if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
            // create the stupid encrypted CRL message, the below can actually only be made 
            // at the CA, since CAs private key is needed to decrypt
            ResponseMessage resp = signSession.getCRL(administrator, reqmsg, ScepResponseMessage.class);
            if (resp != null) {
                ret = resp.getResponseMessage();
            }
        }

        if (log.isTraceEnabled()) {
            log.trace("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));
        }

        if (ret == null) {
            return null;
        } else if (intuneData != null) {
            return intuneData.toScepResponseInfo(ret);
        } else {
            return ScepResponseInfo.onlyResponseBytes(ret);
        }
    }

    @Override
    public boolean doMsIntuneCsrVerification(final AuthenticationToken authenticationToken, final String alias, final byte[] message)
            throws CertificateCreateException {
        if (log.isDebugEnabled()) {
            log.debug("Attempting intune validation for alias " + alias);
        }
        if (scepRaModeExtension == null) {
            // Fail nicely
            log.warn("SCEP RA mode is enabled, but not included in the community version of EJBCA. Unable to continue.");
            throw new CertificateCreateException("Intune enrollment failed because no license.");
        }

        final ScepConfiguration scepConfig = (ScepConfiguration) raMasterApiProxyBean.getGlobalConfiguration(ScepConfiguration.class);
        ScepRequestMessage reqmsg = null;
        String transactionId = null;
        try {
            final boolean includeCACert = scepConfig.getIncludeCA(alias);
            reqmsg = new ScepRequestMessage(Base64.decode(message), includeCACert);
            transactionId = reqmsg.getTransactionId();
        } catch (Exception e) {
            log.info("Error receiving ScepMessage: ", e);
            throw new CertificateCreateException("Error receiving ScepMessage for alias " + alias, e);
        }

        try {
            final IntuneRestApi intuneScepServiceClient = getIntuneScepServiceClient(alias, scepConfig);
            final byte[] derEncodedCsr = raMasterApiProxyBean.verifyScepPkcs10RequestMessage(authenticationToken, alias, message);
            if (log.isDebugEnabled()) {
                log.debug("Try MS Intune validation for alias '" + alias + "' and transaction ID '" + transactionId + "'. ");
            }
            intuneScepServiceClient.validateRequest(transactionId, new String(Base64.encode(derEncodedCsr)));
            log.info("MS Intune validation succeed for alias '" + alias + "' and transaction ID '" + transactionId + "'. ");
            return true;
        } catch (AzureException e) {
            final String msg = "MS Intune validation failed for alias " + alias + "' and transaction ID '" + transactionId + "'. ";
            log.info(msg, e);
            throw new CertificateCreateException(msg, e);
        } catch (Exception e) {
            // See https://github.com/microsoft/Intune-Resource-Access/blob/master/src/CsrValidation/java/lib/src/main/java/com/microsoft/intune/scepvalidation/IntuneScepServiceClient.java
            // ValidateRequest(String transactionId, String certificateRequest) throws IntuneScepServiceException, Exception
            throw new CertificateCreateException("MS Intune enrollment failed for alias " + alias + "' and transaction ID '" + transactionId + "'. ",
                    e);
        }
    }

    /**
     * Return an Intune client for the current configuration.
     * 
     * @param alias SCEP alias
     * @param scepConfig configuration used to build the client
     * @return client for sending commands to Intune
     * @throws CertificateCreateException Unable to create the client
     * @throws AzureException 
     * @throws IOException 
     */
    private IntuneRestApi getIntuneScepServiceClient(final String alias, final ScepConfiguration scepConfig) throws CertificateCreateException, IOException, AzureException {
        try {
            Builder builder = new IntuneRestApi.Builder(scepConfig.getIntuneTenant(alias), scepConfig.getIntuneAadAppId(alias), GlobalConfiguration.EJBCA_VERSION);
            if (isNotBlank(scepConfig.getIntuneProxyHost(alias))) {
                builder = builder.withProxyHost(scepConfig.getIntuneProxyHost(alias))
                        .withProxyPort(Integer.parseInt(scepConfig.getIntuneProxyPort(alias)));
                
                if (isNotBlank(scepConfig.getIntuneProxyUser(alias))) {
                    builder = builder.withProxyUser(scepConfig.getIntuneProxyUser(alias))
                            .withProxyPassword(scepConfig.getIntuneProxyPass(alias));
                }
            }

            if (!scepConfig.getIntuneAadUseKeyBinding(alias)) {
                builder = builder.withClientSecret(scepConfig.getIntuneAadAppKey(alias));
            } else {
                // use public key for authentication to Intune
                final String keyBindingName = scepConfig.getIntuneAadAppKeyBinding(alias);
                log.debug("Authenticating to Intune using internal key binding " + keyBindingName);
                final InternalKeyBindingInfo keyBindingInfo = internalKeyBindingMgmtSession
                        .getAllInternalKeyBindingInfos(AuthenticationKeyBinding.IMPLEMENTATION_ALIAS).stream()
                        .filter(i -> i.getName().equals(keyBindingName)).findFirst().orElseThrow(() -> {
                            return new CertificateCreateException("Intune Key Binding " + keyBindingName + " not found.");
                        });
                final Certificate certificate = certificateStoreSession.findCertificateByFingerprint(keyBindingInfo.getCertificateId());
                log.debug("Authenticating to Intune using certificate " + certificate);
                final CryptoToken token = cryptoTokenSession.getCryptoToken(keyBindingInfo.getCryptoTokenId());
                log.debug("Authenticating to Intune using token " + token.getTokenName());
                try {
                    PrivateKey privateKey = token.getPrivateKey(keyBindingInfo.getKeyPairAlias());
                    builder = builder.withClientCertificate((X509Certificate) certificate);
                    builder = builder.withClientKey(privateKey);
                } catch (CryptoTokenOfflineException e) {
                    log.debug("Crypto token " + token.getTokenName() + " offline.", e);
                    throw new CertificateCreateException("Crypto token " + token.getTokenName() + " offline.", e);
                }
                
            }
            
            // azure government may use a different AD login url
            if (isNotBlank(scepConfig.getIntuneAuthority(alias))) {
                builder.withAzureLoginUrl(scepConfig.getIntuneAuthority(alias));
            }
            if (isNotBlank(scepConfig.getIntuneGraphResourceUrl(alias))) {
                builder.withGraphResourceUrl(scepConfig.getIntuneGraphResourceUrl(alias));
            }
            if (isNotBlank(scepConfig.getIntuneGraphApiVersion(alias))) {
                builder.withGraphResourceVersion(scepConfig.getIntuneGraphApiVersion(alias));
            }
            if (isNotBlank(scepConfig.getIntuneResourceUrl(alias))) {
                builder.withIntuneResourceUrl(scepConfig.getIntuneResourceUrl(alias));
            }

            return builder.build();
        } catch (IllegalArgumentException e) {
            throw new CertificateCreateException("Failed to initialize MS Intune SCEP service client for alias '" + alias + "'.", e);
        }
    }

    @Override
    public byte[] verifyRequestMessage(final AuthenticationToken authenticationToken, final String alias, final byte[] message)
            throws CertificateCreateException {
        log.info("Verify SCEP PKCS10 request message for SCEP alias '" + alias + "'.");
        final ScepConfiguration scepConfig = (ScepConfiguration) globalConfigSession.getCachedConfiguration(ScepConfiguration.SCEP_CONFIGURATION_ID);
        ScepRequestMessage reqmsg = null;
        try {
            final boolean includeCACert = scepConfig.getIncludeCA(alias);
            reqmsg = new ScepRequestMessage(Base64.decode(message), includeCACert);
        } catch (Exception e) {
            log.info("Error receiving ScepMessage: ", e);
            throw new CertificateCreateException("Error receiving ScepMessage for alias " + alias, e);
        }

        String caName = null;
        CAInfo caInfo = null;
        CACommon ca = null;
        try {
            caName = scepConfig.getRADefaultCA(alias);
            caInfo = caSession.getCAInfo(authenticationToken, caName);
            if (caInfo == null) {
                throw new CertificateCreateException("Could not find CA set in SCEP alias '" + alias + "': " + caName);
            }
            ca = caSession.getCA(authenticationToken, caName);
        } catch (AuthorizationDeniedException e) {
            throw new CertificateCreateException("Administator is not authorized for CA: " + caName, e);
        }
        final CAToken caToken = caInfo.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenSession.getCryptoToken(caToken.getCryptoTokenId());
        try {
            reqmsg.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)),
                    cryptoToken.getSignProviderName());
            reqmsg.verify();
            return reqmsg.getCertificationRequest().getEncoded();
        } catch (Exception e) {
            throw new CertificateCreateException("SCEP PKCS10 message verification failed for alias " + alias + "'.", e);
        }
    }

    /**
     * Erases the cached SCEP request and the approval type from the end entity
     * 
     * @param authenticationToken an authentication token
     * @param username the username of the end entity
     */
    private void eraseCachedEnrollmentValue(final AuthenticationToken authenticationToken, final String username)
            throws CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException,
            CustomFieldException, AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException {
        final EndEntityInformation updatedEndEntityInformation = endEntityAccessSession.findUser(username);
        if (updatedEndEntityInformation != null) {
            final ExtendedInformation extendedInformation = updatedEndEntityInformation.getExtendedInformation();
            final String transactionID;
            if (extendedInformation.getCachedScepRequest() != null) {
                final ScepRequestMessage originalRequest = ScepRequestMessage.instance(extendedInformation.getCachedScepRequest());
                transactionID = originalRequest.getTransactionId();
            } else {
                transactionID = null;
            }
            extendedInformation.cacheScepRequest(null);
            extendedInformation.cacheApprovalType(null);
            updatedEndEntityInformation.setExtendedInformation(extendedInformation);
            endEntityManagementSession.changeUserIgnoreApproval(authenticationToken, updatedEndEntityInformation, false);
            if (log.isDebugEnabled()) {
                log.debug("Erased cached SCEP enrollment with transaction ID " + transactionID + " from end entity '" + username + "'.");
            }
        }
    }

    /**
     * Create a response message with status FAILURE
     * 
     * @param req the request message
     * @param signingCa the CA configured to sign responses
     * @return a response message with the given status 
     * @throws CryptoTokenOfflineException
     */
    private ScepResponseMessage createPendingResponseMessage(final RequestMessage req, final X509CAInfo signingCa)
            throws CryptoTokenOfflineException {
        ScepResponseMessage ret = new ScepResponseMessage();
        // Create the response message and set all required fields
        CAToken caToken = signingCa.getCAToken();
        X509Certificate signingCertificate = (X509Certificate) signingCa.getCertificateChain().get(0);
        CryptoToken caCryptoToken = cryptoTokenSession.getCryptoToken(signingCa.getCAToken().getCryptoTokenId());
        PrivateKey signingKey = caCryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        if (ret.requireSignKeyInfo()) {
            if (log.isDebugEnabled()) {
                log.debug("Signing message with cert: " + signingCertificate.getSubjectDN().getName());
            }
            Collection<Certificate> racertColl = new ArrayList<Certificate>();
            racertColl.add(signingCertificate);
            ret.setSignKeyInfo(racertColl, signingKey, caCryptoToken.getSignProviderName());
        }
        if (req.getSenderNonce() != null) {
            ret.setRecipientNonce(req.getSenderNonce());
        }
        if (req.getTransactionId() != null) {
            ret.setTransactionId(req.getTransactionId());
        }

        // SenderNonce is a random number
        byte[] senderNonce = new byte[16];
        secureRandom.nextBytes(senderNonce);
        ret.setSenderNonce(new String(Base64.encode(senderNonce)));

        // If we have a specified request key info, use it in the reply
        if (req.getRequestKeyInfo() != null) {
            ret.setRecipientKeyInfo(req.getRequestKeyInfo());
        }
        // Which digest algorithm to use to create the response, if applicable
        ret.setPreferredDigestAlg(req.getPreferredDigestAlg());
        // Include the CA cert or not in the response, if applicable for the response type
        ret.setIncludeCACert(req.includeCACert());
        ret.setStatus(ResponseStatus.PENDING);
        try {
            ret.create();
        } catch (CertificateEncodingException | CRLException e) {
            throw new IllegalStateException("Response message could not be created.", e);
        }
        return ret;
    }

    /**
     * Create a response message with status FAILURE
     * 
     * @param req the request message
     * @param signingCa the CA configured to sign responses
     * @return a response message with the given status 
     * @throws CryptoTokenOfflineException
     */
    private ScepResponseMessage createFailingResponseMessage(final RequestMessage req, final X509CAInfo signingCa, final FailInfo failInfo,
            final String failText) throws CryptoTokenOfflineException {
        ScepResponseMessage ret = new ScepResponseMessage();
        // Create the response message and set all required fields
        CAToken caToken = signingCa.getCAToken();
        X509Certificate signingCertificate = (X509Certificate) signingCa.getCertificateChain().get(0);
        CryptoToken caCryptoToken = cryptoTokenSession.getCryptoToken(signingCa.getCAToken().getCryptoTokenId());
        PrivateKey signingKey = caCryptoToken.getPrivateKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        if (ret.requireSignKeyInfo()) {
            if (log.isDebugEnabled()) {
                log.debug("Signing message with cert: " + signingCertificate.getSubjectDN().getName());
            }
            Collection<Certificate> racertColl = new ArrayList<Certificate>();
            racertColl.add(signingCertificate);
            ret.setSignKeyInfo(racertColl, signingKey, BouncyCastleProvider.PROVIDER_NAME);
        }
        if (req.getSenderNonce() != null) {
            ret.setRecipientNonce(req.getSenderNonce());
        }
        if (req.getTransactionId() != null) {
            ret.setTransactionId(req.getTransactionId());
        }

        // SenderNonce is a random number
        byte[] senderNonce = new byte[16];
        secureRandom.nextBytes(senderNonce);
        ret.setSenderNonce(new String(Base64.encode(senderNonce)));

        // If we have a specified request key info, use it in the reply
        if (req.getRequestKeyInfo() != null) {
            ret.setRecipientKeyInfo(req.getRequestKeyInfo());
        }
        // Which digest algorithm to use to create the response, if applicable
        ret.setPreferredDigestAlg(req.getPreferredDigestAlg());
        // Include the CA cert or not in the response, if applicable for the response type
        ret.setIncludeCACert(req.includeCACert());
        ret.setStatus(ResponseStatus.FAILURE);
        ret.setFailInfo(failInfo);
        ret.setFailText(failText);
        try {
            ret.create();
        } catch (CertificateEncodingException | CRLException e) {
            throw new IllegalStateException("Response message could not be created.", e);
        }
        return ret;
    }

    @Override
    public void doMsIntuneCompleteRequest(AuthenticationToken authenticationToken, String transactionId, String alias, ScepResponseInfo response)
            throws CertificateCreateException {
        if (log.isDebugEnabled()) {
            log.debug("Attempting intune status update for alias " + alias);
        }
        if (scepRaModeExtension == null) {
            // Fail nicely
            log.warn("SCEP RA mode is enabled, but not included in the community version of EJBCA. Unable to continue.");
            throw new CertificateCreateException("Intune update failed because no license.");
        }

        final ScepConfiguration scepConfig = (ScepConfiguration) raMasterApiProxyBean.getGlobalConfiguration(ScepConfiguration.class);

        try {
            final IntuneRestApi intuneScepServiceClient = getIntuneScepServiceClient(alias, scepConfig);
            if (log.isDebugEnabled()) {
                log.debug("Try MS Intune status update for alias '" + alias + "' and transaction ID '" + transactionId + "'. ");
            }

            if (response == null) {
                log.debug("Logging SCEP failure for alias '" + alias + "' and transaction ID '" + transactionId + "'. ");
                // see https://msdn.microsoft.com/en-us/library/cc231198.aspx.  Below is a "vendor specific" error code for us.  
                // We only send one, since the actual error condition isn't returned from the CA
                final long errorCode = 0x20000001L;
                final String errorMessage = "Failed to issue certificate for alias '" + alias + "' and transaction ID '" + transactionId + "'. ";
                intuneScepServiceClient.sendFailureNotification(transactionId, "", errorCode,
                        // maximum length, per MS documentation
                        errorMessage.substring(0, 255));
            } else if (response.isFailed()) {
                // use java.util to ensure there are no crlfs
                final String base64Message = java.util.Base64.getEncoder().encodeToString(response.getPkcs10Request());
                log.debug("Logging SCEP failure for alias '" + alias + "' and transaction ID '" + transactionId + "'. ");
                // see https://msdn.microsoft.com/en-us/library/cc231198.aspx.  Below is a "vendor specific" error code for us.  
                final long errorCode = 0x20000100L + response.getFailInfo().intValue();
                final String errorMessage = response.getFailText();
                intuneScepServiceClient.sendFailureNotification(transactionId, base64Message, errorCode,
                        // maximum length, per MS documentation
                        errorMessage.substring(0, 255));
            } else {
                // use java.util to ensure there are no crlfs
                final String base64Message = java.util.Base64.getEncoder().encodeToString(response.getPkcs10Request());
                log.debug("Logging SCEP success for alias '" + alias + "' and transaction ID '" + transactionId + "'. ");
                log.debug("scep id = " + transactionId);
                log.debug("scep base64Message = " + base64Message);
                final String thumbprint = toMicrosoftHex(response.getThumbprint());
                log.debug("scep thumbprint = " + thumbprint);
                final String hexSerialNumber = response.getSerialNumber().toString(16);
                log.debug("scep hexSerialNumber = " + hexSerialNumber);
                
                // note that the ca id sent here has to match the ca id sent when polling for revocations.  
                // We're sending the issuer DN, as encoded in the certificate, as the identifier of the issuing CA.  
                final String issuer = response.getIssuer().getName();
                log.debug("scep issuer = " + issuer);
                
                intuneScepServiceClient.sendSuccessNotification(transactionId, base64Message, thumbprint, hexSerialNumber,
                        response.getNotAfter().toString(), issuer, issuer, issuer);
            }
            log.info("MS Intune status update succeeded for alias '" + alias + "' and transaction ID '" + transactionId + "'. ");
        } catch (AzureException e) {
            final String msg = "MS Intune status update failed for alias " + alias + "' and transaction ID '" + transactionId + "'. ";
            log.info(msg, e);
            throw new CertificateCreateException(msg, e);
        } catch (Exception e) {
            throw new CertificateCreateException(
                    "MS Intune status update failed for alias " + alias + "' and transaction ID '" + transactionId + "'. ", e);
        }

    }

    private String toMicrosoftHex(byte[] thumbprint) {
        StringBuilder out = new StringBuilder(thumbprint.length * 3 - 1);
        boolean firstByte = true;
        for (byte b : thumbprint) {
            if (!firstByte)
                out.append(" ");
            else
                firstByte = false;
            out.append(String.format("%02x", b));
        }
        return out.toString();
    }

    /**
     * Just a convenient holder for additional data during SCEP issuance.  
     */
    public class IntuneScepData {

        private boolean failed = false;
        private X500Principal issuer = null;
        private BigInteger serialNumber = null;
        private Instant notAfter = null;
        private byte[] thumbprint = null;
        private FailInfo failInfo = null;
        private String failText = null;
        private byte[] pkcs10Request;

        public IntuneScepData(X500Principal issuer, BigInteger serialNumber, Instant notAfter, byte[] thumbprint) {
            this.issuer = issuer;
            this.serialNumber = serialNumber;
            this.notAfter = notAfter;
            this.thumbprint = thumbprint;
            failed = false;
        }

        public ScepResponseInfo toScepResponseInfo(byte[] ret) {
            if (failed) {
                return new ScepResponseInfo(ret, failInfo, failText == null ? failInfo.toString() : failText, pkcs10Request);
            } else {
                return new ScepResponseInfo(ret, issuer, serialNumber, notAfter, thumbprint, pkcs10Request);
            }
        }

        public IntuneScepData(FailInfo failInfo, String failText) {
            this.failInfo = failInfo;
            this.failText = failText;
            failed = true;
        }

        public void addOriginalRequestIfPresent(PKCS10CertificationRequest certificationRequest) {
            if (certificationRequest == null) {
                log.debug("No pkcs10 request in original request.");
                pkcs10Request = null;
            } else {
                try {
                    pkcs10Request = certificationRequest.getEncoded();
                } catch (IOException e) {
                    log.debug("No readable original pkcs10 request in original request.", e);
                    pkcs10Request = null;
                }
            }
        }
    }
}
