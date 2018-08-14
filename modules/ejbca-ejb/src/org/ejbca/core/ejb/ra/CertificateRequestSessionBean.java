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

package org.ejbca.core.ejb.ra;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.CertTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.WrongTokenTypeException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * Combines EditUser (RA) with CertReq (CA) methods using transactions.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CertificateRequestSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class CertificateRequestSessionBean implements CertificateRequestSessionRemote, CertificateRequestSessionLocal {

    private static final Logger log = Logger.getLogger(CertificateRequestSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private EndEntityAuthenticationSessionLocal authenticationSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private HardTokenSessionLocal hardTokenSession;
    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    @EJB
    private KeyStoreCreateSessionLocal keyStoreCreateSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private SignSessionLocal signSession;
    @Resource
    private SessionContext sessionContext;

    @Override
    public byte[] processCertReq(AuthenticationToken admin, EndEntityInformation userdata, String req, int reqType, String hardTokenSN,
            int responseType) throws AuthorizationDeniedException, NotFoundException, InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchProviderException, SignatureException, IOException, CertificateException,
            EndEntityProfileValidationException, ApprovalException, EjbcaException, CesecoreException, CertificateExtensionException {
        byte[] retval = null;

        // Check tokentype
        if (userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN) {
            throw new WrongTokenTypeException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
        }
        // This is the secret sauce, do the end entity handling automagically here before we get the cert
        addOrEditUser(admin, userdata, false, true);
        // Process request
        try {
            String password = userdata.getPassword();
            String username = userdata.getUsername();
            RequestMessage imsg = RequestMessageUtils.getRequestMessageFromType(username, password, req, reqType);
            if (imsg != null) {
                retval = getCertResponseFromPublicKey(admin, imsg, hardTokenSN, responseType, userdata);
            }
        } catch (NotFoundException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (InvalidKeyException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (NoSuchAlgorithmException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (InvalidKeySpecException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (NoSuchProviderException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (SignatureException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (IOException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (CertificateException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (EjbcaException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (CesecoreException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (ParseException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, e);
        } catch (ConstructionException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, e);
        } catch (NoSuchFieldException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, e);
        } catch (CertificateExtensionException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        }
        return retval;
    }

    @Override
    public ResponseMessage processCertReq(AuthenticationToken admin, EndEntityInformation userdata, RequestMessage req, Class<? extends CertificateResponseMessage> responseClass)
            throws EndEntityExistsException, AuthorizationDeniedException, EndEntityProfileValidationException, EjbcaException, CesecoreException, CertificateExtensionException {
        // Check tokentype
        if (userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN) {
            throw new WrongTokenTypeException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
        }
        // This is the secret sauce, do the end entity handling automagically here before we get the cert
        addOrEditUser(admin, userdata, false, true);
        ResponseMessage retval = null;
        try {
            retval = signSession.createCertificate(admin, req, responseClass, userdata);
        } catch (EjbcaException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (CertificateExtensionException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        }
        return retval;
    }

    /**
     * @throws CADoesntExistsException if userdata.caId is not a valid caid. This is checked in editUser or addUserFromWS
     * @throws IllegalNameException  if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws NoSuchEndEntityException if the end entity was not found
     */
    private void addOrEditUser(AuthenticationToken admin, EndEntityInformation userdata, boolean clearpwd, boolean fromwebservice)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, ApprovalException, EndEntityExistsException,
            CADoesntExistsException, CertificateSerialNumberException, IllegalNameException, CustomFieldException, NoSuchEndEntityException {

        int caid = userdata.getCAId();
        if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + caid, null);
            throw new AuthorizationDeniedException(msg);
        }
        if (!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.REGULAR_CREATECERTIFICATE,
                    null);
            throw new AuthorizationDeniedException(msg);
        }
        // First we need to fetch the CA configuration to see if we save UserData, if not, we still run addUserFromWS to
        // get all the proper authentication checks for CA and end entity profile.
        // No need to to access control here just to fetch this flag, access control for the CA is done in EndEntityManagementSession
        boolean useUserStorage = caSession.getCAInfoInternal(caid, null, true).isUseUserStorage();
        // Add or edit user
        try {
            String username = userdata.getUsername();
            if (useUserStorage && endEntityManagementSession.existsUser(username)) {
                if (log.isDebugEnabled()) {
                    log.debug("User " + username + " exists, update the userdata. New status of user '" + userdata.getStatus() + "'.");
                }
                endEntityManagementSession.changeUser(admin, userdata, clearpwd, fromwebservice);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("New User " + username + ", adding userdata. New status of user '" + userdata.getStatus() + "'.");
                }
                // addUserfromWS also checks useUserStorage internally, so don't duplicate the check
                endEntityManagementSession.addUserFromWS(admin, userdata, clearpwd);
            }
        } catch (WaitingForApprovalException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            String msg = "Single transaction enrollment request rejected since approvals are enabled for this CA (" + caid
                    + ") or Certificate Profile (" + userdata.getCertificateProfileId() + ").";
            log.info(msg);
            throw new ApprovalException(msg);
        }
    }

    /**
     * Process a request in the CA module.
     *
     * @param admin is the requesting administrator
     * @param msg is the request message processed by the CA
     * @param hardTokenSN is the hard token to associate this or null
     * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType
     * @throws AuthorizationDeniedException
     * @throws CertificateExtensionException if the request message contained invalid extensions
     */
    private byte[] getCertResponseFromPublicKey(AuthenticationToken admin, RequestMessage msg, String hardTokenSN, int responseType,
            EndEntityInformation userData) throws EjbcaException, CesecoreException, CertificateEncodingException, CertificateException, IOException,
            AuthorizationDeniedException, CertificateExtensionException {
        byte[] retval = null;
        Class<X509ResponseMessage> respClass = X509ResponseMessage.class;
        ResponseMessage resp = signSession.createCertificate(admin, msg, respClass, userData);
        X509Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), X509Certificate.class);
        if (responseType == CertificateConstants.CERT_RES_TYPE_CERTIFICATE) {
            retval = cert.getEncoded();
        }
        if (responseType == CertificateConstants.CERT_RES_TYPE_PKCS7) {
            retval = signSession.createPKCS7(admin, cert, false);
        }
        if (responseType == CertificateConstants.CERT_RES_TYPE_PKCS7WITHCHAIN) {
            retval = signSession.createPKCS7(admin, cert, true);
        }

        if (hardTokenSN != null) {
            hardTokenSession.addHardTokenCertificateMapping(admin, hardTokenSN, cert);
        }
        return retval;
    }

    @Override
    public byte[] processSoftTokenReq(AuthenticationToken admin, EndEntityInformation userdata, String hardTokenSN, String keyspec, String keyalg,
            boolean createJKS) throws ApprovalException, EndEntityExistsException, CADoesntExistsException, CertificateSerialNumberException,
            IllegalNameException, CustomFieldException, AuthorizationDeniedException, EndEntityProfileValidationException, NoSuchAlgorithmException,
            InvalidKeySpecException, CertificateException, InvalidAlgorithmParameterException, KeyStoreException, NoSuchEndEntityException {

        // This is the secret sauce, do the end entity handling automagically here before we get the cert
        addOrEditUser(admin, userdata, false, true);
        // Process request
        byte[] ret = null;
        try {
            // Get key recovery info
            boolean usekeyrecovery = ( (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
            if (log.isDebugEnabled()) {
                log.debug("usekeyrecovery: " + usekeyrecovery);
            }
            boolean savekeys = userdata.getKeyRecoverable() && usekeyrecovery && (userdata.getStatus() != EndEntityConstants.STATUS_KEYRECOVERY);
            if (log.isDebugEnabled()) {
                log.debug("userdata.getKeyRecoverable(): " + userdata.getKeyRecoverable());
                log.debug("userdata.getStatus(): " + userdata.getStatus());
                log.debug("savekeys: " + savekeys);
            }
            boolean loadkeys = (userdata.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY) && usekeyrecovery;
            if (log.isDebugEnabled()) {
                log.debug("loadkeys: " + loadkeys);
            }
            int endEntityProfileId = userdata.getEndEntityProfileId();
            EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfileNoClone(endEntityProfileId);
            boolean reusecertificate = endEntityProfile.getReUseKeyRecoveredCertificate();
            if (log.isDebugEnabled()) {
                log.debug("reusecertificate: " + reusecertificate);
            }
            // Generate keystore
            String password = userdata.getPassword();
            String username = userdata.getUsername();
            int caid = userdata.getCAId();
            KeyStore keyStore = keyStoreCreateSession.generateOrKeyRecoverToken(admin, username, password, caid, keyspec, keyalg, null, null,
                    createJKS, loadkeys, savekeys,
                    reusecertificate, endEntityProfileId);
            String alias = keyStore.aliases().nextElement();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            if ((hardTokenSN != null) && (cert != null)) {
                hardTokenSession.addHardTokenCertificateMapping(admin, hardTokenSN, cert);
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            keyStore.store(baos, password.toCharArray());
            ret = baos.toByteArray();
        } catch (NoSuchAlgorithmException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (InvalidKeySpecException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (IOException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw new IllegalStateException(e);
        } catch (CertificateException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (InvalidAlgorithmParameterException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw new KeyStoreException(e);
        }
        return ret;
    }
}
