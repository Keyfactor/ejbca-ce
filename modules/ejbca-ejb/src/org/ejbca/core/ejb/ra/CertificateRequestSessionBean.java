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
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.SessionContext;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import com.keyfactor.CesecoreException;
import com.keyfactor.ErrorCode;
import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.ExtendedUserDataHandler;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.MsKeyArchivalRequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.LogRedactionUtils;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
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
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.cvc.exception.ParseException;

/**
 * Combines EditUser (RA) with CertReq (CA) methods using transactions.
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
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private EndEntityAuthenticationSessionLocal authenticationSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
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
    public byte[] processCertReq(AuthenticationToken admin, EndEntityInformation userdata, String req, int reqType, int responseType) 
            throws AuthorizationDeniedException, NotFoundException, InvalidKeyException, NoSuchAlgorithmException,
            InvalidKeySpecException, NoSuchProviderException, SignatureException, IOException, CertificateException,
            EndEntityProfileValidationException, ApprovalException, EjbcaException, CesecoreException, CertificateExtensionException {
        byte[] retval = null;

        // Check tokentype
        if (userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN) {
            throw new WrongTokenTypeException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
        }
        
        String password = userdata.getPassword();
        String username = userdata.getUsername();
        RequestMessage requestMessage;
        try {
            requestMessage = RequestMessageUtils.getRequestMessageFromType(username, password, req, reqType);
        } catch (InvalidKeyException | SignRequestSignatureException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (IOException e) {
            throw LogRedactionUtils.getRedactedException(e);
        } catch (ParseException | ConstructionException | NoSuchFieldException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, LogRedactionUtils.getRedactedException(e));
        }
        CAInfo cainfo = caSession.getCAInfoInternal(userdata.getCAId());
        if (cainfo.isUseUserStorage() && username != null) {
            endEntityManagementSession.initializeEndEntityTransaction(username);
        }
        if(cainfo.getCAType() == CAInfo.CATYPE_X509) {
            String preProcessorClass = ((X509CAInfo) cainfo).getRequestPreProcessor();
            if (!StringUtils.isEmpty(preProcessorClass)) {
                try {
                    ExtendedUserDataHandler extendedUserDataHandler = (ExtendedUserDataHandler) Class.forName(preProcessorClass).getDeclaredConstructor().newInstance();
                    requestMessage = extendedUserDataHandler.processRequestMessage(requestMessage, certificateProfileSession.getCertificateProfileName(userdata.getCertificateProfileId()));
                    userdata.setDN(requestMessage.getRequestX500Name().toString());
                } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | IllegalArgumentException
                        | InvocationTargetException | NoSuchMethodException | SecurityException e) {
                    throw new IllegalStateException("Request Preprocessor implementation " + preProcessorClass + " could not be instansiated.");
                }

            }
        }
        
        EndEntityProfile profile = endEntityProfileSession.getEndEntityProfile(userdata.getEndEntityProfileId());
        boolean isClearPwd = profile.isClearTextPasswordUsed() && profile.isClearTextPasswordDefault();

        // This is the secret sauce, do the end entity handling automagically here before we get the cert
        addOrEditUser(admin, userdata, isClearPwd, true);
        // Process request
        try {
            if (requestMessage == null) {
                return retval;
            }
            KeyPair keyPairToArchive = null;
            log.info("reqtype: " + reqType + ", resptype: " + responseType);
            if (reqType==CertificateConstants.CERT_REQ_TYPE_MS_KEY_ARCHIVAL) { 
                log.info("decrypting private key for archival");
                keyPairToArchive = validateAndGetMsaeKeyPairToArchive((MsKeyArchivalRequestMessage)requestMessage);
                log.info("Verified and retrieved private key for archival");
            }
            
            // If no username is supplied initially and the EEP has autogenerated username,
            // requestMessage should be updated. RequestMessage is created before
            // autogenerated username is calculated in addOrEditUser.
            EndEntityProfile entityProfile = endEntityProfileSession.getEndEntityProfile(userdata.getEndEntityProfileId());
            if (StringUtils.isEmpty(username) && entityProfile.isAutoGeneratedUsername()) {
                requestMessage.setUsername(userdata.getUsername());
            }
            // The same goes for password
            if (StringUtils.isEmpty(password) && entityProfile.useAutoGeneratedPasswd()) {
                requestMessage.setPassword(userdata.getPassword());
            }
            
            retval = getCertResponseFromPublicKey(admin, requestMessage, responseType, userdata, keyPairToArchive);                
        } catch (CertificateExtensionException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw LogRedactionUtils.getRedactedException(e);
        } catch (CertificateException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw LogRedactionUtils.getRedactedException(e);
        } catch (EjbcaException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw LogRedactionUtils.getRedactedException(e);
        } catch (CesecoreException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw LogRedactionUtils.getRedactedException(e);
        }
        return retval;
    }
    
    private KeyPair validateAndGetMsaeKeyPairToArchive(MsKeyArchivalRequestMessage requestMessage) throws CertificateCreateException {
        // make sure global config and EE profile allows key archival i.e. recovery is enabled(use??) etc
        // see KeyStoreCreateSessionBean.generateOrKeyRecoverTokenAsByteArray
        // also encryption key usage in the CSR, RSA key etc
        
        // check AccessRulesConstants.REGULAR_KEYRECOVERY to avoid failure during key recovery data storage
        
        // to decrypt
        // should do CA_ACCESS check first and retrieve the private key from CAToken
        // existing: see KeyRecoveryCAService(add a new command and send the request message -> decryptPrivateKey) 
        // and CAAdminSessionBean.extendedService
        // but we may keep it simple
        
        requestMessage.decryptPrivateKey("BC", getDummyPrivateKey());
        return requestMessage.getKeyPairToArchive();
    }
    
    private PrivateKey getDummyPrivateKey() {
        String encodedPrivateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRTiJtDwsRgozw\n"
                + "atZb4/X/HNB/xaOdiSukZRkJ5tNVOEuWV5fjYxALQcnuSW+uUHkwYyniZWO527Ct\n"
                + "lDEJ55TsI/PSXLJ7kFJCiAD4IpkaUyZ7XXpkmWd6SA7jp2EACIc8UIBJaMTuLpmL\n"
                + "ElgrDnu58Rwz652lbqPKqOYLFjkNr/y+JEtrOog8Lk+UPhsUPmXlx940RvWTkfHT\n"
                + "+K7FQC/tFO+4D5boonrH1VtJFd51ZDxsFDhrl2v3yuV8M3AAar516Td8DGe6Tqb6\n"
                + "88LYI4wTVcEBNFkR4ITC8d6721vR5rkihuzvB+XtYGZVlCekEySuM7dA6PcxZ5O6\n"
                + "evmhMGBHAgMBAAECggEAQ4kVJaB9f0xjIq4udZ8EQKlxA1Fn3kyk9toiLqY62Zwd\n"
                + "E6k22smboy46tHcgoJvZxsmweZsihxWCmDehbSM608k0AtQjSSiDynDs8yPix/I9\n"
                + "j//VHsG6+GNo3n8jFuopjMYi5sz2Ai6qH4wvQ9FcDd7lLUGg8ADXu+wssjYc+bOS\n"
                + "NyY9M7tn2oxj6cZkJW5sVgV7EekkAg21o2XB7EJ4NCudKtXmPrqI55G7f6/g1ekK\n"
                + "/+5G09dNqpRLFcWJphZVuU2n526EG6qIySLniFClwgvod/qK8hqgqINAGSOouDIO\n"
                + "OW3zKUlnBvWq4rn8nWFzt+UjdO42byRcUU0h9U13tQKBgQD4UvvXkzl9ASsuZUTD\n"
                + "P++NDLRNiAy+wx2Ch6k2ak4wR/8VfiJPK9HWofGMWSk0bpJjDgX1yf6u7fl0i+mD\n"
                + "+7+odrwaWG5xbGgSKKYJDwcBHRBRMuH1EIs0drydv0qW0HtTffzLplOx0ehyHk+9\n"
                + "OpXEaPlGxrgxdlXWAEsoCyAhqwKBgQDXxmO5s7DVmfTxG8UpOSmU3HfkhsTRI7Yb\n"
                + "jB3RyEB7fmvCPSJYk1MD8RNgzbuE/aagKSSa2K1tct/rALu5vxheiM4UO+1JTpnj\n"
                + "6HeqPSIovMilzmTzOUY4Z53+aropaJoULnYckmeUqqZy8vXna6NERu/crI45+Xpz\n"
                + "4OutQ0oX1QKBgFxpXWmDU4COn8g7TZSvxXEjSjIUMFIJgIDkBXfHpeNX17ji4Ne/\n"
                + "we5zA9YsFCZ8A6QzQsqOamYlD5Fsw/EnDdMepK/VOvyg0DX5xJhYbE3gyAK/wdEW\n"
                + "YAedLGI0Hwjy+wI+P4Z2Fm11ZWCaoSgVlkiqnCHXsBJQLG9gWpfDVCjTAoGAZ0r8\n"
                + "gHBpzcc2v5lIp/RKWI22AzsUyv1qdwN7XuqbG8MoOMLlRzu3eOKWITg7dW2rr24i\n"
                + "rNHfK87bLHecZk35j3+0D3GkpPwwpS6q4l8DlDbTYrRMFTcsy2Gm+50B40LEx7Z6\n"
                + "KjFXzo5mwg5W82LOtKe0uZINP+mS2hgpGjdlJ8UCgYBrkGcASe18yKscrWis02bx\n"
                + "3d+ror5tdATqmuJDJR31g/lSpC3w+sBvOleHcXkX36LSxZUqZyaHJowNoXYathbs\n"
                + "tgNgD2tp2hDBEHdJOcx5Vo7HGHRSAbJjeSBtjc8kJuSVmEvUNBST5Tt5DWzcOloJ\n"
                + "SSPpWa3QgFphkWUYxVi2Gw=="; // TODO
        String encodedPrivateKey125 = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCv6WTq3YWCeKXk\n"
                + "t4ca7EsOpjylnhMstaoPoFIrj4nN1aOgR3MzQMY9xpf5rKkYpuJSZ4R0byZrL0Mm\n"
                + "7um5A/4eawq93YA2bEvzp7poYfpfc0j4bgD6kb4ksn1zC9NBH4r5J4yqM3vNoqkt\n"
                + "Xqx9WIzwWk61RKB7ugws3ap+aLQJ1sFBbCaUKqJTb3d21o+PcM3m3FAiaXu+NiC+\n"
                + "hAQB7G8xSM8VqHQ8MYFvhZNS2QOUq5pd/aR0B6231pIt08CAc1H7hr+aCGUUC/P9\n"
                + "5MOUH6pgcvb6FuJgklY/+GSrIHgoYBJ9BxLmxVB/36oXZAfuI5nzbRyoYfTCmtGB\n"
                + "6clGUJebAgMBAAECggEAEzikb0lfQj9emRw4pgd1uBcP/2TDYZpEB8sTz3CytQwI\n"
                + "AgZsnwgP4UYm6wAjxe7OQgTPo01V3FZgtwtZ/H5kMPyvQsnGLawtrGUCaE90ZSOa\n"
                + "sJKMhtSP+0CJlp2PKsmAjPL2Ws6fU3vXkn6KyHN5ivXDLelew8YzeF+MNp3INl7S\n"
                + "9pOM34IiYwFB2HYMOlRh6ei5yFo9wKsgo6x3LiHUQD8PdKAnnVyAIG4GkZr28e/8\n"
                + "XXsBUKJRM0A5UmDQ7+8JsNo7F7euyoR4ofzyzbA2jzqW0PBJAKuyUcOx8UshfFLv\n"
                + "4TMzYbm34PLesEk6x9I1EcI2hdr/Fp5U8D9hOtZ94QKBgQD3tKJXjpPjImiVp6tK\n"
                + "5I2nCzJ1sGZ2mSxVzzw/DwyxE2bW+yob0h1c7Hmon+fvKESrb236vyqawwiXgMKL\n"
                + "ptmFE9Kv5/J4aOCV7SKDGpbb5CdYp9N0BqQdcg46J4eQFj+iEZ08yfHIn96PYR5F\n"
                + "BBevfLYF4qOhXWPDI+R+5Qy3CwKBgQC1zVVADwbAuUehE9jXedp0vsFZ/uYGE8+5\n"
                + "mnrAvqTiwcgY7rb2qFmDrcLqv3h6YjdN+OpLYJSCVJjoLBRFBIAugRsg0kSYQfM8\n"
                + "X5CjsRaLFR4t+n7ZK+V2tJqQJkDmX9SScqrqNM94MWoKjDv/3WRKs6hQgUPjA39b\n"
                + "Wa8CuxO7sQKBgQDl42/zYLCh0TJNCjJwLFPG3x5ymUdO9HNwJAfe4kG+Kap9BNcc\n"
                + "wNFdh16Vf+qKS84HaUAhwb9xqGZV7TsgzrX7ytzzQooG9BbTLiSklk3CQCnAHumh\n"
                + "OfSgG1VW5Y7ry6o86KoMW8OYlb7BRLoKBXVR+aUZKzD/tqO63JnYpw045wKBgBcu\n"
                + "wNEzWVQYDEdBBaSseCvs6zDzrRdXTWTIiyCq7tGvjjmHrzMS0p9U+AcBNXa9sXmy\n"
                + "5QWJokZgTUNF46vNYB8N/YyY44Ba4I5xTTtiaJKBteB9EdHVpCQX8aGyDxKRY8Ts\n"
                + "9Fh7NX2JJ5GCwl/lNlXERRFG+oYnOwVGEWgSvPhxAoGBAKbXsNZisgS9GnNX4O4B\n"
                + "P0UP1uYo0Q6p+byXBVLTzbDy3ABTaZP72YN3OTfOTFbDH+xcMPox3mjEW2h93hng\n"
                + "+xEXhHJCGU65RyBGYIjmDvUpL1aOnlGSHWvikvO4Nz6mYf34zM7r/VNfUGJszWt0\n"
                + "d3UPY8K+dVYrgp7d7pGvRybA";
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(encodedPrivateKey125.getBytes())));
        } catch (Exception e) {
            log.error("Unable to reconstruct dummy private key", e);
            return null;
        }
    }

    @Override
    public ResponseMessage processCertReq(AuthenticationToken admin, EndEntityInformation userdata, RequestMessage req, Class<? extends CertificateResponseMessage> responseClass)
            throws EndEntityExistsException, AuthorizationDeniedException, EndEntityProfileValidationException, EjbcaException, CesecoreException, CertificateExtensionException {
        // Check tokentype
        if (userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN) {
            throw new WrongTokenTypeException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10/SPKAC/CRMF/CVC requests");
        }
        CAInfo cainfo = caSession.getCAInfoInternal(userdata.getCAId());
        if (cainfo.isUseUserStorage() && userdata.getUsername() != null) {
            endEntityManagementSession.initializeEndEntityTransaction(userdata.getUsername());
        }
        if(cainfo.getCAType() == CAInfo.CATYPE_X509) {
            String preProcessorClass = ((X509CAInfo) cainfo).getRequestPreProcessor();
            if (!StringUtils.isEmpty(preProcessorClass)) {
                try {
                    ExtendedUserDataHandler extendedUserDataHandler = (ExtendedUserDataHandler) Class.forName(preProcessorClass).getDeclaredConstructor().newInstance();
                    req = extendedUserDataHandler.processRequestMessage(req, certificateProfileSession.getCertificateProfileName(userdata.getCertificateProfileId()));
                    userdata.setDN(req.getRequestX500Name().toString());
                } catch (InstantiationException | IllegalAccessException | ClassNotFoundException | IllegalArgumentException
                        | InvocationTargetException | NoSuchMethodException | SecurityException e) {
                    throw new IllegalStateException("Request Preprocessor implementation " + preProcessorClass + " could not be instansiated.");
                }

            }
        }
        
        if(req instanceof SshRequestMessage) {
            CertificateProfile cerificateProfile = 
                    certificateProfileSession.getCertificateProfile(userdata.getCertificateProfileId());
            if(cerificateProfile!=null) {
                // otherwise, properly logged exception will thrown later
                ((SshRequestMessage) req).populateEndEntityData(userdata, cerificateProfile);
            }            
        }
        
        // This is the secret sauce, do the end entity handling automagically here before we get the cert
        addOrEditUser(admin, userdata, false, true);
        ResponseMessage retval = null;
        try {
            retval = signSession.createCertificate(admin, req, responseClass, userdata);
        } catch (EjbcaException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw LogRedactionUtils.getRedactedException(e);
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
                    log.debug("End entity '" + username + "' exists, update the userdata. New status '" + userdata.getStatus() + "'.");
                }
                endEntityManagementSession.changeUser(admin, userdata, clearpwd, fromwebservice);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("New end entity '" + username + "', adding userdata. New status '" + userdata.getStatus() + "'.");
                }
                // addUserfromWS also checks useUserStorage internally, so don't duplicate the check
                endEntityManagementSession.addUser(admin, userdata, clearpwd);
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
     * @param responseType is one of SecConst.CERT_RES_TYPE_...
     * @return a encoded certificate of the type specified in responseType
     * @throws AuthorizationDeniedException
     * @throws CertificateExtensionException if the request message contained invalid extensions
     */
    private byte[] getCertResponseFromPublicKey(AuthenticationToken admin, RequestMessage msg, int responseType,
            EndEntityInformation userData, KeyPair keyPairToArchive) throws EjbcaException, CesecoreException, CertificateEncodingException, CertificateException,
            AuthorizationDeniedException, CertificateExtensionException {
        byte[] retval = null;
        Class<X509ResponseMessage> respClass = X509ResponseMessage.class;
        ResponseMessage resp = signSession.createCertificate(admin, msg, respClass, userData);
        // TODO: in case of exception need to send a signed response with different cMCStatus
        Certificate cert = CertTools.getCertfromByteArray(resp.getResponseMessage(), Certificate.class);
        if (responseType == CertificateConstants.CERT_RES_TYPE_CERTIFICATE) {
            retval = cert.getEncoded();
        }
        if (keyPairToArchive!=null) {
            // archive the MSAE keypair
            // see KeyStoreCreateSessionBean.finishProcessingAndStoreKeys
            keyRecoverySession.addKeyRecoveryData(admin, EJBTools.wrap(cert), userData.getUsername(), EJBTools.wrap(keyPairToArchive));
        }
        if (!"X.509".equals(cert.getType()) && (responseType == CertificateConstants.CERT_RES_TYPE_PKCS7 || 
                responseType == CertificateConstants.CERT_RES_TYPE_PKCS7WITHCHAIN ||
                responseType == CertificateConstants.CERT_RES_TYPE_CMCFULLPKI)) {
            log.info("Certificate response type PKCS7/PKCS7withChain/CMC can only be used with X.509 certificates, not " + cert.getType());
        }
        if (responseType == CertificateConstants.CERT_RES_TYPE_CMCFULLPKI) {
            retval = signSession.createCmcFullPkiResponse(admin, userData.getCAId(), (X509Certificate)cert, 
                                                                                (MsKeyArchivalRequestMessage) msg);
        }
        if (responseType == CertificateConstants.CERT_RES_TYPE_PKCS7) {
            retval = signSession.createPKCS7(admin, (X509Certificate)cert, false, userData.getEndEntityProfileId());
        }
        if (responseType == CertificateConstants.CERT_RES_TYPE_PKCS7WITHCHAIN) {
            retval = signSession.createPKCS7(admin, (X509Certificate)cert, true, userData.getEndEntityProfileId());
        }
        return retval;
    }

    @Override
    public byte[] processSoftTokenReq(AuthenticationToken admin, EndEntityInformation userdata, String keyspec, String keyalg,
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
                    createJKS ? SecConst.TOKEN_SOFT_JKS : SecConst.TOKEN_SOFT_P12, loadkeys, savekeys,
                    reusecertificate, endEntityProfileId);
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
            throw new IllegalStateException(LogRedactionUtils.getRedactedException(e));
        } catch (CertificateException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw LogRedactionUtils.getRedactedException(e);
        } catch (InvalidAlgorithmParameterException e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw e;
        } catch (RuntimeException e) {
            throw new RuntimeException(LogRedactionUtils.getRedactedException(e));
        } catch (Exception e) {
            sessionContext.setRollbackOnly(); // This is an application exception so it wont trigger a roll-back automatically
            throw new KeyStoreException(LogRedactionUtils.getRedactedException(e));
        }
        return ret;
    }
}
