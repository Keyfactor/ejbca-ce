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

package org.ejbca.ui.web.protocol;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UsernameGenerator;
import org.ejbca.core.model.ra.UsernameGeneratorParams;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.ejbca.core.protocol.scep.ScepResponseMessage;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;


/**
 * Helper class to handle SCEP (draft-nourse-scep-06.txt) requests.
 *
 * @version  $Id$
 */
public class ScepPkiOpHelper {
    private static Logger log = Logger.getLogger(ScepPkiOpHelper.class);
    private AuthenticationToken admin = null;
    private String configAlias = null;
    
    private SignSessionLocal signsession;
    private CaSessionLocal caSession;
    private EndEntityProfileSessionLocal endEntityProfileSession;
    private CertificateProfileSessionLocal certProfileSession;
    private EndEntityManagementSessionLocal endEntityManagementSession;    
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    
    private ScepConfiguration scepConfiguration;

    /**
     * Creates a new ScepPkiOpHelper object.
     *
     * @param admin administrator performing this
     * @param signsession signsession used to request certificates
     */
    public ScepPkiOpHelper(AuthenticationToken admin, String alias, ScepConfiguration scepConfig, SignSessionLocal signsession, CaSessionLocal caSession, EndEntityProfileSessionLocal endEntityProfileSession, 
                    CertificateProfileSessionLocal certProfileSession, EndEntityManagementSessionLocal endEntityManagementSession, 
                    CryptoTokenManagementSessionLocal cryptoTokenManagementSession) {
    	if (log.isTraceEnabled()) {
    		log.trace(">ScepPkiOpHelper");
    	}
        this.admin = admin;
        this.configAlias = alias;
        this.scepConfiguration = scepConfig;
        this.signsession = signsession;
        this.caSession = caSession;
        this.endEntityProfileSession = endEntityProfileSession;
        this.certProfileSession = certProfileSession;
        this.endEntityManagementSession = endEntityManagementSession;
        this.cryptoTokenManagementSession = cryptoTokenManagementSession;
    	if (log.isTraceEnabled()) {
    		log.trace("<ScepPkiOpHelper");
    	}
    }

    /**
     * Handles SCEP certificate request
     *
     * @param msg buffer holding the SCEP-request (DER encoded).
     *
     * @return byte[] containing response to be sent to client.
     * @throws AuthorizationDeniedException 
     * @throws CesecoreException 
     * @throws CertificateExtensionException if msg specified invalid extensions
     */
    public byte[] scepCertRequest(byte[] msg, boolean includeCACert, boolean ramode)
            throws EjbcaException, CesecoreException, AuthorizationDeniedException, CertificateExtensionException, NoSuchEndEntityException {
        byte[] ret = null;
        if (log.isTraceEnabled()) {
        	log.trace(">getRequestMessage(" + msg.length + " bytes)");
        }
        
        try {
            final ScepRequestMessage reqmsg = new ScepRequestMessage(msg, includeCACert);

            if (reqmsg.getErrorNo() != 0) {
                log.error("Error '" + reqmsg.getErrorNo() + "' receiving Scep request message.");
                return null;
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_PKCSREQ) {
            	
                if(log.isDebugEnabled()) {
                    log.debug("SCEP is operating in RA mode: " + ramode);
                }
                
                if(ramode) {
                    if(!addOrEditUser(reqmsg)) {
                        String errmsg = "Error. Failed to add or edit user: " + reqmsg.getUsername();
                        log.error(errmsg);
                        return null;
                    }
                }
                
                // Get the certificate
                ResponseMessage resp = signsession.createCertificate(admin, reqmsg, ScepResponseMessage.class, null);
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
            if (reqmsg.getMessageType() == ScepRequestMessage.SCEP_TYPE_GETCRL) {
                // create the stupid encrypted CRL message, the below can actually only be made 
                // at the CA, since CAs private key is needed to decrypt
                ResponseMessage resp = signsession.getCRL(admin, reqmsg, ScepResponseMessage.class);
                if (resp != null) {
                    ret = resp.getResponseMessage();
                }
            }
        } catch (IOException e) {
            log.error("Error receiving ScepMessage: ", e);
        } catch (GeneralSecurityException e) {
            log.error("Error receiving ScepMessage: ", e);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<getRequestMessage():" + ((ret == null) ? 0 : ret.length));
        }
        return ret;
    }
    
    private boolean addOrEditUser(ScepRequestMessage reqmsg) {
        
        // Try to find the CA name from the issuerDN in the request. If we can't find it, we use the default
        String caName = getCAName(CertTools.stringToBCDNString(reqmsg.getIssuerDN()));
        if(StringUtils.isEmpty(caName)) {
            log.error("No CA was set in the scep.propeties file.");
            return false;
        }
        
        CAInfo cainfo;
        CA ca;
        try {
            cainfo = caSession.getCAInfo(admin, caName);
            ca = caSession.getCA(admin, caName);
        } catch (CADoesntExistsException e1) {
            log.error("Could not find CA: " + caName);
            log.error(e1.getLocalizedMessage(), e1);
            return false;
        } catch (AuthorizationDeniedException e1) {
            log.error("Administator is not authorized for CA: " + caName);
            log.error(e1.getLocalizedMessage(), e1);
            return false;
        }
        final CAToken catoken = cainfo.getCAToken();
        final CryptoToken cryptoToken = cryptoTokenManagementSession.getCryptoToken(catoken.getCryptoTokenId());
        
        try {
            reqmsg.setKeyInfo(ca.getCACertificate(), cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN)), cryptoToken.getSignProviderName());
        } catch (CryptoTokenOfflineException e1) {
            log.error("Failed to set the new private key in the SCEP message");
            log.error(e1.getLocalizedMessage(), e1);
            return false;
        }
        
        // Verify the request
        String authPwd = scepConfiguration.getRAAuthPassword(configAlias);
        if (StringUtils.isNotEmpty(authPwd) && !StringUtils.equals(authPwd, "none")) {
            if (log.isDebugEnabled()) {
                log.debug("Requiring authPwd in order to precess SCEP requests");
            }
            String pwd = reqmsg.getPassword();
            if (!StringUtils.equals(authPwd, pwd)) {
                log.error("Wrong auth password received in SCEP request: "+pwd);
                return false;
            }
            if (log.isDebugEnabled()) {
                log.debug("Request passed authPwd test.");
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Not requiring authPwd in order to precess SCEP requests");
            }
        }
        
        //Creating the user
        UsernameGeneratorParams usernameGenParams = new UsernameGeneratorParams();
        usernameGenParams.setMode(scepConfiguration.getRANameGenerationScheme(configAlias));
        usernameGenParams.setDNGeneratorComponent(scepConfiguration.getRANameGenerationParameters(configAlias));
        usernameGenParams.setPrefix(scepConfiguration.getRANameGenerationPrefix(configAlias));
        usernameGenParams.setPostfix(scepConfiguration.getRANameGenerationPostfix(configAlias));
        
        X500Name dnname = new X500Name(reqmsg.getRequestDN());
        final UsernameGenerator gen = UsernameGenerator.getInstance(usernameGenParams);
        final String username = gen.generateUsername(dnname.toString());
        final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
        final String pwd = pwdgen.getNewPassword(12, 12);
        
        // AltNames may be in the request template
        final String altNames = reqmsg.getRequestAltNames();
        final String email;
        final List<String> emails = CertTools.getEmailFromDN(altNames);
        emails.addAll(CertTools.getEmailFromDN(dnname.toString()));
        if (!emails.isEmpty()) {
            email = emails.get(0); // Use rfc822name or first SubjectDN email address as user email address if available
        } else {
            email = null;
        }
        
        int eeProfileId = 0;
        try {
            eeProfileId = endEntityProfileSession.getEndEntityProfileId(scepConfiguration.getRAEndEntityProfile(configAlias));
        } catch (EndEntityProfileNotFoundException e) {
            log.error("Could not find the end entity profile: " + scepConfiguration.getRAEndEntityProfile(configAlias));
            log.error(e.getLocalizedMessage(), e);
            return false;
        }
        int certProfileId = certProfileSession.getCertificateProfileId(scepConfiguration.getRACertProfile(configAlias));
        
        final EndEntityInformation userdata = new EndEntityInformation(username, dnname.toString(), cainfo.getCAId(), altNames, email, EndEntityConstants.STATUS_NEW, new EndEntityType(EndEntityTypes.ENDUSER), eeProfileId, certProfileId, null, null, SecConst.TOKEN_SOFT_BROWSERGEN, 0, null);
        userdata.setPassword(pwd);
        reqmsg.setUsername(username);
        reqmsg.setPassword(pwd);

        try {
            if(endEntityManagementSession.existsUser(username) ){
                endEntityManagementSession.changeUser(admin, userdata, true);
                endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
            } else {
                endEntityManagementSession.addUser(admin, userdata, true);
            }
        } catch(Exception e) {
            log.error("Failed to add or edit user: " + username);
            log.error(e.getLocalizedMessage(), e);
            return false;
        }
        
        return true;
    }
    
    private String getCAName(String issuerDN) {
        String caName = null;
        try {
            caName = caSession.getCA(admin, issuerDN.hashCode()).getName();
            if (log.isDebugEnabled()) {
                log.debug("Found a CA name '"+caName+"' from issuerDN: "+issuerDN);
            }
        } catch(Exception e) {
            caName = scepConfiguration.getRADefaultCA(configAlias);
            log.info("Did not find a CA name from issuerDN: "+issuerDN+", using the default CA '"+caName+"'");
        }
        return caName;
    }
    
}
