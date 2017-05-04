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

package org.ejbca.core.protocol.cmp.authentication;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.core.protocol.cmp.CmpPbeVerifyer;
import org.ejbca.core.protocol.cmp.InvalidCmpProtectionException;

/**
 * Checks the authentication of the PKIMessage.
 * 
 * In RA mode, the authenticity is checked through a shared secret specified either in 
 * the configuration file or in the CA.
 * 
 * In client mode, the authenticity is checked through the clear-text-password of the 
 * pre-registered endentity from the database. 
 * 
 * @version $Id$
 */
public class HMACAuthenticationModule implements ICMPAuthenticationModule {

    private static final Logger LOG = Logger.getLogger(HMACAuthenticationModule.class);
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();

    private final AuthenticationToken authenticationToken;
    private final EndEntityAccessSession endEntityAccessSession;
    
    private final String globalSharedSecret;
    private final CAInfo caInfo;
    private final String confAlias;
    private final CmpConfiguration cmpConfiguration;
    
    private String password = null;
    private String errorMessage = null;
    private CmpPbeVerifyer verifyer = null;
        
    public HMACAuthenticationModule(AuthenticationToken authenticationToken, String globalSharedSecret, String confAlias, CmpConfiguration cmpConfiguration, 
            CAInfo caInfo, EndEntityAccessSession endEntityAccessSession) {
        this.globalSharedSecret = globalSharedSecret;
        this.confAlias = confAlias;
        this.caInfo = caInfo;
        this.cmpConfiguration = cmpConfiguration;
        this.authenticationToken = authenticationToken;
        this.endEntityAccessSession = endEntityAccessSession;
    }
    
    @Override
    public String getName() {
        return CmpConfiguration.AUTHMODULE_HMAC;
    }
    
    @Override
    public String getAuthenticationString() {
        return this.password;
    }
    
    @Override
    public String getErrorMessage() {
        return this.errorMessage;
    }
    
    public CmpPbeVerifyer getCmpPbeVerifyer() {
        return this.verifyer;
    }
    
    /*
     * Verifies that 'msg' is sent by a trusted source. 
     * 
     * In RA mode:
     *      - A globally configured shared secret for all CAs will be used to authenticate the message.
     *      - If the globally shared secret fails, the password set in the CA will be used to authenticate the message.
     *  In client mode, the clear-text password set in the pre-registered end entity in the database will be used to 
     *  authenticate the message. 
     * 
     * When successful, the authentication string will be set to the password that was successfully used in authenticating the message.
     */
    @Override
    public boolean verifyOrExtract(final PKIMessage pkiMessage, final String username) {
        if (pkiMessage == null) {
            this.errorMessage = "No PKIMessage was found";
            return false;
        }
        if (pkiMessage.getProtection() == null || pkiMessage.getHeader().getProtectionAlg() == null) {
            this.errorMessage = "PKI Message is not athenticated properly. No HMAC protection was found.";
            return false;
        }
        try {
            verifyer = new CmpPbeVerifyer(pkiMessage);
        } catch (InvalidCmpProtectionException e) {
            this.errorMessage = "Could not create CmpPbeVerifyer. "+e.getMessage();
            return false;
        }
        if (this.cmpConfiguration.getRAMode(this.confAlias)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verifying HMAC in RA mode");
            }
            // Check that the value of KeyId from the request is allowed 
            // Note that this restriction only applies to HMAC and not EndEntityCertificate because in the latter, the use of profiles can be restricted through 
            // Administrator privileges. Other authentication modules are not used in RA mode
            final boolean useKeyIdForEndEntityProfile = StringUtils.equals(cmpConfiguration.getRAEEProfile(confAlias), CmpConfiguration.PROFILE_USE_KEYID);
            final boolean useKeyIdForCertificateProfile = StringUtils.equals(cmpConfiguration.getRACertProfile(confAlias), CmpConfiguration.PROFILE_USE_KEYID);
            if (useKeyIdForEndEntityProfile || useKeyIdForCertificateProfile) {
                final String keyId = CmpMessageHelper.getStringFromOctets(pkiMessage.getHeader().getSenderKID());
                if ((useKeyIdForEndEntityProfile && StringUtils.equals(keyId, EndEntityProfileSession.EMPTY_ENDENTITYPROFILENAME)) ||
                        (useKeyIdForCertificateProfile && StringUtils.equals(keyId, CertificateProfile.ENDUSERPROFILENAME))) {
                    errorMessage = "Unaccepted KeyId '" + keyId + "' in CMP request";
                    LOG.info(errorMessage);
                    return false;
                }
            }
            // If we use a globally configured shared secret for all CAs we check it right away
            if (globalSharedSecret != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Verifying message using Global Shared secret");
                }
                if (performPbeVerification(globalSharedSecret, "cmp.errorauthmessage", "Global auth secret")) {
                    return true;
                }
            }
            // We failed verification using global shared secret, try the CA secret
            if (caInfo instanceof X509CAInfo) {
                final String authSecret = ((X509CAInfo) caInfo).getCmpRaAuthSecret();
                if (StringUtils.isNotEmpty(authSecret)) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Verify message using 'CMP RA Authentication Secret' from CA '" + caInfo.getName() + "'.");
                    }
                    if (performPbeVerification(authSecret, "cmp.errorauthmessage", "Auth secret for CA=" + caInfo.getName())) {
                        return true;
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("CMP password is null from CA '"+caInfo.getName()+"'.");
                    }
                }
            }
            // We have failed verification with CA authentication secret too.
            this.errorMessage = "Failed to verify message using both Global Shared Secret and CMP RA Authentication Secret";
        } else {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Verifying HMAC in Client mode");
            }
            //If client mode, we try to get the pre-registered endentity from the DB, and if there is a 
            //clear text password we check HMAC using this password.
            EndEntityInformation endEntityInformation = null;
            String subjectDN = null;
            try {
                if (username != null) {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Searching for an end entity with username='" + username + "'.");
                    }
                    endEntityInformation = this.endEntityAccessSession.findUser(authenticationToken, username);
                } else {
                    // No username given, so we try to find from subject/issuerDN from the certificate request
                    final CertTemplate certTemplate = getCertTemplate(pkiMessage);
                    subjectDN = certTemplate.getSubject().toString();
                    if (subjectDN != null) {
                        final List<EndEntityInformation> endEntityInformations;
                        final X500Name issuer = certTemplate.getIssuer();
                        if (issuer == null) {
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Searching for an end entity with SubjectDN='" + subjectDN + "'.");
                            }
                            endEntityInformations = this.endEntityAccessSession.findUserBySubjectDN(authenticationToken, subjectDN);
                            if (endEntityInformations.size() > 1) {
                                LOG.warn("Multiple end entities with subject DN " + subjectDN + " were found. This may lead to unexpected behavior.");
                            }
                        } else {
                            final String issuerDN = issuer.toString();
                            if (LOG.isDebugEnabled()) {
                                LOG.debug("Searching for an end entity with SubjectDN='" + subjectDN + "' and isserDN='" + issuerDN + "'");
                            }
                            endEntityInformations = endEntityAccessSession.findUserBySubjectAndIssuerDN(this.authenticationToken, subjectDN, issuerDN);
                            if (endEntityInformations.size() > 1) {
                                LOG.warn("Multiple end entities with subject DN " + subjectDN + " and issuer DN" + issuerDN
                                        + " were found. This may lead to unexpected behavior.");
                            }
                        }                    
                        if (!endEntityInformations.isEmpty()) {
                            endEntityInformation = endEntityInformations.get(0);
                        }
                    }
                }
            } catch (AuthorizationDeniedException e) {
                LOG.info("Not authorized to search for end entity: " + e.getMessage());
            }
            if (endEntityInformation == null) {
                LOG.info(INTRES.getLocalizedMessage("ra.errorentitynotexist", StringUtils.isNotEmpty(username) ? username : subjectDN));
                this.errorMessage = INTRES.getLocalizedMessage("ra.wrongusernameorpassword");
                return false;
            }
            if (LOG.isDebugEnabled()) {
                LOG.debug("Comparing HMAC password authentication for user '" + endEntityInformation.getUsername() + "'.");
            }
            final String eepassword = endEntityInformation.getPassword();
            if (StringUtils.isEmpty(eepassword)) {
                this.errorMessage = "No clear text password for user '" + endEntityInformation.getUsername() + "', not possible to check authentication.";
                return false;
            }
            if (performPbeVerification(eepassword, "cmp.errorauthmessage", endEntityInformation.getUsername())) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Try to validate the PKIMessage using the provided shared secret.
     * 
     * Saves last error message on failure to validate.
     * Saves raAuthenticationSecret on successful validation (to be used later when creating response protection)
     * @return true if the validation was successful.
     */
    private boolean performPbeVerification(final String raAuthenticationSecret, final String errorMessageKey, final String errorMessageParameter) {
        try {
            if (verifyer.verify(raAuthenticationSecret)) {
                this.password = raAuthenticationSecret;
                return true;
            } else {
                String errmsg = INTRES.getLocalizedMessage(errorMessageKey, errorMessageParameter);
                LOG.info(errmsg);
                if (verifyer.getErrMsg() != null) {
                    errmsg = verifyer.getErrMsg();
                    LOG.info(errmsg);
                }
                this.errorMessage = errmsg;
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            this.errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
            LOG.info(this.errorMessage, e);
        } 
        return false;
    }

    /**
     * Returns the certificate template specified in the request impeded in msg.
     * 
     * @param msg
     * @return the certificate template embedded in msg. Null if no such template was found.
     */
    private CertTemplate getCertTemplate(final PKIMessage msg) {
        final int tagnr = msg.getBody().getType();
        if(tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST 
                || tagnr==CmpPKIBodyConstants.CERTIFICATAIONREQUEST
                || tagnr==CmpPKIBodyConstants.KEYUPDATEREQUEST) {
            CertReqMessages reqmsgs = (CertReqMessages) msg.getBody().getContent();
            return reqmsgs.toCertReqMsgArray()[0].getCertReq().getCertTemplate();
        }
        if(tagnr==CmpPKIBodyConstants.REVOCATIONREQUEST) {
            RevReqContent rev  =(RevReqContent) msg.getBody().getContent();
            return rev.toRevDetailsArray()[0].getCertDetails();
        }
        return null;
    }
}
