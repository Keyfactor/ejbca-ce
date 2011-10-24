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

package org.ejbca.core.protocol.cmp.authentication;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

import com.novosec.pkix.asn1.cmp.PKIMessage;

/**
 * Check the authentication of the PKIMessage by verifying the signature of the administrator who sent the message
 * 
 * @version $Id$
 *
 */
public class EndEntityCertificateAuthenticationModule implements ICMPAuthenticationModule {

    private static final Logger log = Logger.getLogger(EndEntityCertificateAuthenticationModule.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    private String authenticationParameterCAName;
    private String password;
    private String errorMessage;
    
    private AuthenticationToken admin;
    private CaSession caSession;
    private CertificateStoreSession certSession;
    private AccessControlSession authSession;
    private EndEntityProfileSession eeProfileSession;
    private EndEntityAccessSession eeAccessSession;
    private WebAuthenticationProviderSessionLocal authenticationProviderSession;

    public EndEntityCertificateAuthenticationModule(final String parameter) {
        this.authenticationParameterCAName = parameter;
        password = null;
        errorMessage = null;        
        admin = null;
        caSession = null;
        certSession = null;
        authSession = null;
        eeProfileSession = null;
        eeAccessSession = null;
        authenticationProviderSession = null;
    }
    
    /**
     * Sets the sessions needed to perform the verification.
     * 
     * @param adm
     * @param caSession
     * @param certSession
     * @param authSession
     * @param eeprofSession
     */
    public void setSession(final AuthenticationToken adm, final CaSession caSession, final CertificateStoreSession certSession, 
            final AccessControlSession authSession, final EndEntityProfileSession eeprofSession, final EndEntityAccessSession eeaccessSession,
            final WebAuthenticationProviderSessionLocal authProvSession) {
        this.admin = adm;
        this.caSession = caSession;
        this.certSession = certSession;
        this.authSession = authSession;
        this.eeProfileSession = eeprofSession;
        this.eeAccessSession = eeaccessSession;
        this.authenticationProviderSession = authProvSession;
    }
    
    
    /**
     * Returns the name of this authentication module as String
     * 
     * @return the name of this authentication module as String
     */
    public String getName() {
        return CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
    }
    
    /**
     * Returns the password resulted from the verification process.
     * 
     * This password is set if verify() returns true.
     * 
     * @return The password as String. Null if the verification had failed.
     */
    public String getAuthenticationString() {
        return this.password;
    }
    
    /**
     * Get the error message resulted from the failure of the verification process.
     * 
     * The error message is set if verify() returns false.
     * 
     * @return The error message as String. Null if no error had ocured.
     */
    public String getErrorMessage() {
        return this.errorMessage;
    }

    /**
     * Verifies the signature of 'msg'. msg should be signed by an authorized administrator in EJBCA and 
     * the administrator's cerfificate should be attached in msg in the extraCert field.  
     * 
     * When successful, the password is set to the randomly generated 16-gidits String.
     * When failed, the error message is set.
     * 
     * @param msg PKIMessage
     * @return true if the message signature was verified successfully and false otherwise.
     */
    public boolean verifyOrExtract(final PKIMessage msg, final String username) {
        
        //Check that there is a certificate in the extraCert field in msg
        final X509CertificateStructure extraCertStruct = msg.getExtraCert(0);
        if(extraCertStruct == null) {
            errorMessage = "There is no certificate in the extraCert field in the PKIMessage";
            log.info(errorMessage);
            return false;
        }
        
        //Read the extraCert and store it in a local variable
        Certificate extracert = null;
        try {
            extracert = CertTools.getCertfromByteArray(extraCertStruct.getEncoded());
        } catch (CertificateException e) {
            this.errorMessage = e.getLocalizedMessage();
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage);
            }
            return false;
        } catch (IOException e) {
            this.errorMessage = e.getLocalizedMessage();
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage);
            }
            return false;
        }
        
        final String fp = CertTools.getFingerprintAsString(extracert);
        if(fp == null) {
            this.errorMessage = "Could not get the fingerprint of the certificate in the extraCert field in the CMP request";
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage);
            }
            return false;            
        }
        
        // Get CA info. In case of fail, error message would have already been sat and logged.
        CAInfo cainfo = getAndCheckCAInfo(extracert);
        if(cainfo == null) {
            return false;
        }
 
        if(CmpConfiguration.getRAOperationMode() && CmpConfiguration.getCheckAdminAuthorization()) {
            //Check that the certificate in the extraCert field exists in the DB. In case of fail, error message would have already been sat and logged.
            if(getActiveExistingCertInfo(fp) == null) {
                return false;
            }
                
            //Check that the request sender is an authorized administrator
            try {
                if(!isAuthorized(extracert, msg, cainfo.getCAId())){
                    errorMessage = "'" + CertTools.getSubjectDN(extracert) + "' is not an authorized administrator.";
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;           
                }
            } catch (NotFoundException e1) {
                errorMessage = e1.getLocalizedMessage();
                if(log.isDebugEnabled()) {
                    log.debug(errorMessage);
                }
            }
                
        } else if(!CmpConfiguration.getRAOperationMode()) {
            
            //Check that the certificate in the extraCert field exists in the DB. In case of fail, error message would have already been sat and logged.
            CertificateInfo certInfo = getActiveExistingCertInfo(fp);
            if(certInfo == null) {
                return false;
            }
            
            // Verify the signature of the client certificate as well, that it is really issued by this CA
            Certificate cacert = cainfo.getCertificateChain().iterator().next();
            try {
                extracert.verify(cacert.getPublicKey(), "BC");
            } catch (Exception e) {
                errorMessage = "The End Entity certificate attached to the PKIMessage is not issued by the CA \"" + this.authenticationParameterCAName + "\"";
                if(log.isDebugEnabled()) {
                    log.debug(errorMessage+": "+e.getLocalizedMessage());
                }
                return false;                
            }
         
            // If client mode we will check if this certificate belongs to the user, and set the password of the request to this user's password
            // so it can later be used when issuing the certificate
            if (username != null) {
                if (!StringUtils.equals(username, certInfo.getUsername())) {
                    errorMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+username+"'.";
                    if(log.isDebugEnabled()) {
                        // Use a different debug message, as not to reveal too much information
                        final String debugMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+username+"', but to user '"+certInfo.getUsername()+"'.";
                        log.debug(debugMessage);
                    }
                    return false;                
                }
                
                if (log.isDebugEnabled()) {
                    log.debug("Extracting and setting password for user '"+username+"'.");
                }
                try {
                    password = eeAccessSession.findUser(admin, username).getPassword();
                } catch (AuthorizationDeniedException e) {
                    errorMessage = e.getLocalizedMessage();
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;
                }
            }
        }

        
        //Begin the verification process.
        //Verify the signature of msg using the public key of the certificate we found in the database
        try {
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getObjectId().getId(), "BC");
            sig.initVerify(extracert.getPublicKey());
            sig.update(msg.getProtectedBytes());
            if (sig.verify(msg.getProtection().getBytes())) {
                if (password == null) {
                    // If not set earlier
                    password = genRandomPwd();
                }
                return true;
            }
        } catch (InvalidKeyException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            errorMessage = e.getLocalizedMessage();
        } catch (NoSuchAlgorithmException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            errorMessage = e.getLocalizedMessage();
        } catch (NoSuchProviderException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            errorMessage = e.getLocalizedMessage();
        } catch (SignatureException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            errorMessage = e.getLocalizedMessage();
        }
        return false;
    }

    /**
     * Generated a random password of 16 digits.
     * 
     * @return a randomly generated password
     */
    private String genRandomPwd() {
        final IPasswordGenerator pwdgen = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE);
        return pwdgen.getNewPassword(12, 12);
    }
    
    /**
     * Checks if cert belongs to an administrator who is authorized to process the request.
     * 
     * @param cert
     * @param msg
     * @param caid
     * @return true if the administrator is authorized to process the request and false otherwise.
     * @throws NotFoundException
     */
    private boolean isAuthorized(final Certificate cert, final PKIMessage msg, final int caid) throws NotFoundException {
        final CertificateInfo certInfo = certSession.getCertificateInfo(CertTools.getFingerprintAsString(cert));
        final String username = certInfo.getUsername();
        if(authenticationProviderSession == null) {
            errorMessage = "WebAuthenticationProviderSession is null";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            return false;
        }
        
        X509Certificate x509cert = (X509Certificate) cert;
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(x509cert);
        
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        AuthenticationToken reqAuthToken = authenticationProviderSession.authenticate(subject);
        
        if (!authorizedToCA(reqAuthToken, caid)) {
            errorMessage = intres.getLocalizedMessage("ra.errorauthca", Integer.valueOf(caid));
            log.info("Admin " + username + " is not authorized for CA " + caid);
            return false;
        }
        
        final int eeprofid = getUsedEndEntityProfileId(msg.getHeader().getSenderKID().toString());
        final int tagnr = msg.getBody().getTagNo();
        if((tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) || (tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST)) {
        
            if (!authorizedToEndEntityProfile(reqAuthToken, eeprofid, AccessRulesConstants.CREATE_RIGHTS)) {
                errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid));
                log.info(errorMessage);
                return false;
            }
            
            if(!authorizedToEndEntityProfile(reqAuthToken, eeprofid, AccessRulesConstants.EDIT_RIGHTS)) {
                errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid));
                if(log.isDebugEnabled()) {
                    log.error(errorMessage);
                }
                return false;
            }
            
            if(!authSession.isAuthorizedNoLogging(reqAuthToken, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
                errorMessage = "Administrator " + username + " is not authorized to create certificates.";
                log.info(errorMessage);
                return false;
            }
        } else if(tagnr == CmpPKIBodyConstants.REVOCATIONREQUEST) {
            
            if(!authorizedToEndEntityProfile(reqAuthToken, eeprofid, AccessRulesConstants.REVOKE_RIGHTS)) {
                errorMessage = "Administrator " + username + " is not authorized to revoke.";
                log.info(errorMessage);
                return false;
            }
            
            if(!authSession.isAuthorizedNoLogging(reqAuthToken, AccessRulesConstants.REGULAR_REVOKEENDENTITY)) {
                errorMessage = "Administrator " + username + " is not authorized to revoke End Entities";
                log.info(errorMessage);
                return false;
            }
            
        }
        
        return true;

    }
    
    /**
     * Checks whether admin is authorized to access the CA with ID caid
     * @param admin
     * @param caid
     * @return true of admin is authorized and false otherwize
     */
    private boolean authorizedToCA(AuthenticationToken admin, int caid) {
        boolean returnval = false;
        returnval = authSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid);
        if (!returnval) {
            errorMessage = "Admin " + admin.toString() + " not authorized to resource " + StandardRules.CAACCESS.resource() + caid;
            log.info(errorMessage);
        }
        return returnval;
    }
    
    /**
     * Checks whether admin is authorized to access the EndEntityProfile with the ID profileid
     * 
     * @param admin
     * @param profileid
     * @param rights
     * @return true if admin is authorized and false otherwise.
     */
    private boolean authorizedToEndEntityProfile(AuthenticationToken admin, int profileid, String rights) {
        boolean returnval = false;
        if (profileid == SecConst.EMPTY_ENDENTITYPROFILE
                && (rights.equals(AccessRulesConstants.CREATE_RIGHTS) || rights.equals(AccessRulesConstants.EDIT_RIGHTS))) {

            if (authSession.isAuthorizedNoLogging(admin, "/super_administrator")) {
                returnval = true;
            } else {
                errorMessage = "Admin " + admin.toString() + " was not authorized to resource /super_administrator"; 
                log.info(errorMessage);
            }
        } else {
            returnval = authSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights)
                    && authSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        }
        return returnval;
    }

    /**
     * Return the ID of EndEntityProfile that is used for CMP purposes. 
     * @param keyId
     * @return the ID of EndEntityProfile used for CMP purposes. 0 if no such EndEntityProfile exists. 
     * @throws NotFoundException
     */
    private int getUsedEndEntityProfileId(final String keyId) throws NotFoundException {
        int ret = 0;
        String endEntityProfile = CmpConfiguration.getRAEndEntityProfile();
        if (StringUtils.equals(endEntityProfile, "KeyId")) {
            if (log.isDebugEnabled()) {
                log.debug("Using End Entity Profile with same name as KeyId in request: "+keyId);
            }
            endEntityProfile = keyId;
        } 
        ret = eeProfileSession.getEndEntityProfileId(admin, endEntityProfile);
        if (ret == 0) {
            errorMessage = "No end entity profile found with name: "+endEntityProfile;
            log.info(errorMessage);
            throw new NotFoundException(errorMessage);
        }
        return ret;
    }

    private CertificateInfo getActiveExistingCertInfo(String fp) {
        // Check that the certificate is not revoked
        CertificateInfo info = certSession.getCertificateInfo(fp);
        if(info == null) {
            errorMessage = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+". Fingerprint="+fp);
            }

            return null;
        }
        
        if (info.getStatus() != SecConst.CERT_ACTIVE) {
            errorMessage = "The certificate attached to the PKIMessage in the extraCert field is revoked.";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+" Username="+info.getUsername());
            }

            return null;            
        }
        
        return info;
    }
    
    private CAInfo getAndCheckCAInfo(Certificate extracert) {
        CAInfo cainfo = null;
        try {
            //Check that the extraCert is issued by the right CA
            if (!StringUtils.equals("-", this.authenticationParameterCAName)) {
                cainfo = caSession.getCAInfo(this.admin, this.authenticationParameterCAName);
                //Check that the extraCert is given by the right CA
                if(!StringUtils.equals(CertTools.getIssuerDN(extracert), cainfo.getSubjectDN())) {
                    errorMessage = "The certificate attached to the PKIMessage is not given by the CA '" + this.authenticationParameterCAName + "'";
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    cainfo = null;
                }
            } else {
                cainfo = caSession.getCAInfo(this.admin, CertTools.getIssuerDN(extracert).hashCode());
            }
        } catch (CADoesntExistsException e) {
            errorMessage = e.getLocalizedMessage();
            if(log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
        } catch (AuthorizationDeniedException e) {
            errorMessage = e.getLocalizedMessage();
            if(log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
        }
        
        return cainfo;
    }
}
