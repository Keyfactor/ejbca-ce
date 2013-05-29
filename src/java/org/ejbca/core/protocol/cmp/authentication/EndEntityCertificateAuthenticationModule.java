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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.util.passgen.IPasswordGenerator;
import org.ejbca.util.passgen.PasswordGeneratorFactory;

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
    private Certificate extraCert;
    private String confAlias;
    
    private AuthenticationToken admin;
    private CaSession caSession;
    private CertificateStoreSession certSession;
    private AccessControlSession authSession;
    private EndEntityProfileSession eeProfileSession;
    private EndEntityAccessSession eeAccessSession;
    private WebAuthenticationProviderSessionLocal authenticationProviderSession;
    private EndEntityManagementSession eeManagementSession;

    public EndEntityCertificateAuthenticationModule(final String parameter, String confAlias) {
        this.authenticationParameterCAName = parameter;
        password = null;
        errorMessage = null;      
        extraCert = null;
        this.confAlias = confAlias;
        
        admin = null;
        caSession = null;
        certSession = null;
        authSession = null;
        eeProfileSession = null;
        eeAccessSession = null;
        authenticationProviderSession = null;
        eeManagementSession = null;
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
            final WebAuthenticationProviderSessionLocal authProvSession, EndEntityManagementSession endEntityManagementSession) {
        this.admin = adm;
        this.caSession = caSession;
        this.certSession = certSession;
        this.authSession = authSession;
        this.eeProfileSession = eeprofSession;
        this.eeAccessSession = eeaccessSession;
        this.authenticationProviderSession = authProvSession;
        this.eeManagementSession = endEntityManagementSession;
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
     * Get the certificate that was attached to the CMP request in it's extreCert filed.
     * 
     * @return The certificate that was attached to the CMP request in it's extreCert filed 
     */
    public Certificate getExtraCert() {
        return extraCert;
    }

    /**
     * Verifies the signature of 'msg'. msg should be signed by an authorized administrator in EJBCA and 
     * the administrator's cerfificate should be attached in msg in the extraCert field.  
     * 
     * When successful, the password is set to the randomly generated 16-digit String.
     * When failed, the error message is set.
     * 
     * @param msg PKIMessage
     * @param username
     * @param authenticated
     * @return true if the message signature was verified successfully and false otherwise.
     */
    public boolean verifyOrExtract(final PKIMessage msg, final String username, boolean authenticated) {
        
        //Check that msg is signed
        if(msg.getProtection() == null) {
            errorMessage = "PKI Message is not athenticated properly. No PKI protection is found.";
            log.info(errorMessage);
            return false;
        }
        
        //Check that there is a certificate in the extraCert field in msg
        final CMPCertificate[] extraCerts = msg.getExtraCerts();
        if ((extraCerts == null) || (extraCerts.length == 0)) {
            errorMessage = "There is no certificate in the extraCert field in the PKIMessage";
            log.info(errorMessage);
            return false;
        } else {
            if(log.isDebugEnabled()) {
                log.debug("A certificate is found in the extraCert field in the CMP message");
            }
        }
        
        //Read the extraCert and store it in a local variable
        CMPCertificate cmpcert = extraCerts[0];
        try {
            extraCert = CertTools.getCertfromByteArray(cmpcert.getEncoded());
            if(log.isDebugEnabled()) {
                log.debug("Obtaning the certificate from extraCert field was done successfully");
            }
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

        // Get the fingerprint of extraCert to be used later
        final String fp = CertTools.getFingerprintAsString(extraCert);
        if (fp == null) {
            this.errorMessage = "Could not get the fingerprint of the certificate in the extraCert field in the CMP request";
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage);
            }
            return false;            
        } else {
            if(log.isDebugEnabled()) {
                log.debug("The certificate in the extraCert field in the CMP message had the fingerprint: " + fp);
            }
        }
        
        
        // Determine whether the CA name is set in the 'cmp.authenticationparameters' config value
        boolean isCASet = !(StringUtils.equals("-", this.authenticationParameterCAName) || StringUtils.equalsIgnoreCase("A", this.authenticationParameterCAName));
        boolean vendormode = isVendorCertificateMode(msg.getBody().getType());
        
        // Perform the different checks depending on the configuration and previous authentication
        if(log.isDebugEnabled()) {
            log.debug("CMP is operating in RA mode: " + CmpConfiguration.getRAOperationMode(this.confAlias));
            log.debug("Issuer CA is set: " + isCASet);
            log.debug("CMP message already been authenticated: " + authenticated);
        }
        CAInfo cainfo = null;
        CertificateInfo certinfo = null;
        
        // if client mode, or cmp.authenticationparameters in cmp.properties is set in RA mode:
        //          - Get the CA info that should have issued extraCert
        //          - Check that extraCert is actually issued by the right CA
        //          - Check that extraCert is in the database
        //          - Check that extraCert is valid
        //          - Check that extraCert is active
        if( (!CmpConfiguration.getRAOperationMode(this.confAlias)|| isCASet) && !vendormode  ) {
            
            // Get the CAInfo of the CA that should have issued extraCert 
            cainfo = getCmpCAInfo(extraCert, isCASet, msg.getBody().getType());
            if ( cainfo == null ) {
                return false;
            }

            // Check that extraCert is in the Database
            certinfo = certSession.getCertificateInfo(fp);
            if(certinfo == null) {
                errorMessage = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
                if(log.isDebugEnabled()) {
                    log.debug(errorMessage+". Fingerprint="+fp);
                }
                return false;
            }
            
            // Check that extraCert is issued by the right CA, is valid and is not revoked
            if(!isIssuedByCA(cainfo, true) || !isCertValid(fp) || !isCertActive(certinfo)) {
                return false;
            }
            
            if(log.isDebugEnabled()) {
                log.debug("The certificate in extraCert field is correctly issued by '" + cainfo.getName() + "'");
            }

        }
        
        if(CmpConfiguration.getRAOperationMode(this.confAlias) && isCASet) {// RA mode and cmp.authenticationparameters is set to the name of extraCert issuer
            
            //Check that the request sender is an authorized administrator
            try {
                if (!isAuthorized(extraCert, msg, cainfo.getCAId())){
                    errorMessage = "'" + CertTools.getSubjectDN(extraCert) + "' is not an authorized administrator.";
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
                return false;
            }
            
        } else if(CmpConfiguration.getRAOperationMode(this.confAlias) && !isCASet && !authenticated) { // RA mode, extraCert can be given by any CA and the CMP message has not already been authenticated (aka. is not a NestedMessageContent)
            errorMessage = "The CMP message could not be authenticated in RA mode. No CA has been set in the configuration file and the message has not been authenticated previously";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            return false;            
            
        } else if(!CmpConfiguration.getRAOperationMode(this.confAlias)) { // client mode
            
            if(vendormode) {
                if (log.isDebugEnabled()) {
                    log.debug("CMP is in vendor certificate mode. Not checking that the certificate attached to the PKIMessage in the extraCert field is in the database.");
                }
                
                if(!isIssuedByVendorCA()) {
                    return false;
                }
            }
            
            // Check if this certificate belongs to the user
            if (username != null) {
                String extraCertUsername = getUsername(certinfo, msg.getBody().getType());
                if (!StringUtils.equals(username, extraCertUsername)) {
                    errorMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+username+"'.";
                    if(log.isDebugEnabled()) {
                        // Use a different debug message, as not to reveal too much information
                        final String debugMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+username+"', but to user '"+extraCertUsername+"'.";
                        log.debug(debugMessage);
                    }
                    return false;                
                }
                
                //set the password of the request to this user's password so it can later be used when issuing the certificate
                if (log.isDebugEnabled()) {
                    log.debug("The End Entity certificate attached to the PKIMessage in the extraCert field belongs to user '"+username+"'.");
                    log.debug("Extracting and setting password for user '"+username+"'.");
                }
                try {
                    EndEntityInformation user = eeAccessSession.findUser(admin, username);
                    password = user.getPassword();
                    if(password == null) {
                        password = genRandomPwd();
                        user.setPassword(password);
                        eeManagementSession.changeUser(admin, user, false);
                    }
                } catch (AuthorizationDeniedException e) {
                    errorMessage = e.getLocalizedMessage();
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;
                } catch (CADoesntExistsException e) {
                    errorMessage = e.getLocalizedMessage();
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;
                } catch (UserDoesntFullfillEndEntityProfile e) {
                    errorMessage = e.getLocalizedMessage();
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;
                } catch (WaitingForApprovalException e) {
                    errorMessage = e.getLocalizedMessage();
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;
                } catch (EjbcaException e) {
                    errorMessage = e.getLocalizedMessage();
                    if(log.isDebugEnabled()) {
                        log.debug(errorMessage);
                    }
                    return false;
                }
            }
            
        }
        
        //Begin the signature verification process.
        //Verify the signature of msg using the public key of extraCert
        try {
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), "BC");
            sig.initVerify(extraCert.getPublicKey());
            sig.update(CmpMessageHelper.getProtectedBytes(msg));
            if (sig.verify(msg.getProtection().getBytes())) {
                if (password == null) {
                    // If not set earlier
                    password = genRandomPwd();
                }
                return true;
            } else {
                log.error("Failed to verify the signature in the PKIMessage.");
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
            errorMessage = intres.getLocalizedMessage("ra.errorauthca", Integer.valueOf(caid), reqAuthToken.toString());
            log.info(errorMessage);
            return false;
        }
        
        final int eeprofid = getUsedEndEntityProfileId((DEROctetString) msg.getHeader().getSenderKID());
        final int tagnr = msg.getBody().getType();
        if((tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) || (tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST)) {
        
            if (!authorizedToEndEntityProfile(reqAuthToken, eeprofid, AccessRulesConstants.CREATE_RIGHTS)) {
                errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid), admin.toString());
                log.info(errorMessage);
                return false;
            }
            
            if(!authorizedToEndEntityProfile(reqAuthToken, eeprofid, AccessRulesConstants.EDIT_RIGHTS)) {
                errorMessage = intres.getLocalizedMessage("ra.errorauthprofile", Integer.valueOf(eeprofid), admin.toString());
                log.info(errorMessage);
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

            if (authSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource())) {
                returnval = true;
            } else {
                errorMessage = "Admin " + admin.toString() + " was not authorized to resource " + StandardRules.ROLE_ROOT; 
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
    private int getUsedEndEntityProfileId(final DEROctetString keyId) throws NotFoundException {
        String endEntityProfile = CmpConfiguration.getRAEndEntityProfile(this.confAlias);
        if (StringUtils.equals(endEntityProfile, "KeyId") && (keyId != null)) {
            endEntityProfile = CmpMessageHelper.getStringFromOctets(keyId);
            if (log.isDebugEnabled()) {
                log.debug("Using End Entity Profile with same name as KeyId in request: "+endEntityProfile);
            }
        } 
        try {
            return eeProfileSession.getEndEntityProfileId(endEntityProfile);
        } catch (EndEntityProfileNotFoundException e) {
            errorMessage = "No end entity profile found with name: "+endEntityProfile;
            log.info(errorMessage);
            throw new NotFoundException(errorMessage, e);
        }
    }
    
    private boolean isCertValid(final String fp) {
        X509Certificate cert = (X509Certificate) certSession.findCertificateByFingerprint(fp);
        try {
            cert.checkValidity();
            if(log.isDebugEnabled()) {
                log.debug("The certificate in extraCert is valid");
            }
        } catch(Exception e) {
            errorMessage = "The certificate attached to the PKIMessage in the extraCert field in not valid";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+". Fingerprint="+fp);
                log.debug(e.getLocalizedMessage());
            }
            return false;
        }
        return true;
    }

    private boolean isCertActive(final CertificateInfo certinfo) {
        // Check that the certificate is not revoked
        if (certinfo.getStatus() != CertificateConstants.CERT_ACTIVE) {
            errorMessage = "The certificate attached to the PKIMessage in the extraCert field is revoked.";
            if(log.isDebugEnabled()) {
                log.debug(errorMessage+" Username="+certinfo.getUsername());
            }

            return false;
        } else {
            if(log.isDebugEnabled()) {
                log.debug("The certificate in extraCert is active");
            }
        }
        
        return true;
    }
    
    private boolean isIssuedByCA(CAInfo cainfo, boolean printLog) {
        //Check that the extraCert is given by the right CA
        // Verify the signature of the client certificate as well, that it is really issued by this CA
        Certificate cacert = cainfo.getCertificateChain().iterator().next();
        try {
            extraCert.verify(cacert.getPublicKey(), "BC");
        } catch (Exception e) {
            if(printLog) {
                errorMessage = "The End Entity certificate attached to the PKIMessage is not issued by the CA '" + cainfo.getName() + "'";
                if(log.isDebugEnabled()) {
                    log.debug(errorMessage+": "+e.getLocalizedMessage());
                }
            }
            return false;                
        }
        return true;
    }
    
    private CAInfo getCmpCAInfo(final Certificate extracert, boolean isCASet, int reqType) {
        CAInfo cainfo = null;
        try {
            if (isCASet) {
                cainfo = caSession.getCAInfo(this.admin, this.authenticationParameterCAName);
            } else {
                cainfo = caSession.getCAInfo(this.admin, CertTools.getIssuerDN(extracert).hashCode());
            }
        } catch (CADoesntExistsException e) {
            String canamelog = isCASet ? this.authenticationParameterCAName : String.valueOf(CertTools.getIssuerDN(extracert).hashCode());
            errorMessage = "CA does not exist: " + canamelog;
            if(log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
        } catch (AuthorizationDeniedException e) {
            errorMessage = e.getLocalizedMessage();
            if(log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
        }
        
        return cainfo;
    }
    
    private boolean isIssuedByVendorCA() {
        String vendorCAsStr = CmpConfiguration.getVendorCA(this.confAlias);
        String[] vendorcas = vendorCAsStr.split(";");
        CAInfo cainfo = null;
        for(String vendorca : vendorcas) {
            try {
                cainfo = caSession.getCAInfo(admin, vendorca.trim());
                if(isIssuedByCA(cainfo, false)) {
                    if (log.isDebugEnabled()) {
                        log.debug("The certificate in extraCert field is issued by the Vendor CA: " + vendorca);
                    }
                    return true;
                }
            } catch (CADoesntExistsException e) {
                if(log.isDebugEnabled()) {
                    log.debug("Cannot find CA: " + vendorca);
                }
            } catch (AuthorizationDeniedException e) {
                if(log.isDebugEnabled()) {
                    log.debug(e.getLocalizedMessage());
                }
            }
        }
        errorMessage = "The certificate in extraCert field is not issued by any of the configured Vendor CAs: " + vendorCAsStr;
        if(log.isDebugEnabled()) {
            log.debug(errorMessage);
        }
        return false;
    }
    
    private String getUsername(CertificateInfo certinfo, int reqType) {
        if(isVendorCertificateMode(reqType)) {
            String subjectDN = CertTools.getSubjectDN(extraCert);
            String username = CertTools.getPartFromDN(subjectDN, CmpConfiguration.getExtractUsernameComponent(this.confAlias));
            if(log.isDebugEnabled()) {
                log.debug("Username ("+username+") was extracted from the '" + CmpConfiguration.getExtractUsernameComponent(this.confAlias) + "' part of the subjectDN of the certificate in the 'extraCerts' field.");
            }
            return username;
        } else {
            return certinfo.getUsername();
        }
    }
    
    /**
     * Checks whether authentication by vendor-issued-certificate should be used. If authentication by vendor-issued-certificate is 
     * activated in the Cmp.properties file, it can be used only in client mode and with initialization/certification requests.
     *  
     * @param reqType
     * @return 'True' if authentication by vendor-issued-certificate is used. 'False' otherwise
     */
    private boolean isVendorCertificateMode(int reqType) {
        return !CmpConfiguration.getRAOperationMode(this.confAlias) && CmpConfiguration.getVendorCertificateMode(this.confAlias) && (reqType == 0 || reqType == 2);
    }
 
}
