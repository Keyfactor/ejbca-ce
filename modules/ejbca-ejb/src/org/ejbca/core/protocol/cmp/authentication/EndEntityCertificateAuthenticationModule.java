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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSession;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
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
    
    private String authenticationparameter;
    private String password;
    private String errorMessage;
    private Certificate extraCert;
    private String confAlias;
    private CmpConfiguration cmpConfiguration;
    private boolean authenticated;

    private AuthenticationToken admin;
    private CaSession caSession;
    private CertificateStoreSession certSession;
    private AccessControlSession authSession;
    private EndEntityProfileSession eeProfileSession;
    private EndEntityAccessSession eeAccessSession;
    private WebAuthenticationProviderSessionLocal authenticationProviderSession;
    private EndEntityManagementSession eeManagementSession;

    /** Definition of the optional Vendor mode implementation */
    private static final String implClassName = "org.ejbca.core.protocol.cmp.authentication.CmpVendorModeImpl";
    /** Cache class so we don't have to do Class.forName for every entity object created */
    private static volatile Class<?> implClass = null;
    /** Optimization variable so we don't have to check for existence of implClass for every construction of an object */
    private static volatile boolean implExists = true;

    private CmpVendorMode impl;
    
    public EndEntityCertificateAuthenticationModule( final AuthenticationToken admin, String authparam, String confAlias, 
            CmpConfiguration cmpConfig, boolean authenticated, 
            final CaSession caSession, final CertificateStoreSession certSession, final AccessControlSession authSession, 
            final EndEntityProfileSession eeprofSession, final EndEntityAccessSession eeaccessSession, 
            final WebAuthenticationProviderSessionLocal authProvSession, final EndEntityManagementSession endEntityManagementSession) {
        authenticationparameter = authparam;
        password = null;
        errorMessage = null;
        extraCert = null;
        this.confAlias = confAlias;
        this.cmpConfiguration = cmpConfig;
        this.authenticated = authenticated;
        
        this.admin = admin;
        this.caSession = caSession;
        this.certSession = certSession;
        this.authSession = authSession;
        this.eeProfileSession = eeprofSession;
        eeAccessSession = eeaccessSession;
        authenticationProviderSession = authProvSession;
        eeManagementSession = endEntityManagementSession;
        
        createVendorModeImpl();
    }
    
    /** Creates the implementation for CMP vendor mode, if it exists. If it does not exist, uses a CmpVendorModeNoop implementation that 
     * return false on the question of CMP Vendor mode is used.
     */
    private void createVendorModeImpl() {
        if (implExists) {
            try {
                if (implClass == null) {
                    // We only end up here once, if the class does not exist, we will never end up here again (ClassNotFoundException) 
                    // and if the class exists we will never end up here again (it will not be null)
                    implClass = Class.forName(implClassName);
                    log.debug("CmpVendorModeImpl is available, and used, in this version of EJBCA.");
                }
                impl = (CmpVendorMode)implClass.newInstance();
                impl.setCaSession(caSession);
                impl.setCmpConfiguration(cmpConfiguration);
            } catch (ClassNotFoundException e) {
                // We only end up here once, if the class does not exist, we will never end up here again
                implExists = false;
                log.info("CMP Vendor mode is not available in the version of EJBCA.");
                impl = new CmpVendorModeNoopImpl();
            } catch (InstantiationException e) {
                log.error("Error intitilizing CmpVendorMode: ", e);
            } catch (IllegalAccessException e) {
                log.error("Error intitilizing CmpVendorMode: ", e);
            }           
        } else {
            impl = new CmpVendorModeNoopImpl();
        }
    }

    
    @Override
    public String getName() {
        return CmpConfiguration.AUTHMODULE_ENDENTITY_CERTIFICATE;
    }
    
    @Override
    public String getAuthenticationString() {
        return this.password;
    }
    
    @Override
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

    private Certificate getExtraCert(final PKIMessage msg) {
        final CMPCertificate[] extraCerts = msg.getExtraCerts();
        if ((extraCerts == null) || (extraCerts.length == 0)) {
            if(log.isDebugEnabled()) {
                log.debug("There is no certificate in the extraCert field in the PKIMessage");
            }
            return null;
        } else {
            if(log.isDebugEnabled()) {
                log.debug("A certificate is found in the extraCert field in the CMP message");
            }
        }
        
        //Read the extraCert
        CMPCertificate cmpcert = extraCerts[0];
        Certificate excert = null;
        try {
            excert = CertTools.getCertfromByteArray(cmpcert.getEncoded(), Certificate.class);
            if(log.isDebugEnabled()) {
                log.debug("Obtaning the certificate from extraCert field was done successfully");
            }
        } catch (CertificateException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage(), e);
            }
        } catch (IOException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage(), e);
            }
        }
        return excert;
    }
    
    @Override
    /*
     * Verifies the signature of 'msg'. msg should be signed and the signer's certificate should be  
     * attached in msg in the extraCert field.  
     * 
     * When successful, the authentication string is set.
     */
    public boolean verifyOrExtract(final PKIMessage msg, final String username) {
        
        //Check that msg is signed
        if(msg.getProtection() == null) {
            this.errorMessage = "PKI Message is not authenticated properly. No PKI protection is found.";
            return false;
        }
        
        // Read the extraCert and store it in a local variable
        extraCert = getExtraCert(msg);
        if(extraCert == null) {
            this.errorMessage = "Error while reading the certificate in the extraCert field";
            return false;
        }
        
        boolean vendormode = impl.isVendorCertificateMode(msg.getBody().getType(), this.confAlias);
        boolean omitVerifications = cmpConfiguration.getOmitVerificationsInEEC(confAlias);
        boolean ramode = cmpConfiguration.getRAMode(confAlias);
        if(log.isDebugEnabled()) {
            log.debug("CMP is operating in RA mode: " + this.cmpConfiguration.getRAMode(this.confAlias));
            log.debug("CMP is operating in Vendor mode: " + vendormode);
            log.debug("CMP message already been authenticated: " + authenticated);
            log.debug("Omitting some verifications: " + omitVerifications);
            log.debug("CMP message signed by: SubjectDN '" + CertTools.getSubjectDN(extraCert)+"' IssuerDN '"+CertTools.getIssuerDN(extraCert) +"'");
        }    
        
        //----------------------------------------------------------------------------------------
        // Perform the different checks depending on the configuration and previous authentication
        //----------------------------------------------------------------------------------------

        // Not allowed combinations.
        if(ramode && vendormode) {
            this.errorMessage = "Vendor mode and RA mode cannot be combined";
            return false;
        }
        if(omitVerifications && (!ramode || !authenticated)) {
            this.errorMessage = "Omitting some verifications can only be accepted in RA mode and when the " +
                                 "CMP request has already been authenticated, for example, through the use of NestedMessageContent";
            return false;
        }
        
        // Accepted combinations
        if(omitVerifications && ramode && authenticated) {
            // Do nothing here
            if(log.isDebugEnabled()) {
                log.debug("Skipping some verification of the extraCert certificate in RA mode and an already authenticated CMP message, tex. through NestedMessageContent");
            }
        } else if(ramode) {
            
            // Get the CA to use for the authentication
            CAInfo cainfo = getCAInfoByName(authenticationparameter);
            if(cainfo == null)  return false;
            
            // Check that extraCert is in the Database
            CertificateInfo certinfo = certSession.getCertificateInfo(CertTools.getFingerprintAsString(extraCert));
            if(certinfo == null) {
                this.errorMessage = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
                return false;
            }
            
            // More extraCert verifications
            if(!isExtraCertIssuedByCA(cainfo) || !isExtraCertValid() || !isExtraCertActive(certinfo)) {
                return false;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Certificate in extraCerts field is issued by " + cainfo.getName() + ", is valid and active");
                }
            }

            // Check that extraCert belong to an admin with sufficient access rights
            if(!isAuthorizedAdmin(certinfo, msg)){
                this.errorMessage = "'" + CertTools.getSubjectDN(extraCert) + "' is not an authorized administrator.";
                return false;
            }

        } else if(!ramode) { // client mode
            
            String extraCertUsername = null;
            if(vendormode) {

                // Check that extraCert is issued  by a configured VendorCA
                if(!impl.isExtraCertIssuedByVendorCA(admin, this.confAlias, extraCert)) {
                    this.errorMessage = "The certificate in extraCert field is not issued by any of the configured Vendor CAs: " + cmpConfiguration.getVendorCA(confAlias);
                    return false;
                }
                
                // Extract the username from extraCert to use for  further authentication
                String subjectDN = CertTools.getSubjectDN(extraCert);
                extraCertUsername = CertTools.getPartFromDN(subjectDN, this.cmpConfiguration.getExtractUsernameComponent(this.confAlias));
                if(log.isDebugEnabled()) {
                    log.debug("Username ("+extraCertUsername+") was extracted from the '" + this.cmpConfiguration.getExtractUsernameComponent(this.confAlias) + "' part of the subjectDN of the certificate in the 'extraCerts' field.");
                }
                
            } else {
                
                // Get the CA to use for the authentication
                CAInfo cainfo = getCAInfoByIssuer(CertTools.getIssuerDN(extraCert));

                // Check that extraCert is in the Database
                CertificateInfo certinfo = certSession.getCertificateInfo(CertTools.getFingerprintAsString(extraCert));
                if(certinfo == null) {
                    this.errorMessage = "The certificate attached to the PKIMessage in the extraCert field could not be found in the database.";
                    return false;
                }
                
                // More extraCert verifications
                if(!isExtraCertIssuedByCA(cainfo) || !isExtraCertValid() || !isExtraCertActive(certinfo)) {
                    return false;
                }
                
                // Extract the username from extraCert to use for  further authentication
                extraCertUsername = certinfo.getUsername();
            }
            
            // Check if this certificate belongs to the user
            if ( (username != null) && (extraCertUsername != null) ) {
                if (!StringUtils.equals(username, extraCertUsername)) {
                    this.errorMessage = "The End Entity certificate attached to the PKIMessage in the extraCert field does not belong to user '"+username+"'";
                    if(log.isDebugEnabled()) {
                        // Use a different debug message, as not to reveal too much information
                        log.debug(this.errorMessage + ", but to user '"+extraCertUsername+"'");
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
                } catch (AuthorizationDeniedException | IllegalNameException | CADoesntExistsException | EndEntityProfileValidationException
                        | WaitingForApprovalException | CertificateSerialNumberException | ApprovalException | NoSuchEndEntityException e) {
                    if (log.isDebugEnabled()) {
                        log.debug(e.getLocalizedMessage());
                    }
                    this.errorMessage = e.getLocalizedMessage();
                    return false;
                }
            }
        }
        
        //-------------------------------------------------------------
        //Begin the signature verification process.
        //Verify the signature of msg using the public key of extraCert
        //-------------------------------------------------------------
        try {
            final Signature sig = Signature.getInstance(msg.getHeader().getProtectionAlg().getAlgorithm().getId(), BouncyCastleProvider.PROVIDER_NAME);
            sig.initVerify(extraCert.getPublicKey());
            sig.update(CmpMessageHelper.getProtectedBytes(msg));
            if (sig.verify(msg.getProtection().getBytes())) {
                if (password == null) {
                    // If not set earlier
                    password = genRandomPwd();
                }
            } else {
                this.errorMessage = "Failed to verify the signature in the PKIMessage";
                return false;
            }
        } catch (InvalidKeyException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            this.errorMessage = e.getLocalizedMessage();
            return false;
        } catch (NoSuchAlgorithmException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            this.errorMessage = e.getLocalizedMessage();
            return false;
        } catch (NoSuchProviderException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            this.errorMessage = e.getLocalizedMessage();
            return false;
        } catch (SignatureException e) {
            if(log.isDebugEnabled()) {
                log.debug(e.getLocalizedMessage());
            }
            this.errorMessage = e.getLocalizedMessage();
            return false;
        }
        
        return this.password != null;
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
     * @param certInfo
     * @param msg
     * @param caid
     * @return true if the administrator is authorized to process the request and false otherwise.
     */
    private boolean isAuthorizedAdmin(final CertificateInfo certInfo, final PKIMessage msg) {
    
        X509Certificate x509cert = (X509Certificate) extraCert;
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(x509cert);
        
        AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
        AuthenticationToken reqAuthToken = authenticationProviderSession.authenticate(subject);
        
        final int tagnr = msg.getBody().getType();
        if( (tagnr == CmpPKIBodyConstants.CERTIFICATAIONREQUEST) || (tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST) || (tagnr == CmpPKIBodyConstants.KEYUPDATEREQUEST) ) {
        
            
            final int caid = getRaCaId((DEROctetString) msg.getHeader().getSenderKID());
            if(!authSession.isAuthorizedNoLogging(reqAuthToken, StandardRules.CAACCESS.resource() + caid)) {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " not authorized to resource " + StandardRules.CAACCESS.resource() + caid);
                }
                return false;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " is authorized to access CA with ID " + caid);
                }
            }
            
            final int eeprofid;
            final String eepname;
            try {
                final String configuredId = this.cmpConfiguration.getRAEEProfile(this.confAlias);
                eeprofid = Integer.parseInt(configuredId);
                eepname = eeProfileSession.getEndEntityProfileName(eeprofid);
                if(eepname == null) {
                    log.error("End Entity Profile with ID " + configuredId + " was not found");
                    return false;
                }
            } catch(NumberFormatException e) {
                log.error("Configures End Entity Profile ID in CMP alias " + this.confAlias + " was not an Integer");
                return false;
            }
            
            
            if (!authorizedToEndEntityProfile(reqAuthToken, eeprofid, AccessRulesConstants.CREATE_END_ENTITY)) {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " was not authorized to create end entities with EndEntityProfile " + eepname);
                }
                return false;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " was authorized to create end entities with EndEntityProfile " + eepname);
                }
            }
            
            if(!authorizedToEndEntityProfile(reqAuthToken, eeprofid, AccessRulesConstants.EDIT_END_ENTITY)) {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " was not authorized to edit end entities with EndEntityProfile " + eepname);
                }
                return false;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " was authorized to edit end entities with EndEntityProfile " + eepname);
                }
            }
            
            if(!authSession.isAuthorizedNoLogging(reqAuthToken, AccessRulesConstants.REGULAR_CREATECERTIFICATE)) {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " is not authorized to create certificates.");
                }
                return false;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " was authorized to create certificates");
                }
            }
        } else if(tagnr == CmpPKIBodyConstants.REVOCATIONREQUEST) {
            final String issuerdn = getIssuerDNFromRevRequest((RevReqContent) msg.getBody().getContent());
            final int caid = CertTools.stringToBCDNString(issuerdn).hashCode();
            if(!authSession.isAuthorizedNoLogging(reqAuthToken, StandardRules.CAACCESS.resource() + caid)) {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " NOT authorized to revoke certificates issues by " + issuerdn);
                }
                return false;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " is authorized to revoke certificates issued by " + issuerdn);
                }
            }

            if(!authSession.isAuthorizedNoLogging(reqAuthToken, AccessRulesConstants.REGULAR_REVOKEENDENTITY)) {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " is not authorized to revoke End Entities");
                }
                return false;
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("Administrator " + reqAuthToken.toString() + " was authorized to revoke end entities");
                }
            }
            
        }
        return true;
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
        if (profileid == SecConst.EMPTY_ENDENTITYPROFILE
                && (rights.equals(AccessRulesConstants.CREATE_END_ENTITY) || rights.equals(AccessRulesConstants.EDIT_END_ENTITY))) {

            return authSession.isAuthorizedNoLogging(admin, StandardRules.ROLE_ROOT.resource());
        } else {
            return authSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights)
                    && authSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
        }
    }

    /**
     * Returns the IssuerDN specified in the CMP revocation request
     * @param revReq
     * @return the IssuerDN
     */
    private String getIssuerDNFromRevRequest(final RevReqContent revReq) {
        RevDetails rd;
        try {
            rd = revReq.toRevDetailsArray()[0];
        } catch(Exception e) {
            log.debug("Could not parse the revocation request. Trying to parse it as novosec generated message.");
            rd = CmpMessageHelper.getNovosecRevDetails(revReq);
            log.debug("Succeeded in parsing the novosec generated request.");
        }
        final CertTemplate ct = rd.getCertDetails();
        final X500Name issuer = ct.getIssuer();
        if(issuer != null) {
            return ct.getIssuer().toString();    
        }
        return "";
    }

    /**
     * Return the ID of the CA that is used for CMP purposes. 
     * @param keyId
     * @return the ID of CA used for CMP purposes. 
     * @throws EndEntityProfileNotFoundException 
     */
    private int getRaCaId(final DEROctetString keyId) {
        String caname = this.cmpConfiguration.getRACAName(this.confAlias);
        if (StringUtils.equals(caname, CmpConfiguration.PROFILE_USE_KEYID) && (keyId != null)) {
            caname = CmpMessageHelper.getStringFromOctets(keyId);
            if (log.isDebugEnabled()) {
                log.debug("Using CA with same name as KeyId in request: "+caname);
            }
        } 
        return getCAInfoByName(caname).getCAId();
    }
    
    private boolean isExtraCertValid() {
        X509Certificate cert = (X509Certificate) extraCert;
        try {
            cert.checkValidity();
            if(log.isDebugEnabled()) {
                log.debug("The certificate in extraCert is valid");
            }
        } catch (CertificateExpiredException e) {
            this.errorMessage = "The certificate attached to the PKIMessage in the extraCert field in not valid.";
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage + " SubjectDN=" + CertTools.getSubjectDN(cert) + " - " + e.getLocalizedMessage());
            }
            return false;
        } catch (CertificateNotYetValidException e) {
            this.errorMessage = "The certificate attached to the PKIMessage in the extraCert field in not valid.";
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage + " SubjectDN=" + CertTools.getSubjectDN(cert) + " - " + e.getLocalizedMessage());
            }
            return false;
        }
        return true;
    }

    private boolean isExtraCertActive(final CertificateInfo certinfo) {
        if (certinfo.getStatus() != CertificateConstants.CERT_ACTIVE) {
            this.errorMessage = "The certificate attached to the PKIMessage in the extraCert field is not active.";
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage + " Username="+certinfo.getUsername());
            }
            return false;
        }
        if(log.isDebugEnabled()) {
            log.debug("The certificate in extraCert is active");
        }
        return true;
    }
    
    private boolean isExtraCertIssuedByCA(CAInfo cainfo) {
        //Check that the extraCert is given by the right CA
        // Verify the signature of the client certificate as well, that it is really issued by this CA
        Certificate cacert = cainfo.getCertificateChain().iterator().next();
        try {
            extraCert.verify(cacert.getPublicKey(), "BC");
        } catch (Exception e) {
            if(log.isDebugEnabled()) {
                String errmsg = "The End Entity certificate attached to the PKIMessage is not issued by the CA '" + cainfo.getName() + "'";
                log.debug(errmsg + " - " + e.getLocalizedMessage());
            }
            this.errorMessage = "The End Entity certificate attached to the PKIMessage is issued by the wrong CA";
            return false;
        }
        return true;
    }
    
    private CAInfo getCAInfoByName(String caname) {
        try {
            return caSession.getCAInfo(admin, caname);
        } catch (CADoesntExistsException e) {
            this.errorMessage = "CA '" + caname + "' does not exist";
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage + " - " + e.getLocalizedMessage());
            }
        } catch (AuthorizationDeniedException e) {
            this.errorMessage = "Authorization denied for CA: " + caname;
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage + " - " + e.getLocalizedMessage());
            }
        }
        return null;
    }
    
    private CAInfo getCAInfoByIssuer(String issuerDN) {
        try {
            return caSession.getCAInfo(admin, issuerDN.hashCode());
        } catch (CADoesntExistsException e) {
            this.errorMessage = "CA '" + issuerDN + "' does not exist";
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage + " - " + e.getLocalizedMessage());
            }
        } catch (AuthorizationDeniedException e) {
            this.errorMessage = "Authorization denied for CA: " + issuerDN;
            if(log.isDebugEnabled()) {
                log.debug(this.errorMessage + " - " + e.getLocalizedMessage());
            }
        }
        return null;
    }
    
}