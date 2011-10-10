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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.protocol.cmp.CmpPKIBodyConstants;
import org.ejbca.core.protocol.cmp.CmpPbeVerifyer;

import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.crmf.CertTemplate;

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
 *
 */
public class HMACAuthenticationModule implements ICMPAuthenticationModule {


    private static final Logger LOG = Logger.getLogger(HMACAuthenticationModule.class);
    private static final InternalEjbcaResources INTRES = InternalEjbcaResources.getInstance();

    
    private AuthenticationToken admin;
    private EndEntityAccessSession eeAccessSession;
    
    private String raAuthSecret;
    private CAInfo cainfo;
    private String password;
    private String errorMessage;
    
    private CmpPbeVerifyer verifyer;
        
    public HMACAuthenticationModule(final String parameter) {
        this.raAuthSecret = parameter;
        if(StringUtils.equals(raAuthSecret, "-")) {
            this.raAuthSecret = CmpConfiguration.getRAAuthenticationSecret();
        }
        this.cainfo = null;
        this.password = null;
        this.errorMessage = null;
        
        this.admin = null;
        this.eeAccessSession = null;
        
        this.verifyer = null;
    }

    public void setCaInfo(final CAInfo cainfo) {
        this.cainfo = cainfo;
    }
    
    /**
     * Sets the sessions needed to perform the verification.
     * 
     * @param adm
     * @param userSession
     */
    public void setSession(final AuthenticationToken adm, final EndEntityAccessSession eeSession) {
        this.admin = adm;
        this.eeAccessSession = eeSession;
    }
    
    /**
     * Returns the name of this authentication module as String
     * 
     * @return the name of this authentication module as String
     */
    public String getName() {
        return CmpConfiguration.AUTHMODULE_HMAC;
    }
    
    @Override
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
    
    @Override
    /**
     * Get the error message resulted from the failure of the verification process.
     * 
     * The error message is set if verify() returns false.
     * 
     * @return The error message as String. Null if no error had occurred.
     */
    public String getErrorMessage(){
        return this.errorMessage;
    }
    
    public CmpPbeVerifyer getCmpPbeVerifyer() {
        return this.verifyer;
    }
    
    @Override
    /**
     * Verifies that 'msg' is sent by a trusted source. 
     * 
     * In RA mode:
     *      - A globally configured shared secret for all CAs will be used to authenticate the message.
     *      - If the globallt shared secret fails, the password set in the CA will be used to authenticate the message.
     *  In client mode, the clear-text password set in the pre-registered end entity in the database will be used to 
     *  authenticate the message. 
     * 
     * When successful, the password will be set to the password that was successfully used in authenticating the message.
     * When failed, the error message will be set.
     * 
     * @param msg
     * @return true if the message signature was verified successfully and false otherwise.
     */
    public boolean verifyOrExtract(final PKIMessage msg) {
        
        if(msg == null) {
            LOG.error("No PKIMessage was found");
            return false;
        }

        try {   
            verifyer = new CmpPbeVerifyer(msg);
        } catch(Exception e) {
            if(LOG.isDebugEnabled()) {
                LOG.debug("Could not create CmpPbeVerifyer");
                LOG.debug(e.getLocalizedMessage());
            }
            return false;
        }
        
        if(verifyer == null) {
            if(LOG.isDebugEnabled()) {
                LOG.debug("Could not create CmpPbeVerifyer Object");
            }
            return false;
        }
            
        if(CmpConfiguration.getRAOperationMode()) { //RA mode
        
            // If we use a globally configured shared secret for all CAs we check it right away
            if (this.raAuthSecret != null) {
                try {
                    if(!verifyer.verify(this.raAuthSecret)) {
                        errorMessage = INTRES.getLocalizedMessage("cmp.errorauthmessage", "Global auth secret");
                        LOG.info(errorMessage); // info because this is something we should expect and we handle it
                        if (verifyer.getErrMsg() != null) {
                            errorMessage = verifyer.getErrMsg();
                            LOG.info(errorMessage);
                        }   
                    } else {
                        this.password = this.raAuthSecret;
                    }
                } catch (InvalidKeyException e) {
                    errorMessage = e.getLocalizedMessage();
                    LOG.error(errorMessage, e);
                } catch (NoSuchAlgorithmException e) {
                    errorMessage = e.getLocalizedMessage();
                    LOG.error(errorMessage, e);
                } catch (NoSuchProviderException e) {
                    errorMessage = e.getLocalizedMessage();
                    LOG.error(errorMessage, e);
                }
            }

            // Now we know which CA the request is for, if we didn't use a global shared secret we can check it now!
            if (this.password == null) {
                //CAInfo caInfo = this.caAdminSession.getCAInfo(this.admin, caId);
                String cmpRaAuthSecret = null;  
                if (cainfo instanceof X509CAInfo) {
                    cmpRaAuthSecret = ((X509CAInfo) cainfo).getCmpRaAuthSecret();
                }       
                if (StringUtils.isNotEmpty(cmpRaAuthSecret)) {
                    try {
                        if(!verifyer.verify(cmpRaAuthSecret)) {
                            errorMessage = INTRES.getLocalizedMessage("cmp.errorauthmessage", "Auth secret for CAId="+cainfo.getCAId());
                            if (StringUtils.isEmpty(cmpRaAuthSecret)) {
                                errorMessage += " Secret is empty";
                            } else {
                                errorMessage += " Secret fails verify";
                            }
                            LOG.info(errorMessage); // info because this is something we should expect and we handle it
                            if (verifyer.getErrMsg() != null) {
                                errorMessage = verifyer.getErrMsg();
                            }
                        } else {
                            this.password = cmpRaAuthSecret;
                        }
                    } catch (InvalidKeyException e) {
                        errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
                        LOG.error(errorMessage, e);
                    } catch (NoSuchAlgorithmException e) {
                        errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
                        LOG.error(errorMessage, e);
                    } catch (NoSuchProviderException e) {
                        errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
                        LOG.error(errorMessage, e);
                    }
                }
            }
            
        } else { //client mode
            
            //If client mode, we try to get the pre-registered endentity from the DB, and if there is a 
            //clear text password we check HMAC using this password.
            final CertTemplate certTemp = getCertTemplate(msg);
            final String subjectDN = certTemp.getSubject().toString();
            final String issuerDN = certTemp.getIssuer().toString();
            if(LOG.isDebugEnabled()) {
                LOG.debug("Searching for an end entity with SubjectDN=\"" + subjectDN + "\" and issuerDN=\"" + issuerDN + "\"");
            }
            EndEntityInformation userdata = null;
            try {
                userdata = this.eeAccessSession.findUserBySubjectAndIssuerDN(this.admin, subjectDN, issuerDN);
            } catch (AuthorizationDeniedException e) {
                LOG.info("No EndEntity with subjectDN \"" + subjectDN + "\" and issuer \"" + issuerDN + "\" could be found, wich is expected if the request had been send in Client mode.");
            }
            if(userdata != null) {
                final String eepassword = userdata.getPassword();
                if(StringUtils.isNotEmpty(eepassword)) { 
                    final CmpPbeVerifyer cmpverify = new CmpPbeVerifyer(msg);
                    try {
                        if(cmpverify.verify(eepassword)) {
                            this.password = eepassword;
                        }
                    } catch (InvalidKeyException e) {
                        errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
                        LOG.error(errorMessage, e);
                    } catch (NoSuchAlgorithmException e) {
                        errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
                        LOG.error(errorMessage, e);
                    } catch (NoSuchProviderException e) {
                        errorMessage = INTRES.getLocalizedMessage("cmp.errorgeneral");
                        LOG.error(errorMessage, e);
                    }
                }
            } else {
                errorMessage = "End Entity with subjectDN \"" + subjectDN + "\" and issuerDN \"" + issuerDN + "\" was not found";
                LOG.error(errorMessage);
            }
        }
        return this.password != null;
    }

    
    /**
     * Returns the certificate template specified in the request impeded in msg.
     * 
     * @param msg
     * @return the certificate template imbeded in msg. Null if no such template was found.
     */
    private CertTemplate getCertTemplate(final PKIMessage msg) {
        final int tagnr = msg.getBody().getTagNo();
        if(tagnr == CmpPKIBodyConstants.INITIALIZATIONREQUEST) {
            return msg.getBody().getIr().getCertReqMsg(0).getCertReq().getCertTemplate();
        }
        if(tagnr==CmpPKIBodyConstants.CERTIFICATAIONREQUEST) {
            return msg.getBody().getCr().getCertReqMsg(0).getCertReq().getCertTemplate();
        }
        if(tagnr==CmpPKIBodyConstants.REVOCATIONREQUEST) {
            return msg.getBody().getRr().getRevDetails(0).getCertDetails();
        }
        return null;
    }
    
}
