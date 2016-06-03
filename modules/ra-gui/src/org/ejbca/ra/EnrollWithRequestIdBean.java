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
package org.ejbca.ra;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.ExternalContext;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Managed bean that backs up the enrollwithrequestid.xhtml page
 * 
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class EnrollWithRequestIdBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(EnrollWithRequestIdBean.class);

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value = "#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    @ManagedProperty(value = "#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    private String requestId;
    public int requestStatus;
    EndEntityInformation endEntityInformation;
    
    @PostConstruct
    private void postConstruct(){
        reset();
    }
    
    public void reset(){
        requestStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
        endEntityInformation = null;
        
    }
    
    /**
     * Check the status of request ID
     */
    public void checkRequestId(){
        if(Integer.parseInt(requestId) != 0){
            RaApprovalRequestInfo raApprovalRequestInfo = raMasterApiProxyBean.getApprovalRequestByRequestHash(raAuthenticationBean.getAuthenticationToken(), Integer.parseInt(requestId));
            if(raApprovalRequestInfo == null){
                raLocaleBean.addMessageError("enrollwithrequestid_could_not_find_request_with_request_id", Integer.parseInt(requestId));
                return;
            }
            
            requestStatus = raApprovalRequestInfo.getStatus();
            switch(requestStatus){
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_is_still_waiting_for_approval", Integer.parseInt(requestId));
                return;
            case ApprovalDataVO.STATUS_REJECTED:
            case ApprovalDataVO.STATUS_EXECUTIONDENIED:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_rejected", Integer.parseInt(requestId));
                return;
            case ApprovalDataVO.STATUS_APPROVED:
            case ApprovalDataVO.STATUS_EXECUTED:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_approved", Integer.parseInt(requestId));
                break;
            default:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_is_still_waiting_for_approval", Integer.parseInt(requestId));
                return;
            }
            
            //Get username and set the password to be the same as username
            String username = raApprovalRequestInfo.getEditableData().getUsername();
            endEntityInformation = raMasterApiProxyBean.searchUser(raAuthenticationBean.getAuthenticationToken(), username);   
            if(endEntityInformation == null){
                log.error("Could not find endEntity for the username='" + username + "'" );
                return;
            }
            endEntityInformation.setPassword(username);
            
            //TODO fix hardcoded algorithm
            endEntityInformation.setKeyStoreAlgorithm("RSA");
            endEntityInformation.setKeyStoreAlgorithmLength("4096");
        }
    }
    
    public boolean isRequestApproved(){
        return requestStatus == ApprovalDataVO.STATUS_APPROVED || requestStatus == ApprovalDataVO.STATUS_EXECUTED;
    }
    
    public void finalizeEnrollment(){
        //Generate token
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        KeyStore keystore = null;
        try {
            keystore = raMasterApiProxyBean.generateKeystore(raAuthenticationBean.getAuthenticationToken(), endEntityInformation);
            log.info(raLocaleBean.getMessage("enroll_token_has_been_successfully_generated", "P12", endEntityInformation.getUsername()));

            keystore.store(buffer, endEntityInformation.getPassword().toCharArray());
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException | AuthorizationDeniedException e) {
            raLocaleBean.addMessageError("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage());
            log.error(raLocaleBean.getMessage("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage()), e);
            return;
        } finally {
            if (buffer != null) {
                try {
                    buffer.close();
                } catch (IOException e) {
                }
            }
        }
        
        //Download the token
        switch (endEntityInformation.getTokenType()) {
        case EndEntityConstants.TOKEN_SOFT_P12:
            downloadToken(buffer.toByteArray(), "application/x-pkcs12", ".p12");
            break;
        case EndEntityConstants.TOKEN_SOFT_JKS:
            downloadToken(buffer.toByteArray(), "application/octet-stream", ".jks");
            break;
        default:
            break;
        }
        
        reset(); //After the download let's get on the previous screen
    }
    
    private final void downloadToken(byte[] token, String responseContentType, String fileExtension) {
        if (token == null) {
            return;
        }

        //Download the token
        FacesContext fc = FacesContext.getCurrentInstance();
        ExternalContext ec = fc.getExternalContext();
        ec.responseReset(); // Some JSF component library or some Filter might have set some headers in the buffer beforehand. We want to get rid of them, else it may collide.
        ec.setResponseContentType(responseContentType);
        ec.setResponseContentLength(token.length);
        ec.setResponseHeader("Content-Disposition",
                "attachment; filename=\"" + StringTools.stripFilename(endEntityInformation.getUsername() + fileExtension) + "\""); // The Save As popup magic is done here. You can give it any file name you want, this only won't work in MSIE, it will use current request URL as file name instead.
        OutputStream output = null;
        try {
            output = ec.getResponseOutputStream();
            output.write(token);
            output.flush();
        } catch (IOException e) {
            log.error(raLocaleBean.getMessage("enroll_keystore_could_not_be_generated", endEntityInformation.getUsername(), e.getMessage()), e);
        } finally {
            if (output != null) {
                try {
                    output.close();
                } catch (IOException e) {
                }
            }
            fc.responseComplete(); // Important! Otherwise JSF will attempt to render the response which obviously will fail since it's already written with a file and closed.
        }
    }
    
    //-----------------------------------------------------------------
    //Getters/setters
    public EndEntityInformation getEndEntityInformation() {
        return endEntityInformation;
    }

    public void setEndEntityInformation(EndEntityInformation endEntityInformation) {
        this.endEntityInformation = endEntityInformation;
    }
    /**
     * @return the requestId
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * @param requestId the requestId to set
     */
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }

    public int getRequestStatus() {
        return requestStatus;
    }

    public void setRequestStatus(int requestStatus) {
        this.requestStatus = requestStatus;
    }


    
    
}
