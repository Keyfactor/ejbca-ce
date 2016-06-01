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

import java.io.Serializable;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.SessionScoped;

import org.apache.log4j.Logger;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.era.RaApprovalRequestInfo;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

/**
 * Managed bean that backs up the enrollwithrequestid.xhtml page
 * 
 * @version $Id$
 */
@ManagedBean
@SessionScoped
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
    
    @PostConstruct
    private void postConstruct(){
        requestStatus = ApprovalDataVO.STATUS_WAITINGFORAPPROVAL;
    }
    
    public void checkRequestId(){
        if(Integer.parseInt(requestId) != 0){
            RaApprovalRequestInfo raApprovalRequestInfo = raMasterApiProxyBean.getApprovalRequest(raAuthenticationBean.getAuthenticationToken(), Integer.parseInt(requestId));
            if(raApprovalRequestInfo == null){
                raLocaleBean.addMessageError("enrollwithrequestid_could_not_find_request_with_request_id", Integer.parseInt(requestId));
                return;
            }
            requestStatus = raApprovalRequestInfo.getStatus();
            switch(requestStatus){
            case ApprovalDataVO.STATUS_WAITINGFORAPPROVAL:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_is_still_waiting_for_approval", Integer.parseInt(requestId));
                break;
            case ApprovalDataVO.STATUS_REJECTED:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_rejected", Integer.parseInt(requestId));
                break;
            case ApprovalDataVO.STATUS_APPROVED:
                raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_approved", Integer.parseInt(requestId));
                break;
            }
        }
    }
    
    public boolean isRequestApproved(){
        return requestStatus == ApprovalDataVO.STATUS_APPROVED;
    }
    
    public void finalizeEnrollment(){
        raLocaleBean.addMessageInfo("enrollwithrequestid_request_with_request_id_has_been_successfully_enrolled", Integer.parseInt(requestId));
    }
    
    //-----------------------------------------------------------------
    //Getters/setters
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
