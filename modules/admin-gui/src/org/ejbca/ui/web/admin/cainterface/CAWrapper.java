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
package org.ejbca.ui.web.admin.cainterface;

import java.io.Serializable;

import org.apache.log4j.Logger;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.catoken.ICAToken;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/** Web bean for displaying CA status in a dataTable
 * 
 * @author Tham Wickenberg
 * @version $Id$
 */ 
public class CAWrapper implements Serializable {
	
	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(CAActivationMBean.class);

	private CAInfo cainfo;
	private EjbcaWebBean webBean;
	private CAActivationMBean mbean;
	private boolean can_activate;
	private int caStatus;
	private int tokenStatus;
	private String activationmessage = "";
	private String activateoption = "";
	private boolean monitored = true;

	public CAWrapper (CAInfo cainfo, EjbcaWebBean webbean, CAActivationMBean mbean) {
		this.cainfo = cainfo;
		this.webBean = webbean;
		this.mbean = mbean;

		try {
			can_activate = webBean.isAuthorizedNoLog(AccessRulesConstants.REGULAR_ACTIVATECA);
		} catch (AuthorizationDeniedException ade) {}

	}
	
	public String getStatus() {
		caStatus = cainfo.getStatus();
		String status = webBean.getText("ACTIVE");
		if(caStatus == SecConst.CA_EXPIRED) {
			status = webBean.getText("EXPIRED");
		} else if(caStatus == SecConst.CA_REVOKED) {
			status = webBean.getText("REVOKED");
		} else if (caStatus != SecConst.CA_ACTIVE) {
			status = webBean.getText("OFFLINE");
		} 
		return status;	
	}
	public String getStatusImg() {
		caStatus = cainfo.getStatus();
		if(caStatus == SecConst.CA_ACTIVE) {
			return webBean.getImagefileInfix("status-ca-active.png");
		}		
		return webBean.getImagefileInfix("status-ca-offline.png");
	}

	public String getName() {
		return cainfo.getName();
	}
	
	public String getActivateOption() {
		return activateoption;
	}
	public String getDefaultActivateOption() {
		getStatus();
		getTokenStatus();
		activateoption = CAActivationMBean.KEEPCURRENT;
		if ((caStatus == SecConst.CA_EXPIRED) || (caStatus == SecConst.CA_REVOKED)) {
			//If CA status is expired of revoked, status should be to not change anything
			activateoption = CAActivationMBean.KEEPCURRENT;
		} else if ((tokenStatus != ICAToken.STATUS_OFFLINE) && (caStatus != SecConst.CA_ACTIVE)) {
			//If CA status is off line and Token is online default should be 'Make off line'
			activateoption = CAActivationMBean.MAKEOFFLINE;
		} else if ((tokenStatus == ICAToken.STATUS_OFFLINE) && (caStatus == SecConst.CA_ACTIVE)) {
			//If CA status is active and Token is off line default should be 'Activate'
			activateoption = CAActivationMBean.ACTIVATE;
		}
		return activateoption;
	}
	
	protected void activateCAToken() {
		if (can_activate) {
			try {
				this.cainfo=mbean.activateCAToken(cainfo.getCAId());
				setCAActivationMessage(webBean.getText("CAACTIVATIONSUCCESSFUL"));
			} catch (CATokenAuthenticationFailedException catafe) {
				setCAActivationMessage(webBean.getText("AUTHENTICATIONERROR"));
			} catch (CATokenOfflineException catoe) {
				log.error(catoe);
				String msg = catoe.getMessage();
				setCAActivationMessage(webBean.getText("ERROR")+": "+msg==null?"":msg);
			} catch (ApprovalException e) {
				setCAActivationMessage(webBean.getText("CAACTIVATIONREQEXISTS"));
			} catch (WaitingForApprovalException e){
				setCAActivationMessage(webBean.getText("CAACTIVATIONSENTAPPROVAL"));
			} catch (AuthorizationDeniedException e) {
				setCAActivationMessage("Authorization denied: "+e.getMessage()); //TODO what message should this be?
			} catch (Exception e) {
				log.error("Error activating CA token: ", e);
				String msg = e.getMessage();
				setCAActivationMessage(webBean.getText("ERROR")+": "+msg==null?"":msg);
			}
		}
	}
	
	protected void updateMonitored() {
		if (can_activate) {
			try {
				this.cainfo=mbean.updateMonitored(cainfo.getCAId(), getMonitored());
				setCAActivationMessage(webBean.getText("UPDATEDMONITORED"));
			} catch (Exception e) {
				log.error("Error updating monitored: ", e);
				String msg = e.getMessage();
				setCAActivationMessage(webBean.getText("ERROR")+": "+msg==null?"":msg);
			}
		}
	}
	
	protected int getID() {
		return cainfo.getCAId();
	}
	
	protected void setCAInfo(CAInfo cainfo) {
		this.cainfo=cainfo;
		this.activateoption = getDefaultActivateOption();
		this.monitored = cainfo.getIncludeInHealthCheck();
	}
	
	protected void deactivateCAToken() {
		if (can_activate) {
			try{
				this.cainfo=mbean.deactivateCAToken(cainfo.getCAId());
				setCAActivationMessage(webBean.getText("MAKEOFFLINESUCCESSFUL"));
			} catch (AuthorizationDeniedException e) {
				setCAActivationMessage(webBean.getText("NOTAUTHORIZEDTOVIEWCA"));
			} catch (Exception e) {
				setCAActivationMessage(webBean.getText("ERROR"));
			}			
		}
	}
	
	public void setActivateOption(String option) {
		activateoption = option;
	}
	
	public String getTokenStatus()
	{
		tokenStatus = cainfo.getCATokenInfo().getCATokenStatus();
		if (tokenStatus == ICAToken.STATUS_OFFLINE) {
			return(webBean.getText("OFFLINE"));
		}
		return (webBean.getText("ACTIVE"));
	}
	public String getTokenStatusImg() {
		tokenStatus = cainfo.getCATokenInfo().getCATokenStatus();
		if (tokenStatus == ICAToken.STATUS_OFFLINE) {
			return webBean.getImagefileInfix("status-ca-offline.png");
		}		
		return webBean.getImagefileInfix("status-ca-active.png");
	}
	
	public boolean getMonitored() {
		return monitored;
	}
	
	public void setMonitored(boolean includeInHealthCheck) {
		this.monitored = includeInHealthCheck;
	}
	
	public String getCAActivationMessage() {
		return activationmessage;
	}
	public void setCAActivationMessage(String message) {
		activationmessage = message;
	}
}
