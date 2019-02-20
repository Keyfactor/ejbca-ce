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

package org.ejbca.ui.web.admin.approval;

import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;

import javax.ejb.EJBException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

/**
 * Class used to represent the view of an approval
 * 
 * @version $Id$
 */
public class ApprovalView {
	
	private final Approval approval;
	
	public ApprovalView(final Approval approval){
		this.approval=approval; 
	}

	public Approval getApproval() {
		return approval;
	}
	
	public String getApprovalDate(){
		return EjbcaJSFHelper.getBean().getEjbcaWebBean().formatAsISO8601(approval.getApprovalDate());
	}
	
	public String getApprovalAdmin(){
		//return approval.getAdmin().getUsername();
		return approval.getAdmin().toString();
	}
	
	public String getAdminAction(){
		final EjbcaWebBean ejbcawebbean = EjbcaJSFHelper.getBean().getEjbcaWebBean();
		
		if(approval.isApproved()){
			return ejbcawebbean.getText("APPROVED");
		}
		return ejbcawebbean.getText("REJECTED");
	}
	
	public String getViewApproverCertLink(){
		String link="";
		try {
			final AuthenticationToken token = approval.getAdmin();
			if (token instanceof X509CertificateAuthenticationToken) {
				final X509CertificateAuthenticationToken xtok = (X509CertificateAuthenticationToken) token;
				final X509Certificate adminCertificate = xtok.getCertificate();
				final String certificateSerialNumber = CertTools.getSerialNumberAsString(adminCertificate);
				final String adminIssuerDN = CertTools.getIssuerDN(adminCertificate);
				link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl() + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
				            + "viewcertificate.xhtml?certsernoparameter=" + java.net.URLEncoder.encode(certificateSerialNumber + "," + adminIssuerDN,"UTF-8");				
			}
			return "window.open('" + link + "', 'ViewApproverCertAction', 'width=800,height=800,scrollbars=yes,toolbar=no,resizable=yes').focus()";
		} catch (final UnsupportedEncodingException e) {
			throw new EJBException(e);
		}
		
	}
	
	public String getComment(){
		return approval.getComment();
	}
}
