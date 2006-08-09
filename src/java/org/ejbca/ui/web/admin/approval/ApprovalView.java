package org.ejbca.ui.web.admin.approval;

import java.io.UnsupportedEncodingException;
import java.text.DateFormat;

import javax.ejb.EJBException;

import org.ejbca.core.model.approval.Approval;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * Class used to represent the view of an approval
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class ApprovalView {
	
	private Approval approval;
	
	public ApprovalView(Approval approval){
		this.approval=approval; 
	}
	

	public Approval getApproval() {
		return approval;
	}
	
	public String getApprovalDate(){
		DateFormat dateformat = DateFormat.getDateTimeInstance();	
		return dateformat.format(approval.getApprovalDate());
	}
	
	public String getApprovalAdmin(){
		return approval.getUsername();
	}
	
	public String getAdminAction(){
		EjbcaWebBean ejbcawebbean = EjbcaJSFHelper.getBean().getEjbcaWebBean();
		
		if(approval.isApproved()){
			return ejbcawebbean.getText("APPROVED");
		}
		return ejbcawebbean.getText("REJECTED");
	}
	
	public String getViewApproverCertLink(){
		String link;
		try {
			link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl() + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
			            + "viewcertificate.jsp?certsernoparameter=" + java.net.URLEncoder.encode(approval.getAdminCertSerialNumber().toString(16) + "," + approval.getAdminCertIssuerDN(),"UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new EJBException(e);
		}
		
		return "viewcert('" + link + "')";
	}
	
	public String getComment(){
		return approval.getComment();
	}
}
