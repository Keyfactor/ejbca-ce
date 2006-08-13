package org.ejbca.ui.web.admin.approval;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ejb.EJBException;
import javax.faces.application.Application;
import javax.faces.context.FacesContext;
import javax.faces.el.ValueBinding;

import org.apache.log4j.Logger;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.DummyApprovalRequest;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;


/**
 * Class representing the view of one ApprovalDataVO data
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class ApprovalDataVOView  implements Serializable{
	
	private static final Logger log = Logger.getLogger(ApprovalDataVOView.class);
	
	private ApprovalDataVO data;
	
	private boolean initialized = false;
	
	public ApprovalDataVOView( ApprovalDataVO data){		
		this.data= data;
		initialized = true;
	}
	
	/**
	 * Constructor used for initialization of dummy values.
	 */
	public ApprovalDataVOView(){}{}
	
	public String getRequestDate(){		
	  DateFormat dateformat = DateFormat.getDateTimeInstance();	  
	  if(!initialized){
		return dateformat.format(new Date());
      }
	  
	  return dateformat.format(data.getRequestDate());
	}
	
	public String getExpireDate(){	  
	  DateFormat dateformat = DateFormat.getDateTimeInstance();	  
	  if(!initialized){
		 return dateformat.format(new Date());
	   }
	  
	   return dateformat.format(data.getExpireDate());
	}
	
	public String getCaName(){
	    if(!initialized){
		  return "TestCA";
	    }		
		
	    EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();	
	    if(data.getCAId() == ApprovalDataVO.ANY_CA){
	    	return helpBean.getEjbcaWebBean().getText("ANYCA");
	    }
	    
			
		return helpBean.getCAAdminSession().getCAInfo(helpBean.getAdmin(), data.getCAId()).getName();		
	}
	
	public String getEndEntityProfileName(){
	    if(!initialized){
		  return "TestProfile";
		}	
		EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();	
	    if(data.getEndEntityProfileiId() == ApprovalDataVO.ANY_ENDENTITYPROFILE){
	    	return helpBean.getEjbcaWebBean().getText("ANYENDENTITYPROFILE");
	    }
		return helpBean.getRaAdminSession().getEndEntityProfileName(helpBean.getAdmin(), data.getEndEntityProfileiId());		
	}
	
	public String getRemainingApprovals(){
	    if(!initialized){
			  return "1";
	    }
	    
	    return "" +data.getRemainingApprovals();
	}
	
	
	public String getApproveActionName(){
	    if(!initialized){
			  return "DummyAction";
	    }	
		return EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(ApprovalDataVO.APPROVALTYPENAMES[data.getApprovalRequest().getApprovalType()]);
	}
	
	public String getRequestAdminName(){
		String retval;
	    if(!initialized){
			  return "DummyAdmin";
	    }
	    
	    if(data.getApprovalRequest().getRequestAdmin().getAdminType() == Admin.TYPE_CLIENTCERT_USER){
		  String dn = data.getApprovalRequest().getRequestAdminCert().getSubjectDN().toString();
		  String o =  CertTools.getPartFromDN(dn, "O");
		  if(o==null){
			o="";
		  }else{
			o = ", " +  o;
		  }
		  
		  retval =  CertTools.getPartFromDN(dn, "CN") + o;
	    }else{
	    	retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("CLITOOL");
	    }
		
	   log.debug("getRequestAdminName " + retval);
	   return retval;
	}
	
	public String getStatus(){
	    if(!initialized){
			  return "EXPIRED";
	    }
	    
    	FacesContext context = FacesContext.getCurrentInstance();    
    	Application app = context.getApplication();    
    	ValueBinding binding = app.createValueBinding("#{approvalActionSession}");    
    	Object value = binding.getValue(context);    
    	ApproveActionSessionBean approvalActionSession = (ApproveActionSessionBean) value;

	    
	  return (String) approvalActionSession.getStatusText().get(new Integer(data.getStatus()));									
	}
	


	/**
	 * @return
	 */
	public ApprovalDataVO getApproveActionDataVO() {
	    if(!initialized){
			  try {
				return new ApprovalDataVO(1,1, ApprovalDataVO.APPROVALTYPE_DUMMY, 0,0,"","",ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,new ArrayList(),new DummyApprovalRequest(new Admin(CertTools.getCertfromByteArray(ApprovalDataVOView.dummycert)),null,ApprovalDataVO.ANY_ENDENTITYPROFILE,ApprovalDataVO.ANY_CA,false),new Date(),new Date(),2);
			} catch (CertificateException e) {
				log.error(e);
			}
	    }
		return data;
	}
	
	public int getApprovalId() {
	    if(!initialized){
			  return 1;
	    }
		return data.getApprovalId();
	}
	
	
	/**
	 * Constructs javazcript that opens up a new window and opens up actionview there
	 * @return
	 */
	public String getApproveActionWindowLink(){
        String link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl() + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath() + "approval/approveaction.jsf?uniqueId=" + data.getId();
		
		return "window.open('"+link+"', 'ViewApproveAction', 'width=1000,height=800,scrollbars=yes,toolbar=no,resizable=yes').focus()";
	}

	
	public boolean getShowViewRequestorCertLink(){
		return data.getApprovalRequest().getRequestAdmin().getAdminType() == Admin.TYPE_CLIENTCERT_USER;		
	}
	
	public String getViewRequestorCertLink(){
		String retval = "";
		if(data.getApprovalRequest().getRequestAdmin().getAdminType() == Admin.TYPE_CLIENTCERT_USER){
			String link;
			try {
				link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl() + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
				+ "viewcertificate.jsp?certsernoparameter=" + java.net.URLEncoder.encode(data.getReqadmincertsn() + "," + data.getReqadmincertissuerdn(),"UTF-8");
			} catch (UnsupportedEncodingException e) {
				throw new EJBException(e);
			}
			
			retval =  "viewcert('" + link + "')";
		}
		
		return retval;
	}

	public List getTextComparisonList(){
    	ArrayList textComparisonList = new ArrayList();
	    if(!initialized){
			  return textComparisonList;
	    }
    	
    	if(data.getApprovalRequest().getApprovalRequestType() == ApprovalRequest.REQUESTTYPE_COMPARING){
    	  List newTextRows = data.getApprovalRequest().getNewRequestDataAsText(EjbcaJSFHelper.getBean().getAdmin());
    	  List orgTextRows = data.getApprovalRequest().getOldRequestDataAsText(EjbcaJSFHelper.getBean().getAdmin());
    	  int size = newTextRows.size();
    	  if(orgTextRows.size() > size){
    	  	size = orgTextRows.size(); 
    	  }
    	  
    	  for(int i=0;i<size;i++){
    	  	String orgString ="";    	  
    	  	try{
    	  	  orgString = translateApprovalDataText((ApprovalDataText) orgTextRows.get(i));
    	  	}catch(ArrayIndexOutOfBoundsException e){
    	  	  // Do nothing orgstring should be "";	
    	  	}
    	  	String newString ="";    	  
    	  	try{
    	  	  newString = translateApprovalDataText((ApprovalDataText) newTextRows.get(i));
    	  	}catch(ArrayIndexOutOfBoundsException e){
    	  	  // Do nothing orgstring should be "";	
    	  	}
    	  	textComparisonList.add(new TextComparisonView(orgString, newString));
    	  }
    		    		
    	}else{
    		List newTextRows = data.getApprovalRequest().getNewRequestDataAsText(EjbcaJSFHelper.getBean().getAdmin());
    		int size = newTextRows.size();
    		for(int i=0;i<size;i++){
    		  textComparisonList.add(new TextComparisonView(null, translateApprovalDataText((ApprovalDataText) newTextRows.get(i)))); 	
    		}
    	}

    	
    	return textComparisonList;
    }
	
	private String translateApprovalDataText(ApprovalDataText data){
		String retval = "";
		if(data.isHeaderTranslateable()){
			retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(data.getHeader());
		}else{
			retval = data.getHeader();
		}
		
		if(data.isDataTranslatable()){
			retval += " : " + EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(data.getData());
		}else{
			retval += " : " +  data.getData();
		}
		
		return retval;
	}
    
    private static byte[] dummycert = Base64.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky"
            + "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
            + "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB"
            + "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
            + "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ"
            + "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
            + "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw"
            + "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
            + "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj"
            + "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
            + "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0"
            + "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
            + "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4"
            + "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
            + "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ"
            + "QUOBOvc=").getBytes());
    
}
