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

package org.ejbca.core.ejb.approval;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseEntityBean;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataUtil;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * Entity bean should not be used directly, use though Session beans.
 *
 * Entity Bean representing approval data used to control request and their approvals.
 * Information stored:
 * <pre>
 *  id (Primary key),    unique row id
 *  approvalid           Constructed from action data as actiontype, admin, username etc. It should
 *                       result in the same approvalid if the admin tries to request the same action twice.                   
 *  approvaltype         type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
 *                       constants ex: ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA
 *  endentityprofileid   For RA specific approval requests should the related end entity profile id be specified
 *                       for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
 *  caid                 For CA specific approval requests should the related ca id be specified
 *                       for non ca request should this field be set to ApprovalDataVO.ANY_CA            
 *  reqadmincertissuerdn The issuerdn of the administrator certificate that generated the request.
 *  reqadmincertsn       The serialnumber of the administrator certificate that generated the request. String in Hex                               
 *  status               Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, STATUS_REJECTED, STATUS_EXPIRED, STATUS_EXPIREDANDNOTIFIED, STATUS_EXECUTED                    
 *  approvaldata         Stringrepresentation of data of approvals made by one or more administrators                   
 *  requestdata          Data containing information about the request displayed for the approval administrator.
 *  requestdate          Date the request for approval were added
 *  expiredate           Date the request for action or the approvel action will expire, Long.MAX_VALUE 
 *                       means that the request/approval never expires
 *  remainingapprovals   Indicates the number of approvals that remains in order to execute the action                     
 * </pre>
 *
 * @ejb.bean
 *   description="This enterprise bean entity represents an approval request or approved request"
 *   display-name="ApprovalDataEB"
 *   name="ApprovalData"
 *   jndi-name="ApprovalData"
 *   local-jndi-name="ApprovalDataLocal"
 *   view-type="local"
 *   type="CMP"
 *   reentrant="False"
 *   cmp-version="2.x"
 *   transaction-type="Container"
 *   schema="ApprovalDataBean"
 *   primkey-field="id"
 *
 * @ejb.pk generate="false"
 *   class="java.lang.Integer"
 *   
 * @ejb.persistence table-name = "ApprovalData"
 *
 * @ejb.home
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.approval.ApprovalDataLocalHome"
 *
 * @ejb.interface
 *   generate="local"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.approval.ApprovalDataLocal"
 *
 * @ejb.finder
 *   description="findByApprovalId"
 *   signature="Collection findByApprovalId(int approvalid)"
 *   query="SELECT OBJECT(a) from ApprovalDataBean a WHERE a.approvalid=?1"
 *   
 * @ejb.finder
 *   description="findByApprovalIdNonExpired"
 *   signature="Collection findByApprovalIdNonExpired(int approvalid)"
 *   query="SELECT OBJECT(a) from ApprovalDataBean a WHERE a.approvalid=?1 and (a.status=-1 or a.status=0 or a.status=-3)"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="Collection findAll()"
 *   query="SELECT OBJECT(a) from ApprovalDataBean a"
 *
 * @ejb.transaction type="Supports"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *   
 * @author Philip Vendil
 * @version $Id: ApprovalDataBean.java,v 1.4 2006-08-11 02:57:50 herrvendil Exp $   
 */
public abstract class ApprovalDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(ApprovalDataBean.class);
    

    /**
     * unique row id
     * 
     * @ejb.pk-field
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract Integer getId();

    /**
     * unique row id
     * 
     * @ejb.persistence
     */
    public abstract void setId(Integer id);
    
    /**
     * Constructed from action data as actiontype, admin, username etc. It should
     * result in the same approvalid if the admin tries to request the same action twice.
     * 
     * @ejb.pk-field
     * @ejb.persistence
     */
    public abstract int getApprovalid();

    /**
     * Constructed from action data as actiontype, admin, username etc. It should
     * result in the same approvalid if the admin tries to request the same action twice.
     * 
     * @ejb.persistence
     */
    public abstract void setApprovalid(int approvalid);

    
    /**   
     * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
     * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
     *     
     * @ejb.persistence
     */
    public abstract int getApprovaltype();

    /**
     * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
     * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
     *     
     * @ejb.persistence
     */
    public abstract void setApprovaltype(int approvaltype);

    
    /**
     * For RA specific approval requests should the related end entity profile id be specified
     * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
     *     
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract int getEndentityprofileid();

    
    /**
     * For RA specific approval requests should the related end entity profile id be specified
     * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
     *     
     * @ejb.persistence
     */
    public abstract void setEndentityprofileid(int endentityprofileid);
    
    /**
     * For CA specific approval requests should the related ca id be specified
     * for non ca request should this field be set to ApprovalDataVO.ANY_CA
     *      
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract int getCaid();

    
    /**
     * For CA specific approval requests should the related ca id be specified
     * for non ca request should this field be set to ApprovalDataVO.ANY_CA    
     *     
     * @ejb.persistence
     */
    public abstract void setCaid(int caid);
    
    /**
     * The issuerdn of the administrator certificate that generated the request.
     * 
     * @ejb.persistence
     */
    public abstract String getReqadmincertissuerdn();

    /**
     * The issuerdn of the administrator certificate that generated the request.
     * 
     * @ejb.persistence
     */
    public abstract void setReqadmincertissuerdn(String reqadmincertissuerdn);
    
    /**
     * The serialnumber of the administrator certificate that generated the request. String in Hex.
     * 
     * @ejb.persistence
     */
    public abstract String getReqadmincertsn();

    /**
     * The serialnumber of the administrator certificate that generated the request. String in Hex.
     * 
     * @ejb.persistence
     */
    public abstract void setReqadmincertsn(String reqadmincertsn);
    
    /**
     * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, 
     * STATUS_REJECTED, STATUS_EXPIRED
     * 
     * @ejb.persistence
     * @ejb.interface-method view-type="local"
     */
    public abstract int getStatus();

    /**
     * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, 
     * STATUS_REJECTED, STATUS_EXPIRED
     * 
     * @ejb.persistence
     */
    public abstract void setStatus(int status);

    /**
     * Stringrepresentation of data of approvals made by one or more administrators
     * 
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getApprovaldata();

    /**
     * Stringrepresentation of data of approvals made by one or more administrators
     * @ejb.persistence
     */
    public abstract void setApprovaldata(String approvaldata);

    /**
     * Data containing information about the request displayed for the approval administrator.
     * 
     * @ejb.persistence jdbc-type="LONGVARCHAR"
     */
    public abstract String getRequestdata();

    /**
     * Data containing information about the request displayed for the approval administrator.
     * @ejb.persistence
     */
    public abstract void setRequestdata(String requestdata);            
    
    /**
     * Date the request for approval were added
     *
     * @ejb.persistence
     */
    public abstract long getRequestdate();

    /**
     * Date the request for approval were added
     *
     * @ejb.persistence
     */
    public abstract void setRequestdate(long requestdate);
    
    /**
     * Date the request for action or the approvel action will expire, Long.MAX_VALUE 
     * means that the request/approval never expires
     *
     * @ejb.persistence
     */
    public abstract long getExpiredate();

    /**
     * Date the request for action or the approvel action will expire, Long.MAX_VALUE 
     * means that the request/approval never expires
     *
     * @ejb.persistence
     */
    public abstract void setExpiredate(long expiredate);
      
    /**
     * Indicates the number of approvals that remains in order to execute the action
     *      
     * @ejb.persistence
     */
    public abstract int getRemainingapprovals();

    
    /**
     * Indicates the number of approvals that remains in order to execute the action  
     *     
     * @ejb.persistence
     */
    public abstract void setRemainingapprovals(int remainingapprovals);
    
    
    
    private Collection getApprovals() {   
    	return ApprovalDataUtil.getApprovals(getApprovaldata());
    }
    
    /**
     * Collection of Approval
     * @param approvals cannot be null.
     * @throws IOException
     */
    private void setApprovals(Collection approvals){
    	try{
    		ByteArrayOutputStream baos = new ByteArrayOutputStream();
    		ObjectOutputStream oos = new ObjectOutputStream(baos);
    		
    		int size = approvals.size();
    		oos.writeInt(size);
    		Iterator iter = approvals.iterator();
    		while(iter.hasNext()){
    			Approval next = (Approval) iter.next();
    			oos.writeObject(next);
    		}
    		oos.flush();
    		
    		setApprovaldata(new String(Base64.encode(baos.toByteArray(),false)));
    	} catch (IOException e) {
    		log.error("Error building approvals.",e);
    		throw new EJBException(e);
    	}
    }
    
    private ApprovalRequest getApprovalRequest() {
    	return ApprovalDataUtil.getApprovalRequest(getRequestdata());
    }
    
    private void setApprovalRequest(ApprovalRequest approvalRequest){
    	try{
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream(baos);
    	oos.writeObject(approvalRequest);
    	oos.flush();
    	setRequestdata(new String(Base64.encode(baos.toByteArray(),false)));
    	}catch(IOException e){
			log.error("Error building approval request.",e);
			throw new EJBException(e);   		
    	}
    }
    
    private Date getRequestDate(){    
    	return new Date(getRequestdate());
    }
    
    private void setRequestDate(Date requestDate){
    	setRequestdate(requestDate.getTime());
    }
    
    private Date getExpireDate(){    
    	return new Date(getExpiredate());
    }

    /**
     * Method used to set the expire date of the request
     *
     */
    public void setExpireDate(Date expireDate){
    	setExpiredate(expireDate.getTime());
    }
     
    /**
     * Method that checks if the request or approval have expired
     * The status is set to expired of it as
     * @return true of the request or approval have expired
     */
    private boolean haveRequestOrApprovalExpired(){
    	Date currentDate = new Date();
    	boolean retval = false;
    	if(currentDate.after(getExpireDate())){
    		if(getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL ||
    		   getStatus() == ApprovalDataVO.STATUS_APPROVED ||
    		   getStatus() == ApprovalDataVO.STATUS_REJECTED){
    		  setStatus(ApprovalDataVO.STATUS_EXPIRED);
    		}
    		retval=true;
    	}
    	
    	return retval;
    	
    }
    
    /**
     * Method that returns the approval data.
     *
     * @ejb.interface-method view-type="local"
     */
    public ApprovalDataVO getApprovalDataVO() {
    	haveRequestOrApprovalExpired();

        return new ApprovalDataVO(getId().intValue(),getApprovalid(),getApprovaltype(),
        		                  getEndentityprofileid(),getCaid(),getReqadmincertissuerdn(),
        		                  getReqadmincertsn(), getStatus(),getApprovals(), getApprovalRequest(),
        		                  getRequestDate(),getExpireDate(),getRemainingapprovals());
        		                                           
    }
    
    /**
     * Method adds an approval to the approval data.
     * If the number of required approvals have been reached will
     * the request be executed and expiredate set.
     * @throws ApprovalRequestExpiredException 
     * @throws ApprovalRequestExecutionException 
     * @throws ApprovalException 
     *
     * @ejb.interface-method view-type="local"
     */
    public void approve(Approval approval) throws ApprovalRequestExpiredException, ApprovalRequestExecutionException, ApprovalException {
    	if(haveRequestOrApprovalExpired()){
    		throw new ApprovalRequestExpiredException();
    	}
    	
    	if(getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
    		throw new ApprovalException("Wrong status of approval request.");
    	}
    	
    	int numberofapprovalsleft = getRemainingapprovals() -1;
    	if(numberofapprovalsleft < 0){
    		throw new ApprovalException("Error already enough approvals have been done on this request.");
    	}
    		
    	setRemainingapprovals(numberofapprovalsleft);
    	Collection approvals = getApprovals();
    	approvals.add(approval);
    	setApprovals(approvals);
    	
    	if(numberofapprovalsleft == 0){
    		ApprovalRequest approvalRequest = getApprovalRequest();
    		if(approvalRequest.isExecutable()){
    			try{
    			  approvalRequest.execute();
    			  setStatus(ApprovalDataVO.STATUS_EXECUTED);
    			} catch(ApprovalRequestExecutionException e){
    			  setStatus(ApprovalDataVO.STATUS_EXECUTIONFAILED);
    			  throw e;
    			}
    			setStatus(ApprovalDataVO.STATUS_EXECUTED);
    			setExpireDate(new Date());
    		}else{
    			setStatus(ApprovalDataVO.STATUS_APPROVED);
    			setExpiredate((new Date()).getTime() + approvalRequest.getApprovalValidity());
    		}
    	}
        		                                           
    }

    /**
     * Method that rejects an apporval.
     * After someone have rejected the request noone else can approve it
     *
     * @throws ApprovalRequestExpiredException 
     * @throws ApprovalRequestExecutionException 
     * @throws ApprovalException 
     *
     * @ejb.interface-method view-type="local"
     */
    public void reject(Approval approval) throws ApprovalRequestExpiredException,  ApprovalException {
    	if(haveRequestOrApprovalExpired()){
    		throw new ApprovalRequestExpiredException();
    	}
    	
    	if(getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
    		throw new ApprovalException("Wrong status of approval request.");
    	}
    	
    	int numberofapprovalsleft = getRemainingapprovals() -1;
    	if(numberofapprovalsleft < 0){
    		throw new ApprovalException("Error already enough approvals have been done on this request.");
    	}
    		
    	setRemainingapprovals(0);
    	Collection approvals = getApprovals();
    	approvals.add(approval);
    	setApprovals(approvals);
    	
    	if(getApprovalRequest().isExecutable()){
			setStatus(ApprovalDataVO.STATUS_EXECUTIONDENIED);
			setExpireDate(new Date());    		    		
    	}else{
        	setStatus(ApprovalDataVO.STATUS_REJECTED);
        	setExpiredate((new Date()).getTime() + getApprovalRequest().getApprovalValidity());   		
    	}

    	        		                                           
    } 
    
    /**
     * Method used by the requestadmin to check if an approval request have been approved
     *
     * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the statys.
     * @throws ApprovalRequestExpiredException if the request or approval have expired, the status will be EXPIREDANDNOTIFIED in this case. 
     *
     * @ejb.interface-method view-type="local"
     */
    public int isApproved() throws ApprovalRequestExpiredException {    	
    	if(haveRequestOrApprovalExpired()){
    		if(getStatus() != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED &&
    		   getStatus() != ApprovalDataVO.STATUS_EXECUTED &&
    		   getStatus() != ApprovalDataVO.STATUS_EXECUTIONDENIED &&
    		   getStatus() != ApprovalDataVO.STATUS_EXECUTIONFAILED){
    			setStatus(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED);
    			throw new ApprovalRequestExpiredException();
    		}
    		return ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
    		
    	}
    	
    	if(getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
    		return getRemainingapprovals();
    	}
    	
    	return getStatus();
    	        		                                           
    } 


    //
    // Fields required by Container
    //
    /**
     * Passivates bean
     */
    public void ejbPassivate() {
    }


    /**
     * Entity Bean holding data of a approval data
     *
     * @return id
     * @ejb.create-method view-type="local"
     */
    
    
    public Integer ejbCreate(Integer id, ApprovalRequest approvalRequest) throws CreateException {
        setId(id);
        setApprovalid(approvalRequest.generateApprovalId());
        setApprovaltype(approvalRequest.getApprovalType());
        setEndentityprofileid(approvalRequest.getEndEntityProfileId());        
        setCaid(approvalRequest.getCAId());
        
        if(approvalRequest.getRequestAdminCert() != null){
          setReqadmincertissuerdn(CertTools.getIssuerDN(approvalRequest.getRequestAdminCert()));
          setReqadmincertsn(approvalRequest.getRequestAdminCert().getSerialNumber().toString(16));
        }
        setStatus(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);        
        setApprovals(new ArrayList());
        setApprovalRequest(approvalRequest);                
        setRequestDate(new Date());
        setExpiredate((new Date()).getTime() + approvalRequest.getRequestValidity());
        setRemainingapprovals(approvalRequest.getNumOfRequiredApprovals());


        log.debug("Created approval with id " + id);
        return id;
    }

    public void ejbPostCreate(Integer id, ApprovalRequest approvalRequest) {
        // Do nothing. Required.
    }
}
