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
import org.ejbca.core.ErrorCode;
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
 *  approvalId           Constructed from action data as actiontype, admin, username etc. It should
 *                       result in the same approvalid if the admin tries to request the same action twice.                   
 *  approvalType         type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
 *                       constants ex: ApprovalDataVO.APPROVALTYPE_VIEWHARDTOKENDATA
 *  endEntityProfileId   For RA specific approval requests should the related end entity profile id be specified
 *                       for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
 *  caId                 For CA specific approval requests should the related ca id be specified
 *                       for non ca request should this field be set to ApprovalDataVO.ANY_CA            
 *  reqAdminCertIssuerDn The issuerdn of the administrator certificate that generated the request.
 *  reqAdminCertSn       The serialnumber of the administrator certificate that generated the request. String in Hex                               
 *  status               Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, STATUS_REJECTED, STATUS_EXPIRED, STATUS_EXPIREDANDNOTIFIED, STATUS_EXECUTED                    
 *  approvalData         Stringrepresentation of data of approvals made by one or more administrators                   
 *  requestData          Data containing information about the request displayed for the approval administrator.
 *  requestDate          Date the request for approval were added
 *  expireDate           Date the request for action or the approvel action will expire, Long.MAX_VALUE 
 *                       means that the request/approval never expires
 *  remainingApprovals   Indicates the number of approvals that remains in order to execute the action                     
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
 *   reentrant="True"
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
 * @ejb.ejb-external-ref
 *   description="The key recovery bean"
 *   view-type="local"
 *   ref-name="ejb/KeyRecoverySessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome"
 *   business="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal"
 *   link="KeyRecoverySession"
 *
 * @ejb.finder
 *   description="findByApprovalId"
 *   signature="Collection findByApprovalId(int approvalid)"
 *   query="SELECT OBJECT(a) from ApprovalDataBean a WHERE a.approvalId=?1"
 *   
 * @ejb.finder
 *   description="findByApprovalIdNonExpired"
 *   signature="Collection findByApprovalIdNonExpired(int approvalid)"
 *   query="SELECT OBJECT(a) from ApprovalDataBean a WHERE (a.status>-3) and a.approvalId=?1"
 *
 * @ejb.finder
 *   description="findAll"
 *   signature="Collection findAll()"
 *   query="SELECT OBJECT(a) from ApprovalDataBean a"
 *
 * @ejb.transaction type="Required"
 *
 * @jonas.jdbc-mapping
 *   jndi-name="${datasource.jndi-name}"
 *   
 * @author Philip Vendil
 * @version $Id$   
 */
public abstract class ApprovalDataBean extends BaseEntityBean {

    private static final Logger log = Logger.getLogger(ApprovalDataBean.class);
    

    /**
     * unique row id
     * 
     * @ejb.pk-field
     * @ejb.persistence column-name="id"
     * @ejb.interface-method view-type="local"
     */
    public abstract Integer getId();

    /**
     * unique row id
     * 
     */
    public abstract void setId(Integer id);
    
    /**
     * Constructed from action data as actiontype, admin, username etc. It should
     * result in the same approvalid if the admin tries to request the same action twice.
     * 
     * @ejb.pk-field
     * @ejb.persistence column-name="approvalId"
     */
    public abstract int getApprovalId();

    /**
     * Constructed from action data as actiontype, admin, username etc. It should
     * result in the same approvalid if the admin tries to request the same action twice.
     * 
     */
    public abstract void setApprovalId(int approvalid);

    
    /**   
     * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
     * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
     *     
     * @ejb.persistence column-name="approvalType"
     */
    public abstract int getApprovalType();

    /**
     * Type of action that should be approved, should be one of ApprovalDataVO.APPROVALTYPE_ 
     * constants ex: ApprovalDataVO.APPROVALTYPE_ADDUSER
     *     
     */
    public abstract void setApprovalType(int approvaltype);

    
    /**
     * For RA specific approval requests should the related end entity profile id be specified
     * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
     *     
     * @ejb.persistence column-name="endEntityProfileId"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getEndEntityProfileId();

    
    /**
     * For RA specific approval requests should the related end entity profile id be specified
     * for non ra request should this field be set to ApprovalDataVO.ANY_ENDENTITYPROFILE     
     *     
     */
    public abstract void setEndEntityProfileId(int endentityprofileid);
    
    /**
     * For CA specific approval requests should the related ca id be specified
     * for non ca request should this field be set to ApprovalDataVO.ANY_CA
     *      
     * @ejb.persistence column-name="cAId"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getCaId();

    
    /**
     * For CA specific approval requests should the related ca id be specified
     * for non ca request should this field be set to ApprovalDataVO.ANY_CA    
     *     
     */
    public abstract void setCaId(int caid);
    
    /**
     * The issuerdn of the administrator certificate that generated the request.
     * 
     * @ejb.persistence column-name="reqAdminCertIssuerDn"
     */
    public abstract String getReqAdminCertIssuerDn();

    /**
     * The issuerdn of the administrator certificate that generated the request.
     * 
     */
    public abstract void setReqAdminCertIssuerDn(String reqadmincertissuerdn);
    
    /**
     * The serialnumber of the administrator certificate that generated the request. String in Hex.
     * 
     * @ejb.persistence column-name="reqAdminCertSn"
     */
    public abstract String getReqAdminCertSn();

    /**
     * The serialnumber of the administrator certificate that generated the request. String in Hex.
     * 
     */
    public abstract void setReqAdminCertSn(String reqadmincertsn);
    
    /**
     * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, 
     * STATUS_REJECTED, STATUS_EXPIRED
     * 
     * @ejb.persistence column-name="status"
     * @ejb.interface-method view-type="local"
     */
    public abstract int getStatus();

    /**
     * Should be one of ApprovalDataVO.STATUS_WAITINGFORAPPROVAL, STATUS_APPROVED, 
     * STATUS_REJECTED, STATUS_EXPIRED
     * 
     */
    public abstract void setStatus(int status);

    /**
     * Stringrepresentation of data of approvals made by one or more administrators
     * 
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="approvalData"
     */
    public abstract String getApprovalData();

    /**
     * Stringrepresentation of data of approvals made by one or more administrators
     */
    public abstract void setApprovalData(String approvaldata);

    /**
     * Data containing information about the request displayed for the approval administrator.
     * 
     * @ejb.persistence jdbc-type="LONGVARCHAR" column-name="requestData"
     */
    public abstract String getRequestData();

    /**
     * Data containing information about the request displayed for the approval administrator.
     */
    public abstract void setRequestData(String requestdata);            
    
    /**
     * Date the request for approval were added
     *
     * @ejb.persistence column-name="requestDate"
     */
    public abstract long getRequestDate();

    /**
     * Date the request for approval were added
     *
     */
    public abstract void setRequestDate(long requestdate);
    
    /**
     * Date the request for action or the approvel action will expire, Long.MAX_VALUE 
     * means that the request/approval never expires
     *
     * @ejb.persistence column-name="expireDate"
     */
    public abstract long getExpireDate();

    /**
     * Date the request for action or the approvel action will expire, Long.MAX_VALUE 
     * means that the request/approval never expires
     *
     */
    public abstract void setExpireDate(long expiredate);
      
    /**
     * Indicates the number of approvals that remains in order to execute the action
     *      
     * @ejb.persistence column-name="remainingApprovals"
     */
    public abstract int getRemainingApprovals();

    
    /**
     * Indicates the number of approvals that remains in order to execute the action  
     *     
     */
    public abstract void setRemainingApprovals(int remainingapprovals);
    
    
    /**
     * NOTE: This method should never be used publicly except from UpgradeSessionBean 
     * @return Collection<Approval>
     * @ejb.interface-method view-type="local"
     */
    public Collection getApprovals() {   
    	return ApprovalDataUtil.getApprovals(getApprovalData());
    }
    
    /**
     * NOTE: This method should never be used publicly except from UpgradeSessionBean 
     * 
     * @param approvals Collection<Approval>, cannot be null.
     * @throws IOException
     */
    public void setApprovals(Collection approvals){
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
    		
    		setApprovalData(new String(Base64.encode(baos.toByteArray(),false)));
    	} catch (IOException e) {
    		log.error("Error building approvals.",e);
    		throw new EJBException(e);
    	}
    }
    
    /**
     * NOTE: This method should never be used publicly except from UpgradeSessionBean 
     * @return ApprovalRequest
     * @ejb.interface-method view-type="local"
     */
    public ApprovalRequest getApprovalRequest() {
    	return ApprovalDataUtil.getApprovalRequest(getRequestData());
    }
    
    /**
     * NOTE: This method should never be used publicly except from UpgradeSessionBean 
     * @ejb.interface-method view-type="local"
     */
    public void setApprovalRequest(ApprovalRequest approvalRequest){
    	try{
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	ObjectOutputStream oos = new ObjectOutputStream(baos);
    	oos.writeObject(approvalRequest);
    	oos.flush();
    	setRequestData(new String(Base64.encode(baos.toByteArray(),false)));
    	}catch(IOException e){
			log.error("Error building approval request.",e);
			throw new EJBException(e);   		
    	}
    }
    
    private Date getReqDate(){    
    	return new Date(getRequestDate());
    }
    
    private void setReqDate(Date requestDate){
    	setRequestDate(requestDate.getTime());
    }
    
    private Date getExpDate(){    
    	return new Date(getExpireDate());
    }

    /**
     * Method used to set the expire date of the request
     *
     */
    public void setExpDate(Date expireDate){
    	setExpireDate(expireDate.getTime());
    }
     
    /**
     * Method that checks if the request or approval have expired
     * The status is set to expired of it as
     * @return true of the request or approval have expired
     */
    private boolean haveRequestOrApprovalExpired(){
    	Date currentDate = new Date();
    	boolean retval = false;
    	if(currentDate.after(getExpDate())){
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
     * Method that returns the approval data. This method currently extracts the ApprovalRequest object.
     *
     * @ejb.interface-method view-type="local"
     */
    public String getRequestAdminUsername() {
    	return getApprovalRequest().getRequestAdmin().getUsername();
    }
    
    /**
     * Method that returns the approval data.
     *
     * @ejb.interface-method view-type="local"
     */
    public ApprovalDataVO getApprovalDataVO() {
    	haveRequestOrApprovalExpired();

        return new ApprovalDataVO(getId().intValue(),getApprovalId(),getApprovalType(),
        		                  getEndEntityProfileId(),getCaId(),getReqAdminCertIssuerDn(),
        		                  getReqAdminCertSn(), getStatus(),getApprovals(), getApprovalRequest(),
        		                  getReqDate(),getExpDate(),getRemainingApprovals());
        		                                           
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
    		throw new ApprovalException(ErrorCode.APPROVAL_WRONG_STATUS, "Wrong status of approval request.");
    	}
    	
    	int numberofapprovalsleft = getRemainingApprovals() -1;
    	if(numberofapprovalsleft < 0){
    		throw new ApprovalException(ErrorCode.ENOUGH_APPROVAL,
                "Error already enough approvals have been done on this request.");
    	}
    		
    	setRemainingApprovals(numberofapprovalsleft);
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
    			setExpDate(new Date());
    		}else{
    			setStatus(ApprovalDataVO.STATUS_APPROVED);
    			setExpireDate((new Date()).getTime() + approvalRequest.getApprovalValidity());
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
    		throw new ApprovalException(ErrorCode.APPROVAL_WRONG_STATUS, "Wrong status of approval request.");
    	}
    	
    	int numberofapprovalsleft = getRemainingApprovals() -1;
    	if(numberofapprovalsleft < 0){
    		throw new ApprovalException(ErrorCode.ENOUGH_APPROVAL,
                "Error already enough approvals have been done on this request.");
    	}
    		
    	setRemainingApprovals(0);
    	Collection approvals = getApprovals();
    	approvals.add(approval);
    	setApprovals(approvals);
    	
    	if(getApprovalRequest().isExecutable()){
			setStatus(ApprovalDataVO.STATUS_EXECUTIONDENIED);
			setExpDate(new Date());    		    		
    	}else{
        	setStatus(ApprovalDataVO.STATUS_REJECTED);
        	setExpireDate((new Date()).getTime() + getApprovalRequest().getApprovalValidity());   		
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
    public int isApproved(int step) throws ApprovalRequestExpiredException {    	
    	if(getApprovalRequest().isStepDone(step)){
    		return ApprovalDataVO.STATUS_EXPIRED;
    	}
    	
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
    		return getRemainingApprovals();
    	}
    	
    	return getStatus();
    	        		                                           
    } 
    
    /**
     * Method used to mark an non-executable approval as done
     * if the last step is performed will the status be set as
     * expired.
     *
     * @throws ApprovalRequestExpiredException if the step have already been executed
     * @ejb.interface-method view-type="local"
     */
    public void markStepAsDone(int step) throws ApprovalRequestExpiredException {
    	ApprovalRequest ar = getApprovalRequest();
        if(!ar.isExecutable() && getStatus() == ApprovalDataVO.STATUS_APPROVED){
        	if(!ar.isStepDone(step)){
        		ar.markStepAsDone(step);
        		setApprovalRequest(ar);
        		if(step == ar.getNumberOfApprovalSteps()-1){
        			setStatus(ApprovalDataVO.STATUS_EXPIRED);
        		}
        	}else{
        		throw new ApprovalRequestExpiredException("Error step " + step + " of approval with id " + getApprovalId() + " have alread been performed");
        	}
        	
        }
        		                                           
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
        setApprovalId(approvalRequest.generateApprovalId());
        setApprovalType(approvalRequest.getApprovalType());
        setEndEntityProfileId(approvalRequest.getEndEntityProfileId());        
        setCaId(approvalRequest.getCAId());
        
        if(approvalRequest.getRequestAdminCert() != null){
          setReqAdminCertIssuerDn(CertTools.getIssuerDN(approvalRequest.getRequestAdminCert()));
          setReqAdminCertSn(CertTools.getSerialNumberAsString(approvalRequest.getRequestAdminCert()));
        }
        setStatus(ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);        
        setApprovals(new ArrayList());
        setApprovalRequest(approvalRequest);                
        setReqDate(new Date());
        setExpireDate((new Date()).getTime() + approvalRequest.getRequestValidity());
        setRemainingApprovals(approvalRequest.getNumOfRequiredApprovals());


        log.debug("Created approval with id " + id);
        return id;
    }

    public void ejbPostCreate(Integer id, ApprovalRequest approvalRequest) {
        // Do nothing. Required.
    }
}
