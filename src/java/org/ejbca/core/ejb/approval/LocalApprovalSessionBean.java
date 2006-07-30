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

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataUtil;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;



/**
 * Keeps track of approval requests and their approval or rejects.
 * 
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @ejb.bean description="Session bean handling interface with user data sources"
 *   display-name="ApprovalSessionSB"
 *   name="ApprovalSession"
 *   jndi-name="ApprovalSession"
 *   local-jndi-name="ApprovalSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry name="DataSource"
 *   type="java.lang.String"
 *   value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 *
 * @ejb.ejb-external-ref description="The Approval entity bean"
 *   view-type="local"
 *   ejb-name="ApprovalDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.Approval.ApprovalDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.Approval.ApprovalDataLocal"
 *   link="ApprovalData"
 *   
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ejb-name="CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ejb-name="AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The Ra Admin session bean"
 *   view-type="local"
 *   ejb-name="RaAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *
 *
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ejb-name="LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ra.Approval.IApprovalSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ra.Approval.IApprovalSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ra.Approval.IApprovalSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ra.Approval.IApprovalSessionRemote"
 *
 *  @jonas.bean ejb-name="ApprovalSession"
 */
public class LocalApprovalSessionBean extends BaseSessionBean {

	
	private static final Logger log = Logger.getLogger(LocalApprovalSessionBean.class);
	
    /**
     * The local home interface of approval entity bean.
     */
    private ApprovalDataLocalHome approvalHome = null;


    /**
     * The local interface of RaAdmin Session Bean.
     */
    private IRaAdminSessionLocal raadminsession;
    
    /**
     * The local interface of authorization session bean
     */
    private IAuthorizationSessionLocal authorizationsession = null;

    /**
     * The remote interface of  log session bean
     */
    private ILogSessionLocal logsession = null;


    /** The local interface of the certificate store session bean */
    private ICertificateStoreSessionLocal certificatestoresession;
    
    /**
     * Columns in the database used in select
     */
    private static final String APPROVALDATA_COL = "id, approvalid, approvaltype, endentityprofileid, caid, reqadmincertissuerdn, reqadmincertsn, status, approvaldata, requestdata, requestdate, expiredate, remainingapprovals";

    
    /**
     * Default create for SessionBean without any creation Arguments.
     *
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
    	approvalHome = (ApprovalDataLocalHome) getLocator().getLocalHome(ApprovalDataLocalHome.COMP_NAME);
    }


    /**
     * Gets connection to log session bean
     *
     * @return Connection
     */
    private ILogSessionLocal getLogSession() {
        if (logsession == null) {
            try {
                ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
                logsession = logsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return logsession;
    } //getLogSession
    
    /**
     * Gets connection to ra admin session bean
     *
     * @return Connection
     */
    private IRaAdminSessionLocal getRAAdminSession() {
        if (raadminsession == null) {
            try {
            	IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) getLocator().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
                raadminsession = raadminsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return raadminsession;
    } //getRAAdminSession


    /** Gets connection to certificate store session bean
     * @return Connection
     */
    private ICertificateStoreSessionLocal getCertificateStoreSession() {
        if(certificatestoresession == null){
            try{
                ICertificateStoreSessionLocalHome home = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
                certificatestoresession = home.create();
            }catch(Exception e){
                throw new EJBException(e);
            }
        }
        return certificatestoresession;
    } //getCertificateStoreSession    

    /**
     * Gets connection to authorization session bean
     *
     * @return IAuthorizationSessionLocal
     */
    private IAuthorizationSessionLocal getAuthorizationSession() {
        if (authorizationsession == null) {
            try {
                IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
                authorizationsession = authorizationsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return authorizationsession;
    } //getAuthorizationSession


   /**
    * Method used to add an approval to database.
    * 
    * The main key of an approval is the approvalid, which should be unique for
    * one administrator doing one type of action, requesting the same action twice should
    * result in the same approvalId
    * 
    * It the approvalId already exists, it will check the status:
    *   If status is waiting, approved, or rejected an ApprovalException is thrown
    *   otherwise is an new approval requeset added to the database
    *   
    * @throws ApprovalException 
    *   
    * @ejb.interface-method view-type="both"
    */
    public void addApprovalRequest(Admin admin, ApprovalRequest approvalRequest) throws ApprovalException{
    	log.debug(">addApprovalRequest");
    	int approvalId = approvalRequest.generateApprovalId();
    	
    	
        ApprovalDataVO data = findNonExpiredApprovalRequest(admin, approvalId);
        if(data != null){						
			getLogSession().log(admin,approvalRequest.getCAId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREQUESTED,"Approval with id : " +approvalId +" already exists");
			throw new ApprovalException("Approval Request " + approvalId + " already exists in database");
		} else {
			// The exists no approval request with status waiting add a new one
			try {
				approvalHome.create(this.findFreeApprovalId(),approvalRequest);
				getLogSession().log(admin,approvalRequest.getCAId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_INFO_APPROVALREQUESTED,"Approval with id : " +approvalId +" added with status waiting.");
			} catch (CreateException e1) {
				getLogSession().log(admin,approvalRequest.getCAId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREQUESTED,"Approval with id : " +approvalId +" couldn't be created");
				log.error("Error creating approval request",e1);
				
			}
		}
		log.debug("<addApprovalRequest");
    }
    

    /**
     * Method used to remove an approval from database.
     * 
     * @param id, the uniqu id of the approvalrequest, not the same as approvalId
     *   
     * @throws ApprovalException 
     *   
     * @ejb.interface-method view-type="both"
     */
     public void removeApprovalRequest(Admin admin, int id) throws ApprovalException{
     	log.debug(">removeApprovalRequest");
     	
     	
     	try {
			ApprovalDataLocal adl = approvalHome.findByPrimaryKey(new Integer(id));
			adl.remove();
			getLogSession().log(admin,admin.getCaId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_INFO_APPROVALREQUESTED,"Approval with unique id : " + id +" removed successfully.");
		} catch (FinderException e) {
			getLogSession().log(admin,admin.getCaId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREQUESTED,"Error removing approvalrequest with unique id : " +id +", doesn't exist");
 			throw new ApprovalException("Error removing approvalrequest with unique id : " +id +", doesn't exist");
		} catch (EJBException e) {
			getLogSession().log(admin,admin.getCaId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREQUESTED,"Error removing approvalrequest with unique id : " +id);
		    log.error("Error removing approval request",e);
		} catch (RemoveException e) {
			getLogSession().log(admin,admin.getCaId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREQUESTED,"Error removing approvalrequest with unique id : " +id);
		    log.error("Error removing approval request",e);
		}

 		log.debug("<removeApprovalRequest");
     }
    
    /**
     * Method used to approve an approval requests.
     * 
     * It does the follwing
     *  1. checks if the approval with the status waiting exists, throws an ApprovalRequestDoesntExistException otherwise
     *  
     *  2. check if the administrator is authorized using the follwing rules:
     *     2.1 if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     *         authorized to AvailableAccessRules.REGULAR_APPROVECAACTION othervise AvailableAccessRules.REGULAR_APPORVEENDENTITY 
     *         and APPROVAL_RIGHTS for the end entity profile.
     *     2.2 Checks if the admin is authoried to the approval requests getCAId()
     *     
     *  3. looks upp the username of the administrator and checks that no approval
     *     have been made by this user earlier.
     *        
     *  4. Runs the approval command in the end entity bean.      
     * 
     * @param admin
     * @param approvalId
     * @param approval
     * @throws ApprovalRequestExpiredException 
     * @throws ApprovalRequestExecutionException 
     * @throws AuthorizationDeniedException 
     * @throws ApprovalRequestDoesntExistException 
     * @throws ApprovalException 
     * @throws AdminAlreadyApprovedRequestException 
     * 
    *   
    * @ejb.interface-method view-type="both"
     */
    public void approve(Admin admin, int approvalId, Approval approval) throws ApprovalRequestExpiredException, ApprovalRequestExecutionException, 
                                                                               AuthorizationDeniedException,  ApprovalException, AdminAlreadyApprovedRequestException{
    	log.debug(">approve");
    	ApprovalDataLocal adl;
		try {
			adl = isAuthorizedBeforeApproveOrReject(admin,approvalId,approval);
		} catch (ApprovalException e1) {
			getLogSession().log(admin,admin.getCaId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALAPPROVED,"Approval request with id : " +approvalId +" doesn't exists.");
			throw e1;
		} 
		
		// Check that the approvers username doesn't exists among the existing usernames.
    	X509Certificate approvingCert = admin.getAdminInformation().getX509Certificate();
    	ApprovalDataVO data = adl.getApprovalDataVO();
		String username = getCertificateStoreSession().findUsernameByCertSerno(admin,approvingCert.getSerialNumber(),CertTools.getIssuerDN(approvingCert));
		
        // Check that the approver isn't the same as requested the action.
		String requsername = getCertificateStoreSession().findUsernameByCertSerno(admin,new BigInteger(data.getReqadmincertsn(),16),data.getReqadmincertissuerdn());
		if(username.equals(requsername)){
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALAPPROVED,"Error administrator have already approved, rejected or requested current request, approveId " + approvalId);
			throw new AdminAlreadyApprovedRequestException("Error administrator have already approved, rejected or requested current request, approveId : " + approvalId);			
		}
		if(username != null && requsername != null){
			Iterator iter = data.getApprovals().iterator();
			while(iter.hasNext()){
				Approval next = (Approval) iter.next();
				if(next.getUsername().equals(username)){
					getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALAPPROVED,"Error administrator have already approved or rejected current request, approveId " + approvalId);
					throw new AdminAlreadyApprovedRequestException("Error administrator have already approved or rejected current request, approveId : " + approvalId);					
				}
			}
			approval.setApprovalCertificateAndUsername(true, approvingCert,username);
		}else{
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALAPPROVED,"Approval request with id : " +approvalId +", Error no username exists for the given approver certificate.");
			throw new ApprovalException("Error no username exists for the given approver or requestor certificate");
		}
				
    	
    	try {
			adl.approve(approval);
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_INFO_APPROVALAPPROVED,"Approval request with id : " +approvalId +" have been approved.");
		} catch (ApprovalRequestExpiredException e) {
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALAPPROVED,"Approval request with id : " +approvalId +" have expired.");
			throw e;
		} catch (ApprovalRequestExecutionException e) {
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALAPPROVED,"Approval with id : " +approvalId +" couldn't execute properly");
			throw e;
		}
		log.debug("<approve");
    }
    
    /**
     * Method used to reject a approval requests.
     * 
     * It does the follwing
     *  1. checks if the approval with the status waiting exists, throws an ApprovalRequestDoesntExistException otherwise
     *  
     *  2. check if the administrator is authorized using the follwing rules:
     *     2.1 if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     *         authorized to AvailableAccessRules.REGULAR_APPROVECAACTION othervise AvailableAccessRules.REGULAR_APPORVEENDENTITY 
     *         and APPROVAL_RIGHTS for the end entity profile.
     *     2.2 Checks if the admin is authoried to the approval requests getCAId()
     *     
     *  3. looks upp the username of the administrator and checks that no approval
     *     have been made by this user earlier.
     *        
     *  4. Runs the approval command in the end entity bean.      
     * 
     * @param admin
     * @param approvalId
     * @param approval
     * @throws ApprovalRequestExpiredException 
     * @throws AuthorizationDeniedException 
     * @throws ApprovalRequestDoesntExistException 
     * @throws ApprovalException 
     * @throws AdminAlreadyApprovedRequestException 
     * 
     *   
     * @ejb.interface-method view-type="both"
     */
    public void reject(Admin admin, int approvalId, Approval approval) throws ApprovalRequestExpiredException,  
                                                                               AuthorizationDeniedException,  ApprovalException, AdminAlreadyApprovedRequestException{
    	log.debug(">reject");
    	ApprovalDataLocal adl;
		try {
			adl = isAuthorizedBeforeApproveOrReject(admin,approvalId,approval);
		} catch (ApprovalException e1) {
			getLogSession().log(admin,admin.getCaId(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREJECTED,"Approval request with id : " +approvalId +" doesn't exists.");
			throw e1;
		} 
		
		// Check that the approvers username doesn't exists among the existing usernames.
    	X509Certificate approvingCert = admin.getAdminInformation().getX509Certificate();
		String username = getCertificateStoreSession().findUsernameByCertSerno(admin,approvingCert.getSerialNumber(),CertTools.getIssuerDN(approvingCert));
		ApprovalDataVO data = adl.getApprovalDataVO();
        // Check that the approver isn't the same as requested the action.
		String requsername = getCertificateStoreSession().findUsernameByCertSerno(admin,new BigInteger(data.getReqadmincertsn(),16),data.getReqadmincertissuerdn());
		if(username.equals(requsername)){
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREJECTED,"Error administrator have already approved, rejected or requested current request, approveId ");
			throw new AdminAlreadyApprovedRequestException("Error administrator have already approved, rejected or requested current request, approveId : " + approvalId);			
		}
		if(username != null && requsername != null){			
			Iterator iter = data.getApprovals().iterator();
			while(iter.hasNext()){
				Approval next = (Approval) iter.next();
				if(next.getUsername().equals(username)){
					getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREJECTED,"Error administrator have already approved or rejected current request, approveId ");
					throw new AdminAlreadyApprovedRequestException("Error administrator have already approved or rejected current request, approveId : " + approvalId);					
				}
			}
			approval.setApprovalCertificateAndUsername(false, approvingCert,username);
		}else{
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREJECTED,"Approval request with id : " +approvalId +", Error no username exists for the given approver certificate.");
			throw new ApprovalException("Error no username exists for the given approver or requestor certificate");
		}
				
    	
    	try {
			adl.reject(approval);
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_INFO_APPROVALREJECTED,"Approval request with id : " +approvalId +" have been rejected.");
		} catch (ApprovalRequestExpiredException e) {
			getLogSession().log(admin,adl.getCaid(),LogEntry.MODULE_RA,new Date(),null,null,LogEntry.EVENT_ERROR_APPROVALREJECTED,"Approval request with id : " +approvalId +" have expired.");
			throw e;
		}
		log.debug("<reject");
    }
    
    /**
     * Help method for approve and reject.
     */
    private ApprovalDataLocal isAuthorizedBeforeApproveOrReject(Admin admin, int approvalId, Approval approval) throws ApprovalException, AuthorizationDeniedException{
    	ApprovalDataLocal retval = null;
    	
    	retval = findNonExpiredApprovalDataLocal(admin,approvalId);
    	
    	if(retval != null){
    		if(retval.getEndentityprofileid() == ApprovalDataVO.ANY_ENDENTITYPROFILE){
    			getAuthorizationSession().isAuthorized(admin,AvailableAccessRules.REGULAR_APPROVECAACTION);				
    		}else{
    			getAuthorizationSession().isAuthorized(admin,AvailableAccessRules.REGULAR_APPORVEENDENTITY);
    			getAuthorizationSession().isAuthorized(admin,AvailableAccessRules.ENDENTITYPROFILEPREFIX + retval.getEndentityprofileid() + AvailableAccessRules.APPROVAL_RIGHTS);
    		}
    		if(retval.getCaid() != ApprovalDataVO.ANY_CA){
    			getAuthorizationSession().isAuthorized(admin,AvailableAccessRules.CAPREFIX + retval.getCaid());
    		}


		} else {
			throw new ApprovalException("Suitable approval with id : " + approvalId + " doesn't exist");
		}
    	return retval;
    }
    
    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved action.
     * 
     * If goes through all approvalrequests with the given Id and checks
     * their status, if any have status approved it returns true.
     * 
     * This method should be used by action requiring the requesting administrator
     * to poll to see if it have been approved.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the statys.
     * @throws ApprovalException if approvalId doesn't exists
     * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it wount throw it anymore.
     * 
     * @ejb.interface-method view-type="both"
     */
    public int isApproved(Admin admin, int approvalId) throws ApprovalException, ApprovalRequestExpiredException{
    	log.debug(">isApproved, approvalId" + approvalId);
    	int retval = ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
    	
    	try {
			Collection result = approvalHome.findByApprovalId(approvalId);
			Iterator iter = result.iterator();
			while(iter.hasNext()){
				ApprovalDataLocal adl = (ApprovalDataLocal) iter.next();
				retval = adl.isApproved();
				if(retval != ApprovalDataVO.STATUS_EXPIRED && 
				   retval != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED && 
				   retval != ApprovalDataVO.STATUS_EXECUTED ){
					break;
				}
			}
			
		} catch (FinderException e) {
            throw new ApprovalException("Approval request with id : " + approvalId + " doesn't exists");
		}
    	
		log.debug("<isApproved, result" + retval);
    	return retval;
    }
    
    /**
     * Method returning  an approval requests with status 'waiting', 'Approved' or 'Reject'
     * returns null if no non expirted have exists
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public ApprovalDataVO findNonExpiredApprovalRequest(Admin admin, int approvalId){
    	ApprovalDataVO retval = null;
    	ApprovalDataLocal data = findNonExpiredApprovalDataLocal(admin,approvalId);

    	if(data != null){
    		retval = data.getApprovalDataVO(); 
    	}
		
    	return retval;    	
    }
    
    private ApprovalDataLocal findNonExpiredApprovalDataLocal(Admin admin, int approvalId){
    	ApprovalDataLocal retval = null;
    	try {
			Collection result = approvalHome.findByApprovalIdNonExpired(approvalId);
			Iterator iter = result.iterator();
			while(iter.hasNext()){
				ApprovalDataLocal next = (ApprovalDataLocal) iter.next();
				ApprovalDataVO data = next.getApprovalDataVO();
				if(data.getStatus() != ApprovalDataVO.STATUS_EXECUTED &&
				   data.getStatus() != ApprovalDataVO.STATUS_EXPIRED &&
				   data.getStatus() != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED){
					retval = next;
				}
				
			}
		} catch (FinderException e) {}  
		
    	return retval;    	
    }
    
    /**
     * Method that takes an approvalId and returns all aprovalrequests for 
     * this.
     * 
     * @param admin
     * @param approvalId
     * @return and collection of ApprovalDataVO, empty if no approvals exists.
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public Collection findApprovalDataVO(Admin admin, int approvalId){
    	log.debug(">findApprovalDataVO");
    	ArrayList retval = new ArrayList();
    	
    	try {
			Collection result = approvalHome.findByApprovalId(approvalId);
			Iterator iter = result.iterator();
			while(iter.hasNext()){
				ApprovalDataLocal adl = (ApprovalDataLocal) iter.next();
				retval.add(adl.getApprovalDataVO());
			}
		} catch (FinderException e) {
		}
		
    	log.debug("<findApprovalDataVO");
		return retval;
    }
    

    /**
     * Method returning a list of approvals from the give query
     * 
     * @param admin
     * @param query should be a Query object containing ApprovalMatch and TimeMatch
     * @param index where the resultset should start. 
     * objects only
     * @return a List of ApprovalDataVO, never null
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    
    public List query(Admin admin, Query query, int index, int numberofrows) throws IllegalQueryException {
        debug(">query(): ");
        boolean authorizedtoanyprofile = true;
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;

        ArrayList returnval = new ArrayList();
        GlobalConfiguration globalconfiguration = getRAAdminSession().loadGlobalConfiguration(admin);
        RAAuthorization raauthorization = null;
        String sqlquery = "select " + APPROVALDATA_COL + " from ApprovalData where ";


        // Check if query is legal.
        if (query != null && !query.isLegalQuery())
            throw new IllegalQueryException();

        if (query != null)
            sqlquery = sqlquery + query.getQueryString();

        raauthorization = new RAAuthorization(admin, getRAAdminSession(), getAuthorizationSession());
        String caauthstring = raauthorization.getCAAuthorizationString();
        String endentityauth = "";
        if (globalconfiguration.getEnableEndEntityProfileLimitations()){
        	endentityauth = raauthorization.getEndEntityProfileAuthorizationString();
        }


        if (!caauthstring.trim().equals("") && query != null)
            sqlquery = sqlquery + " AND " + caauthstring;
        else
            sqlquery = sqlquery + caauthstring;


        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            if (caauthstring.trim().equals("") && query == null)
                sqlquery = sqlquery + endentityauth;
            else
                sqlquery = sqlquery + " AND " + endentityauth;

            if (endentityauth == null || endentityauth.trim().equals("")) {
                authorizedtoanyprofile = false;
            }
        }

        try {
            if (authorizedtoanyprofile) {
                // Construct SQL query.
                con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
                log.info(sqlquery);

                ps = con.prepareStatement(sqlquery);
                
                // Execute query.
                rs = ps.executeQuery();
                rs.relative(index);
                // Assemble result.
                while (rs.next() && returnval.size() < numberofrows) {
                	
                    // Read the variables in order, some databases (i.e. MS-SQL) 
                    // seems to not like out-of-order read of columns (i.e. nr 15 before nr 1)
                    int id = rs.getInt(1);
                    int approvalid = rs.getInt(2);
                    int approvaltype = rs.getInt(3);
                    int endentityprofileId = rs.getInt(4);
                    int caid = rs.getInt(5);
                    String reqadmincertissuerdn = rs.getString(6);
                    String reqadmincertserial = rs.getString(7);
                    int status = rs.getInt(8);
                    String approvaldatastring = rs.getString(9);
                    String requestdatastring = rs.getString(10);
                    long requestdate = rs.getLong(11);
                    long expiredate = rs.getLong(12);
                    int remainingapprovals = rs.getInt(13);
                	ApprovalDataVO data = new ApprovalDataVO(id,approvalid,approvaltype,endentityprofileId,caid,
                			                                 reqadmincertissuerdn, reqadmincertserial, status,
                			                                 ApprovalDataUtil.getApprovals(approvaldatastring),
                			                                 ApprovalDataUtil.getApprovalRequest(requestdatastring),
                			                                 new Date(requestdate), new Date(expiredate), remainingapprovals); 

                	returnval.add(data);
                }
            }
            debug("<query()");
            return returnval;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }

    } // query 

    private Integer findFreeApprovalId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > 1)
                   approvalHome.findByPrimaryKey(new Integer(id));
                id = ran.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return new Integer(id);
    } // findFreeApprovalId


} // LocalApprovalSessionBean
