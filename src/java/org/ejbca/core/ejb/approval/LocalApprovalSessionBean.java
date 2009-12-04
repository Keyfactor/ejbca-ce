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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.RemoveException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataUtil;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExecutionException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.ApprovedActionAdmin;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.NotificationParamGen;
import org.ejbca.util.mail.MailSender;
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
 * @ejb.ejb-external-ref description="The Approval entity bean"
 *   view-type="local"
 *   ref-name="ejb/ApprovalDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.approval.ApprovalDataLocalHome"
 *   business="org.ejbca.core.ejb.approval.ApprovalDataLocal"
 *   link="ApprovalData"
 *   
 * @ejb.ejb-external-ref description="The Certificate store used to store and fetch certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref description="The Authorization Session Bean"
 *   view-type="local"
 *   ref-name="ejb/AuthorizationSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *   business="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *   link="AuthorizationSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The Ra Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/RaAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *   link="RaAdminSession"
 *   
 * @ejb.ejb-external-ref
 *   description="The User Admin session bean"
 *   view-type="local"
 *   ref-name="ejb/UserAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *   link="UserAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Hard token session bean"
 *   view-type="local"
 *   ref-name="ejb/HardTokenSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome"
 *   business="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal"
 *   link="HardTokenSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Key Recovery session bean"
 *   view-type="local"
 *   ref-name="ejb/KeyRecoverySessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome"
 *   business="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal"
 *   link="KeyRecoverySession"
 *
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *   
 * @ejb.ejb-external-ref description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.home extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.approval.IApprovalSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.approval.IApprovalSessionHome"
 *
 * @ejb.interface extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.approval.IApprovalSessionLocal"
 *   remote-class="org.ejbca.core.ejb.approval.IApprovalSessionRemote"
 *
 *  @jonas.bean ejb-name="ApprovalSession"
 */
public class LocalApprovalSessionBean extends BaseSessionBean {

	
	private static final Logger log = Logger.getLogger(LocalApprovalSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
	
    /**
     * The local home interface of approval entity bean.
     */
    private ApprovalDataLocalHome approvalHome = null;


    /**
     * The local interface of RaAdmin Session Bean.
     */
    private IRaAdminSessionLocal raadminsession;

    /**
     * The local interface of User Admin Session Bean.
     */
    private IUserAdminSessionLocal useradminsession;
    
    /**
     * The local interface of authorization session bean
     */
    private IAuthorizationSessionLocal authorizationsession = null;

    /**
     * The remote interface of  log session bean
     */
    private ILogSessionLocal logsession = null;

    private ICAAdminSessionLocal caAdminSession;

    /** The local interface of the certificate store session bean */
    private ICertificateStoreSessionLocal certificatestoresession;
    
    /**
     * Columns in the database used in select
     */
    private static final String APPROVALDATA_COL = "id, approvalId, approvalType, endEntityProfileId, cAId, reqAdminCertIssuerDn, reqAdminCertSn, status, approvalData, requestData, requestDate, expireDate, remainingApprovals";

    
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

    /**
     * Gets connection to user admin session bean
     *
     * @return Connection
     */
    private IUserAdminSessionLocal getUserAdminSession() {
        if (useradminsession == null) {
            try {
            	IUserAdminSessionLocalHome useradminsessionhome = (IUserAdminSessionLocalHome) getLocator().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
            	useradminsession = useradminsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return useradminsession;
    } //getUserAdminSession

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
     * Gets connection to caadmin session bean
     *
     * @return ICAAdminSessionLocal
     */
    private ICAAdminSessionLocal getCAAdminSession() {
        if (caAdminSession == null) {
            try {
                ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
                caAdminSession = caadminsessionhome.create();
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return caAdminSession;
    } //getCAAdminSession

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
    	log.trace(">addApprovalRequest");
    	int approvalId = approvalRequest.generateApprovalId();
    	
        ApprovalDataVO data = findNonExpiredApprovalRequest(admin, approvalId);
        if(data != null){						
			getLogSession().log(admin,approvalRequest.getCAId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREQUESTED,"Approval with id : " +approvalId +" already exists");
			throw new ApprovalException(ErrorCode.APPROVAL_ALREADY_EXISTS,
                "Approval Request " + approvalId + " already exists in database");
		} else {
			// The exists no approval request with status waiting add a new one
			try {
				Integer freeId = this.findFreeApprovalId();
				approvalHome.create(freeId,approvalRequest);
				GlobalConfiguration gc = getRAAdminSession().loadGlobalConfiguration(admin);
				if(gc.getUseApprovalNotifications()){
					sendApprovalNotification(admin, gc,
							                 intres.getLocalizedMessage("notification.newrequest.subject"),
							                 intres.getLocalizedMessage("notification.newrequest.msg"),
							                 freeId, approvalRequest.getNumOfRequiredApprovals(), new Date(), approvalRequest,null);
				}
				getLogSession().log(admin,approvalRequest.getCAId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_INFO_APPROVALREQUESTED,"Approval with id : " +approvalId +" added with status waiting.");
			} catch (CreateException e1) {
				getLogSession().log(admin,approvalRequest.getCAId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREQUESTED,"Approval with id : " +approvalId +" couldn't be created");
				log.error("Error creating approval request",e1);
				
			}
		}
		log.trace("<addApprovalRequest");
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
     	log.trace(">removeApprovalRequest");
     	
     	
     	try {
			ApprovalDataLocal adl = approvalHome.findByPrimaryKey(new Integer(id));
			adl.remove();
			getLogSession().log(admin,admin.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_INFO_APPROVALREQUESTED,"Approval with unique id : " + id +" removed successfully.");
		} catch (FinderException e) {
			getLogSession().log(admin,admin.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREQUESTED,"Error removing approvalrequest with unique id : " +id +", doesn't exist");
 			throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST,
                "Error removing approvalrequest with unique id : " +id +", doesn't exist");
		} catch (EJBException e) {
			getLogSession().log(admin,admin.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREQUESTED,"Error removing approvalrequest with unique id : " +id);
		    log.error("Error removing approval request",e);
		} catch (RemoveException e) {
			getLogSession().log(admin,admin.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREQUESTED,"Error removing approvalrequest with unique id : " +id);
		    log.error("Error removing approval request",e);
		}

 		log.trace("<removeApprovalRequest");
     }
    
    /**
     * Method used to approve an approval requests.
     * 
     * It does the follwing
     *  1. checks if the approval with the status waiting exists, throws an ApprovalRequestDoesntExistException otherwise
     *  
     *  2. check if the administrator is authorized using the follwing rules:
     *     2.1 if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     *         authorized to AccessRulesConstants.REGULAR_APPROVECAACTION othervise AccessRulesConstants.REGULAR_APPORVEENDENTITY 
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
    	log.trace(">approve");
    	ApprovalDataLocal adl;
		try {
			adl = isAuthorizedBeforeApproveOrReject(admin,approvalId);
		} catch (ApprovalException e1) {
			getLogSession().log(admin,admin.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALAPPROVED,"Approval request with id : " +approvalId +" doesn't exists.");
			throw e1;
		} 
		
		// Check that the approvers username doesn't exists among the existing usernames.
    	Certificate approvingCert = admin.getAdminInformation().getX509Certificate();
    	ApprovalDataVO data = adl.getApprovalDataVO();
		String username = getCertificateStoreSession().findUsernameByCertSerno(admin,CertTools.getSerialNumber(approvingCert),CertTools.getIssuerDN(approvingCert));
		
        // Check that the approver isn't the same as requested the action.
		if(data.getReqadmincertissuerdn() != null){
			String requsername = getCertificateStoreSession().findUsernameByCertSerno(admin,new BigInteger(data.getReqadmincertsn(),16),data.getReqadmincertissuerdn());
			if(username.equals(requsername)){
				getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALAPPROVED,"Error administrator have already approved, rejected or requested current request, approveId " + approvalId);
				throw new AdminAlreadyApprovedRequestException("Error administrator have already approved, rejected or requested current request, approveId : " + approvalId);			
			}
		}
		if(username != null){
			Iterator iter = data.getApprovals().iterator();
			while(iter.hasNext()){
				Approval next = (Approval) iter.next();
				if(next.getUsername().equals(username)){
					getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALAPPROVED,"Error administrator have already approved or rejected current request, approveId " + approvalId);
					throw new AdminAlreadyApprovedRequestException("Error administrator have already approved or rejected current request, approveId : " + approvalId);					
				}
			}
			approval.setApprovalCertificateAndUsername(true, approvingCert,username);
		}else{
			getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALAPPROVED,"Approval request with id : " +approvalId +", Error no username exists for the given approver certificate.");
			throw new ApprovalException(ErrorCode.USER_NOT_FOUND,
                "Error no username exists for the given approver or requestor certificate");
		}
				
    	
    	try {
			adl.approve(approval);
			GlobalConfiguration gc = getRAAdminSession().loadGlobalConfiguration(admin);
			if(gc.getUseApprovalNotifications()){
			  if(adl.getApprovalDataVO().getRemainingApprovals() != 0){
			    sendApprovalNotification(admin, gc,
						               intres.getLocalizedMessage("notification.requestconcured.subject"),
						               intres.getLocalizedMessage("notification.requestconcured.msg"),
						               adl.getId(), adl.getApprovalDataVO().getRemainingApprovals(),  adl.getApprovalDataVO().getRequestDate(),
						               adl.getApprovalDataVO().getApprovalRequest(), 
						               approval);
			  }else{
				 sendApprovalNotification(admin, gc,
				               intres.getLocalizedMessage("notification.requestapproved.subject"),
				               intres.getLocalizedMessage("notification.requestapproved.msg"),
				               adl.getId(), adl.getApprovalDataVO().getRemainingApprovals(),  adl.getApprovalDataVO().getRequestDate(),
				               adl.getApprovalDataVO().getApprovalRequest(), 
				               approval);				  
			  }
			}
			getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_INFO_APPROVALAPPROVED,"Approval request with id : " +approvalId +" have been approved.");
		} catch (ApprovalRequestExpiredException e) {
			getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALAPPROVED,"Approval request with id : " +approvalId +" have expired.");
			throw e;
		} catch (ApprovalRequestExecutionException e) {
			getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALAPPROVED,"Approval with id : " +approvalId +" couldn't execute properly");
			throw e;
		}
		log.trace("<approve");
    }
    
    /**
     * Method used to reject a approval requests.
     * 
     * It does the follwing
     *  1. checks if the approval with the status waiting exists, throws an ApprovalRequestDoesntExistException otherwise
     *  
     *  2. check if the administrator is authorized using the follwing rules:
     *     2.1 if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     *         authorized to AccessRulesConstants.REGULAR_APPROVECAACTION othervise AccessRulesConstants.REGULAR_APPORVEENDENTITY 
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
    	log.trace(">reject");
    	ApprovalDataLocal adl;
		try {
			adl = isAuthorizedBeforeApproveOrReject(admin,approvalId);
		} catch (ApprovalException e1) {
			getLogSession().log(admin,admin.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREJECTED,"Approval request with id : " +approvalId +" doesn't exists.");
			throw e1;
		} 
		
		// Check that the approvers username doesn't exists among the existing usernames.
    	Certificate approvingCert = admin.getAdminInformation().getX509Certificate();
		String username = getCertificateStoreSession().findUsernameByCertSerno(admin,CertTools.getSerialNumber(approvingCert),CertTools.getIssuerDN(approvingCert));
		ApprovalDataVO data = adl.getApprovalDataVO();
		
		if(data.getReqadmincertissuerdn() != null){
			// Check that the approver isn't the same as requested the action.
			String requsername = getCertificateStoreSession().findUsernameByCertSerno(admin,new BigInteger(data.getReqadmincertsn(),16),data.getReqadmincertissuerdn());
			if(username.equals(requsername)){
				getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREJECTED,"Error administrator have already approved, rejected or requested current request, approveId ");
				throw new AdminAlreadyApprovedRequestException("Error administrator have already approved, rejected or requested current request, approveId : " + approvalId);			
			}
		}
		if(username != null){			
			Iterator iter = data.getApprovals().iterator();
			while(iter.hasNext()){
				Approval next = (Approval) iter.next();
				if(next.getUsername().equals(username)){
					getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREJECTED,"Error administrator have already approved or rejected current request, approveId ");
					throw new AdminAlreadyApprovedRequestException("Error administrator have already approved or rejected current request, approveId : " + approvalId);					
				}
			}
			approval.setApprovalCertificateAndUsername(false, approvingCert,username);
		}else{
			getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREJECTED,"Approval request with id : " +approvalId +", Error no username exists for the given approver certificate.");
			throw new ApprovalException(ErrorCode.USER_NOT_FOUND,
                "Error no username exists for the given approver or requestor certificate");
		}
				
    	
    	try {
			adl.reject(approval);
			GlobalConfiguration gc = getRAAdminSession().loadGlobalConfiguration(admin);
			if(gc.getUseApprovalNotifications()){				
			  sendApprovalNotification(admin, gc,
						               intres.getLocalizedMessage("notification.requestrejected.subject"),
						               intres.getLocalizedMessage("notification.requestrejected.msg"),
						               adl.getId(), adl.getApprovalDataVO().getRemainingApprovals(), adl.getApprovalDataVO().getRequestDate(),
						               adl.getApprovalDataVO().getApprovalRequest(), 
						               approval);
			}
			getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_INFO_APPROVALREJECTED,"Approval request with id : " +approvalId +" have been rejected.");
		} catch (ApprovalRequestExpiredException e) {
			getLogSession().log(admin,adl.getCaId(),LogConstants.MODULE_APPROVAL,new Date(),null,null,LogConstants.EVENT_ERROR_APPROVALREJECTED,"Approval request with id : " +approvalId +" have expired.");
			throw e;
		}
		log.trace("<reject");
    }    


	/**
     * Help method for approve and reject.
     */
    private ApprovalDataLocal isAuthorizedBeforeApproveOrReject(Admin admin, int approvalId) throws ApprovalException, AuthorizationDeniedException{
    	ApprovalDataLocal retval = null;
    	
    	retval = findNonExpiredApprovalDataLocal(approvalId);
    	
    	if(retval != null){
    		if(retval.getEndEntityProfileId() == ApprovalDataVO.ANY_ENDENTITYPROFILE){
    			getAuthorizationSession().isAuthorized(admin,AccessRulesConstants.REGULAR_APPROVECAACTION);				
    		}else{
    			getAuthorizationSession().isAuthorized(admin,AccessRulesConstants.REGULAR_APPROVEENDENTITY);
    			getAuthorizationSession().isAuthorized(admin,AccessRulesConstants.ENDENTITYPROFILEPREFIX + retval.getEndEntityProfileId() + AccessRulesConstants.APPROVAL_RIGHTS);
    		}
    		if(retval.getCaId() != ApprovalDataVO.ANY_CA){
    			getAuthorizationSession().isAuthorized(admin,AccessRulesConstants.CAPREFIX + retval.getCaId());
    		}


		} else {
			throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST,
                "Suitable approval with id : " + approvalId + " doesn't exist");
		}
    	return retval;
    }
    
    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved action.
     * 
     * If goes through all approvalrequests with the given Id and checks
     * their status, if any have status approved it returns STATUS_APPROVED.
     * 
     * This method should be used by action requiring the requesting administrator
     * to poll to see if it have been approved and only have one step, othervise
     * use the method with the step parameter.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the statys.
     * @throws ApprovalException if approvalId doesn't exists
     * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it wont throw it anymore. But 
     * If the request is multiple steps and user have already performed that step, the Exception will always be thrown. 
     * 
     * @ejb.interface-method view-type="both"
     */
    public int isApproved(Admin admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException{
    	if (log.isTraceEnabled()) {
        	log.trace(">isApproved, approvalId" + approvalId);
    	}
    	int retval = ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
    	
    	try {
			Collection result = approvalHome.findByApprovalId(approvalId);
			if(result.size() == 0){
				throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST,
                    "Approval request with id : " + approvalId + " doesn't exists");
			}
			Iterator iter = result.iterator();
			while(iter.hasNext()){
				ApprovalDataLocal adl = (ApprovalDataLocal) iter.next();
				retval = adl.isApproved(step);
				if(adl.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL ||
				   adl.getStatus() == ApprovalDataVO.STATUS_APPROVED ||
				   adl.getStatus() == ApprovalDataVO.STATUS_REJECTED ){
					break;
				}
			}
			
		} catch (FinderException e) {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST,
                "Approval request with id : " + approvalId + " doesn't exists");
		}
    	if (log.isTraceEnabled()) {
    		log.trace("<isApproved, result" + retval);
    	}
    	return retval;
    }
    
    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved. This is the default method for simple single step
     * approvals.
     * 
     * If goes through all approvalrequests with the given Id and checks
     * their status, if any have status approved it returns STATUS_APPROVED.
     * 
     * This method should be used by action requiring the requesting administrator
     * to poll to see if it have been approved and only have one step, othervise
     * use the method with the step parameter.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the status.
     * @throws ApprovalException if approvalId doesn't exists
     * @throws ApprovalRequestExpiredException Throws this exception one time if one of the approvals have expired, once notified it wont throw it anymore. But 
     * If the request is multiple steps and user have already performed that step, the Exception will always be thrown.
     * 
     * @ejb.interface-method view-type="both"
     */
    public int isApproved(Admin admin, int approvalId) throws ApprovalException, ApprovalRequestExpiredException{
       return isApproved(admin, approvalId, 0);
    }
    
    
    /**
     * Method that marks a certain step of a a non-executable approval 
     * as done. When the last step is performed the approvel is marked as EXPRIED.
     *  
     * @param admin
     * @param approvalId
     * @param step in approval to mark
     * @throws ApprovalException if approvalId doesn't exists,
     * 
     * @ejb.interface-method view-type="both"
     */
    public void markAsStepDone(Admin admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException{
    	if (log.isTraceEnabled()) {
        	log.trace(">markAsStepDone, approvalId" + approvalId + ", step " + step);
    	}
    	try {
			Collection result = approvalHome.findByApprovalId(approvalId);
			Iterator iter = result.iterator();
			while(iter.hasNext()){
				ApprovalDataLocal adl = (ApprovalDataLocal) iter.next();				
                adl.markStepAsDone(step);
			}
			
		} catch (FinderException e) {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST,
                "Approval request with id : " + approvalId + " doesn't exists");
		}
		log.trace("<markAsStepDone.");
    }
    
    /**
     * Method returning  an approval requests with status 'waiting', 'Approved' or 'Reject'
     * returns null if no non expired exists
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    public ApprovalDataVO findNonExpiredApprovalRequest(Admin admin, int approvalId){
    	ApprovalDataVO retval = null;
    	ApprovalDataLocal data = findNonExpiredApprovalDataLocal(approvalId);
    	if(data != null){
    		retval = data.getApprovalDataVO(); 
    	}
    	return retval;    	
    }
    
    private ApprovalDataLocal findNonExpiredApprovalDataLocal(int approvalId){
    	ApprovalDataLocal retval = null;
    	try {
			Collection result = approvalHome.findByApprovalIdNonExpired(approvalId);
			log.debug("Found number of approvalIdNonExpired: "+result.size());
			Iterator iter = result.iterator();
			while(iter.hasNext()){
				ApprovalDataLocal next = (ApprovalDataLocal) iter.next();
				ApprovalDataVO data = next.getApprovalDataVO();
				if(data.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL ||
				   data.getStatus() == ApprovalDataVO.STATUS_APPROVED ||
				   data.getStatus() == ApprovalDataVO.STATUS_REJECTED){
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
    	log.trace(">findApprovalDataVO");
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
		
    	log.trace("<findApprovalDataVO");
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
     * @throws AuthorizationDeniedException 
     * 
     * @ejb.transaction type="Supports"
     * @ejb.interface-method view-type="both"
     */
    
    public List query(Admin admin, Query query, int index, int numberofrows) throws IllegalQueryException, AuthorizationDeniedException {
        trace(">query()");
        
        boolean authorizedToApproveCAActions = false; // i.e approvals with endentityprofile ApprovalDataVO.ANY_ENDENTITYPROFILE
        boolean authorizedToApproveRAActions = false; // i.e approvals with endentityprofile not ApprovalDataVO.ANY_ENDENTITYPROFILE 
        
        try {
			authorizedToApproveCAActions = getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_APPROVECAACTION);
		} catch (AuthorizationDeniedException e1) {}
        try {
			authorizedToApproveRAActions = getAuthorizationSession().isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY);
		} catch (AuthorizationDeniedException e1) {
		}

		if(!authorizedToApproveCAActions && !authorizedToApproveRAActions){
			throw new AuthorizationDeniedException("Not authorized to query apporvals");
		}
		
        ArrayList returnData = new ArrayList();
        GlobalConfiguration globalconfiguration = getRAAdminSession().loadGlobalConfiguration(admin);
        RAAuthorization raauthorization = null;
        String sqlquery = "select " + APPROVALDATA_COL + " from ApprovalData where ";


        // Check if query is legal.
        if (query != null && !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }

        if (query != null) {
            sqlquery = sqlquery + query.getQueryString();
        }
        
        raauthorization = new RAAuthorization(admin, getRAAdminSession(), getAuthorizationSession(), getCAAdminSession());
        String caauthstring = raauthorization.getCAAuthorizationString();
        String endentityauth = "";
        if (globalconfiguration.getEnableEndEntityProfileLimitations()){
        	endentityauth = raauthorization.getEndEntityProfileAuthorizationString(true);
        	if(authorizedToApproveCAActions && authorizedToApproveRAActions){
        		endentityauth = raauthorization.getEndEntityProfileAuthorizationString(true);
        		if(endentityauth != null){
        		  endentityauth = "(" + raauthorization.getEndEntityProfileAuthorizationString(false) + " OR endEntityProfileId=" + ApprovalDataVO.ANY_ENDENTITYPROFILE + " ) ";
        		}
        	}else if (authorizedToApproveCAActions) {
        		endentityauth = " endEntityProfileId=" + ApprovalDataVO.ANY_ENDENTITYPROFILE;
			}else if (authorizedToApproveRAActions) {
				endentityauth = raauthorization.getEndEntityProfileAuthorizationString(true);
			}        	
        	
        }

        if (!caauthstring.trim().equals("") && query != null){
          sqlquery = sqlquery + " AND " + caauthstring;
        }else{
          sqlquery = sqlquery + caauthstring;
        }

        if (StringUtils.isNotEmpty(endentityauth)) {
          if (caauthstring.trim().equals("") && query == null){
        	sqlquery = sqlquery + endentityauth;
          }else{
          	sqlquery = sqlquery + " AND " + endentityauth;
          }
        }

        
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
                // Construct SQL query.
                con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
                log.debug(sqlquery);

                ps = con.prepareStatement(sqlquery);
                
                // Execute query.
                rs = ps.executeQuery();
                int direction = rs.getFetchDirection();
                if (direction == ResultSet.FETCH_FORWARD) {
                	// Special handling for databases that do not support backward moving in the RS, i.e. Hsql
                	if (index < 0) {
                		throw new Exception("Database does only support forward fetching, but index is "+index);
                	}
                	for (int i = 0; i < index; i++) {
                		rs.next();
                	}
                } else {
                    // Oracles JDBC driver in Weblogic 9.x does not support ResultSet.relative, 
                    // that is why we have to move around manually.
                    boolean forward = true;
                    if (index < 0) {
                        forward = false;
                    }
                    for (int i = 0; i < index; i++) {
                        if (forward) {
                            rs.next();                            
                        } else {
                            rs.previous();
                        }
                    }
                }
                // Assemble result.
                while (rs.next() && returnData.size() < numberofrows) {
                	
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

                	returnData.add(data);
                }
            trace("<query()");
            return returnData;
        } catch (Exception e) { 
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    } // query 

 
     
    private void sendApprovalNotification(Admin admin, GlobalConfiguration gc, String notificationSubject, String notificationMsg, Integer id, int numberOfApprovalsLeft, Date requestDate, ApprovalRequest approvalRequest, Approval approval) {
    	if (log.isTraceEnabled()) {
            log.trace(">sendNotification approval notification: id="+id);
    	}
        try {
        	Admin sendAdmin = admin;
        	if(admin.getAdminType() == Admin.TYPE_CLIENTCERT_USER){
        		sendAdmin = new ApprovedActionAdmin(admin.getAdminInformation().getX509Certificate());
        	}
        	
        	String requestAdminEmail = null;
        	String approvalAdminsEmail = null;
            String fromAddress = null;
        	// Find the email address of the requesting administrator.
        	Certificate requestAdminCert = approvalRequest.getRequestAdminCert();
        	String requestAdminDN = null;
        	String requestAdminUsername = null;
        	if(requestAdminCert != null){
        	  requestAdminDN = CertTools.getSubjectDN(requestAdminCert);
        	  requestAdminUsername = getCertificateStoreSession().findUsernameByCertSerno(sendAdmin,CertTools.getSerialNumber(requestAdminCert),CertTools.getIssuerDN(requestAdminCert));
              UserDataVO requestAdminData = getUserAdminSession().findUser(sendAdmin, requestAdminUsername);        	
              if (requestAdminData == null || requestAdminData.getEmail() == null || requestAdminData.getEmail().equals("")) {
               	getLogSession().log(sendAdmin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(),requestAdminUsername, null, LogConstants.EVENT_ERROR_NOTIFICATION, "Error sending notification to administrator requesting approval. Set a correct email to the administrator");
              }else{
               	requestAdminEmail = requestAdminData.getEmail();
              }
        	}else{
        		requestAdminUsername = intres.getLocalizedMessage("CLITOOL");
        		requestAdminDN = "CN=" + requestAdminUsername;
        	}
 
            
            // Find the email address of the approving administrators
            approvalAdminsEmail = gc.getApprovalAdminEmailAddress();            
            // Find the email address that should be used in the from field
            fromAddress = gc.getApprovalNotificationFromAddress();                        
            
            if(approvalAdminsEmail.equals("") || fromAddress.equals("")){
            	getLogSession().log(sendAdmin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(),requestAdminUsername, null, LogConstants.EVENT_ERROR_NOTIFICATION, "Error sending approval notification. The email-addresses, either to approval administrators or from-address isn't configured properly");
            }else{
              String approvalURL =  gc.getBaseUrl() + "adminweb/approval/approveaction.jsf?uniqueId=" + id;
              String approvalTypeText = intres.getLocalizedMessage(ApprovalDataVO.APPROVALTYPENAMES[approvalRequest.getApprovalType()]);
            	
              String approvalAdminUsername = null;
              String approvalAdminDN = null;
              String approveComment = null;
              if(approval != null){
            	  approvalAdminUsername = approval.getUsername();
            	  X509Certificate approvalCert =  (X509Certificate) getCertificateStoreSession().findCertificateByIssuerAndSerno(sendAdmin, approval.getAdminCertIssuerDN(), approval.getAdminCertSerialNumber());
            	  approvalAdminDN = CertTools.getSubjectDN(approvalCert);
            	  approveComment = approval.getComment();
              }
              Integer numAppr =  new Integer(numberOfApprovalsLeft);
              NotificationParamGen paramGen = new NotificationParamGen(requestDate,id,approvalTypeText,numAppr,
            		                                                   approvalURL, approveComment, requestAdminUsername,
            		                                                   requestAdminDN,approvalAdminUsername,approvalAdminDN);
              HashMap params = paramGen.getParams();
              String subject = NotificationParamGen.interpolate(params, notificationSubject);
              String message = NotificationParamGen.interpolate(params, notificationMsg);
              List toList = Arrays.asList(approvalAdminsEmail);
              if(requestAdminEmail != null){
            	  toList.add(requestAdminEmail);
              }
              MailSender.sendMailOrThrow(fromAddress, toList, MailSender.NO_CC, subject, message, MailSender.NO_ATTACHMENTS);
              getLogSession().log(sendAdmin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(), requestAdminUsername, null, LogConstants.EVENT_INFO_NOTIFICATION, "Approval notification with id " + id + " was sent successfully.");
            }
        } catch (Exception e) {
            error("Error when sending notification approving notification", e);
            try{
            	getLogSession().log(admin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_NOTIFICATION, "Error sending approval notification with id " + id + ".");
            }catch(Exception f){
                throw new EJBException(f);
            }
        }
    	if (log.isTraceEnabled()) {
            log.trace("<sendNotification approval notification: id="+id);
    	}
	}
    
    private Integer findFreeApprovalId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;

        while (!foundfree) {
            try {
                if (id > 1){
                    approvalHome.findByPrimaryKey(new Integer(id));
                }
                id = ran.nextInt();
            } catch (FinderException e) {
                foundfree = true;
            }
        }
        return new Integer(id);
    } // findFreeApprovalId

} // LocalApprovalSessionBean
