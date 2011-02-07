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
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.approval.AdminAlreadyApprovedRequestException;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataUtil;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalNotificationParamGen;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.ApprovedActionAdmin;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;
import org.ejbca.util.mail.MailSender;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Keeps track of approval requests and their approval or rejects.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "ApprovalSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class ApprovalSessionBean implements ApprovalSessionLocal, ApprovalSessionRemote {

    private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(ApprovalSessionBean.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private LogSessionLocal logSession;

    /**
     * Method used to add an approval to database.
     * 
     * The main key of an approval is the approvalId, which should be unique
     * for one administrator doing one type of action, requesting the same
     * action twice should result in the same approvalId
     * 
     * If the approvalId already exists, with a non expired approval, a new approval
     * request is added to the database. An approvalException is thrown otherwise
     * 
     * @throws ApprovalException
     *             if an approval already exists for this request.
     * 
     */
    public void addApprovalRequest(Admin admin, ApprovalRequest approvalRequest, GlobalConfiguration gc) throws ApprovalException {
        log.trace(">addApprovalRequest");
        int approvalId = approvalRequest.generateApprovalId();

        ApprovalDataVO data = findNonExpiredApprovalRequest(admin, approvalId);
        if (data != null) {
            logSession.log(admin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALREQUESTED,
                    "Approval with id : " + approvalId + " already exists");
            throw new ApprovalException(ErrorCode.APPROVAL_ALREADY_EXISTS, "Approval Request " + approvalId + " already exists in database");
        } else {
            // There exists no approval request with status waiting. Add a new one
            try {
                final Integer freeId = findFreeApprovalId();
                final ApprovalData approvalData = new ApprovalData(freeId);
                approvalData.setApprovalid(approvalRequest.generateApprovalId());
                approvalData.setApprovaltype(approvalRequest.getApprovalType());
                approvalData.setEndentityprofileid(approvalRequest.getEndEntityProfileId());        
                approvalData.setCaid(approvalRequest.getCAId());
        		if(approvalRequest.getRequestAdminCert() != null){
        			approvalData.setReqadmincertissuerdn(CertTools.getIssuerDN(approvalRequest.getRequestAdminCert()));
        			approvalData.setReqadmincertsn(CertTools.getSerialNumberAsString(approvalRequest.getRequestAdminCert()));
        		}
        		setApprovalRequest(approvalData, approvalRequest);
        		setApprovals(approvalData, new ArrayList<Approval>());
        		approvalData.setExpiredate((new Date()).getTime() + approvalRequest.getRequestValidity());
        		approvalData.setRemainingapprovals(approvalRequest.getNumOfRequiredApprovals());
                entityManager.persist(approvalData);
                if (gc.getUseApprovalNotifications()) {
                    sendApprovalNotification(admin, gc.getApprovalAdminEmailAddress(), gc.getApprovalNotificationFromAddress(), gc.getBaseUrl()
                            + "adminweb/approval/approveaction.jsf?uniqueId=" + freeId, intres.getLocalizedMessage("notification.newrequest.subject"), intres
                            .getLocalizedMessage("notification.newrequest.msg"), freeId, approvalRequest.getNumOfRequiredApprovals(), new Date(),
                            approvalRequest, null);
                }
                logSession.log(admin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new Date(), null, null,
                        LogConstants.EVENT_INFO_APPROVALREQUESTED, "Approval with id : " + approvalId + " added with status waiting.");
            } catch (Exception e1) {
                logSession.log(admin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new Date(), null, null,
                        LogConstants.EVENT_ERROR_APPROVALREQUESTED, "Approval with id : " + approvalId + " couldn't be created");
                log.error("Error creating approval request", e1);
            }
        }
        log.trace("<addApprovalRequest");
    }

    /**
     * Method used to remove an approval from database.
     * 
     * @param id
     *            , the uniqu id of the approvalrequest, not the same as
     *            approvalId
     * 
     * @throws ApprovalException
     * 
     */
    public void removeApprovalRequest(Admin admin, int id) throws ApprovalException {
        log.trace(">removeApprovalRequest");
        try {
        	ApprovalData ad = ApprovalData.findById(entityManager, Integer.valueOf(id));
        	if (ad != null) {
        		entityManager.remove(ad);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_INFO_APPROVALREQUESTED,
                        "Approval with unique id : " + id + " removed successfully.");
        	} else {
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALREQUESTED,
                        "Error removing approvalrequest with unique id : " + id + ", doesn't exist");
                throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Error removing approvalrequest with unique id : " + id + ", doesn't exist");
        	}
        } catch (Exception e) {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALREQUESTED,
                    "Error removing approvalrequest with unique id : " + id);
            log.error("Error removing approval request", e);
        }
        log.trace("<removeApprovalRequest");
    }

    /**
     * Method used to reject an approval requests.
     * 
     * It does the follwing 1. checks if the approval with the status waiting
     * exists, throws an ApprovalRequestDoesntExistException otherwise
     * 
     * 2. check if the administrator is authorized using the follwing rules: 2.1
     * if getEndEntityProfile is ANY_ENDENTITYPROFILE then check if the admin is
     * authorized to AccessRulesConstants.REGULAR_APPROVECAACTION othervise
     * AccessRulesConstants.REGULAR_APPORVEENDENTITY and APPROVAL_RIGHTS for the
     * end entity profile. 2.2 Checks if the admin is authoried to the approval
     * requests getCAId()
     * 
     * 3. looks upp the username of the administrator and checks that no
     * approval have been made by this user earlier.
     * 
     * 4. Runs the approval command in the end entity bean.
     * 
     * @param gc is the GlobalConfiguration used for notification info
     */
    public void reject(Admin admin, int approvalId, Approval approval, GlobalConfiguration gc) throws ApprovalRequestExpiredException,
            AuthorizationDeniedException, ApprovalException, AdminAlreadyApprovedRequestException {
        log.trace(">reject");
        ApprovalData adl;
        try {
            adl = isAuthorizedBeforeApproveOrReject(admin, approvalId);
        } catch (ApprovalException e1) {
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALREJECTED,
                    "Approval request with id : " + approvalId + " doesn't exists.");
            throw e1;
        }

        checkExecutionPossibility(admin, adl);
        approval.setApprovalAdmin(false, admin);

        try {
            reject(adl, approval);
            if (gc.getUseApprovalNotifications()) {
            	final ApprovalDataVO approvalDataVO = getApprovalDataVO(adl);
                sendApprovalNotification(admin, gc.getApprovalAdminEmailAddress(), gc.getApprovalNotificationFromAddress(), gc.getBaseUrl()
                        + "adminweb/approval/approveaction.jsf?uniqueId=" + adl.getId(), intres.getLocalizedMessage("notification.requestrejected.subject"),
                        intres.getLocalizedMessage("notification.requestrejected.msg"), adl.getId(), approvalDataVO.getRemainingApprovals(),
                        approvalDataVO.getRequestDate(), approvalDataVO.getApprovalRequest(), approval);
            }
            logSession.log(admin, adl.getCaid(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_INFO_APPROVALREJECTED,
                    "Approval request with id : " + approvalId + " have been rejected.");
        } catch (ApprovalRequestExpiredException e) {
            logSession.log(admin, adl.getCaid(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALREJECTED,
                    "Approval request with id : " + approvalId + " have expired.");
            throw e;
        }
        log.trace("<reject");
    }
    
    /** Verifies that an administrator can approve an action, i.e. that it is not the same admin approving the request as made the request originally.
     * An admin is not allowed to approve his/her own actions.
     * 
     * @param admin the administrator that tries to approve the action
     * @param adl the action that the administrator tries to approve
     * @throws AdminAlreadyApprovedRequestException if the admin has already approved the action before
     */
    public void checkExecutionPossibility(Admin admin, ApprovalData adl) throws AdminAlreadyApprovedRequestException{
        // Check that the approvers username doesn't exists among the existing
        // usernames.
        ApprovalDataVO data = getApprovalDataVO(adl);
        String username = admin.getUsername();
        if (data.getReqadmincertissuerdn() != null) {
            // Check that the approver isn't the same as requested the action.
            boolean sameAsRequester = false;
            String requsername = getRequestAdminUsername(adl);
            if(username != null) {
            	if(username.equals(requsername)) {
            		sameAsRequester=true;
            	}
            } else {
            	if(admin.getAdminData().equals(getApprovalRequest(adl).getRequestAdmin().getAdminData())) {
            		sameAsRequester=true;
            	}
            }
            if (sameAsRequester) {
                logSession.log(admin, adl.getCaid(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALREJECTED,
                        "Error administrator have already approved, rejected or requested current request, approveId ");
                throw new AdminAlreadyApprovedRequestException("Error administrator have already approved, rejected or requested current request, approveId : "
                        + /*approvalId*/ adl.getApprovalid());
            }
        }
        //Check that his admin has not approved this this request before
        Iterator<Approval> iter = data.getApprovals().iterator();
        while (iter.hasNext()) {
        	Approval next = iter.next();
            if ((next.getAdmin().getUsername()!=null && username!=null && next.getAdmin().getUsername().equals(username)) || ((next.getAdmin().getUsername()==null || username==null) && admin.getAdminData().equals(next.getAdmin().getAdminData()))) {
                logSession.log(admin, adl.getCaid(), LogConstants.MODULE_APPROVAL, new Date(), null, null, LogConstants.EVENT_ERROR_APPROVALREJECTED,
                        "Error administrator have already approved or rejected current request, approveId ");
                throw new AdminAlreadyApprovedRequestException("Error administrator have already approved or rejected current request, approveId : "
                        + /*approvalId*/ adl.getApprovalid());
            }
        }
    }

    /**
     * Help method for approve and reject.
     */
    public ApprovalData isAuthorizedBeforeApproveOrReject(Admin admin, int approvalId) throws ApprovalException, AuthorizationDeniedException {
        ApprovalData retval = findNonExpiredApprovalDataLocal(approvalId);
        if (retval != null) {
            if (retval.getEndentityprofileid() == ApprovalDataVO.ANY_ENDENTITYPROFILE) {
                if(!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVECAACTION)) {
                    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_APPROVECAACTION, null);
                }
            } else {
                if(!authorizationSession.isAuthorized(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY)) {
                    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_APPROVEENDENTITY, null);
                }
                if(!authorizationSession.isAuthorized(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + retval.getEndentityprofileid()
                        + AccessRulesConstants.APPROVAL_RIGHTS)) {
                    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + retval.getEndentityprofileid()
                            + AccessRulesConstants.APPROVAL_RIGHTS, null);
                }
            }
            if (retval.getCaid() != ApprovalDataVO.ANY_CA) {
                if(!authorizationSession.isAuthorized(admin, AccessRulesConstants.CAPREFIX + retval.getCaid())) {
                    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.CAPREFIX + retval.getCaid(), null);
                }
            }
        } else {
            throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Suitable approval with id : " + approvalId + " doesn't exist");
        }
        return retval;
    }

    /**
     * Method that goes through exists approvals in database to see if there
     * exists any approved action.
     * 
     * If goes through all approvalrequests with the given Id and checks their
     * status, if any have status approved it returns STATUS_APPROVED.
     * 
     * This method should be used by action requiring the requesting
     * administrator to poll to see if it have been approved and only have one
     * step, othervise use the method with the step parameter.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left, 0 if approved othervis is the
     *         ApprovalDataVO.STATUS constants returned indicating the statys.
     * @throws ApprovalException
     *             if approvalId doesn't exists
     * @throws ApprovalRequestExpiredException
     *             Throws this exception one time if one of the approvals have
     *             expired, once notified it wont throw it anymore. But If the
     *             request is multiple steps and user have already performed
     *             that step, the Exception will always be thrown.
     */
    public int isApproved(Admin admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException {
        if (log.isTraceEnabled()) {
            log.trace(">isApproved, approvalId" + approvalId);
        }
        int retval = ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
        Collection<ApprovalData> result = ApprovalData.findByApprovalId(entityManager, approvalId);
        if (result.size() == 0) {
        	throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Approval request with id : " + approvalId + " doesn't exists");
        }
        Iterator<ApprovalData> iter = result.iterator();
        while (iter.hasNext()) {
        	ApprovalData adl = iter.next();
        	retval = isApproved(adl, step);
        	if (adl.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL || adl.getStatus() == ApprovalDataVO.STATUS_APPROVED
        			|| adl.getStatus() == ApprovalDataVO.STATUS_REJECTED) {
        		break;
        	}
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
     * If goes through all approvalrequests with the given Id and checks their
     * status, if any have status approved it returns STATUS_APPROVED.
     * 
     * This method should be used by action requiring the requesting
     * administrator to poll to see if it have been approved and only have one
     * step, othervise use the method with the step parameter.
     * 
     * @param admin
     * @param approvalId
     * @return the number of approvals left, 0 if approved othervis is the
     *         ApprovalDataVO.STATUS constants returned indicating the status.
     * @throws ApprovalException
     *             if approvalId doesn't exists
     * @throws ApprovalRequestExpiredException
     *             Throws this exception one time if one of the approvals have
     *             expired, once notified it wont throw it anymore. But If the
     *             request is multiple steps and user have already performed
     *             that step, the Exception will always be thrown.
     * 
     */
    public int isApproved(Admin admin, int approvalId) throws ApprovalException, ApprovalRequestExpiredException {
        return isApproved(admin, approvalId, 0);
    }

    /**
     * Method that marks a certain step of a a non-executable approval as done.
     * When the last step is performed the approvel is marked as EXPRIED.
     * 
     * @param admin
     * @param approvalId
     * @param step
     *            in approval to mark
     * @throws ApprovalException
     *             if approvalId doesn't exists,
     * 
     */
    public void markAsStepDone(Admin admin, int approvalId, int step) throws ApprovalException, ApprovalRequestExpiredException {
        if (log.isTraceEnabled()) {
            log.trace(">markAsStepDone, approvalId" + approvalId + ", step " + step);
        }
        Collection<ApprovalData> result = ApprovalData.findByApprovalId(entityManager, approvalId);
        Iterator<ApprovalData> iter = result.iterator();
        if (result.size() == 0) {
        	throw new ApprovalException(ErrorCode.APPROVAL_REQUEST_ID_NOT_EXIST, "Approval request with id : " + approvalId + " doesn't exists");
        }
        while (iter.hasNext()) {
        	ApprovalData adl = iter.next();
        	markStepAsDone(adl, step);
        }
        log.trace("<markAsStepDone.");
    }

    /**
     * Method returning an approval requests with status 'waiting', 'Approved'
     * or 'Reject' returns null if no non expired exists
     * 
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public ApprovalDataVO findNonExpiredApprovalRequest(Admin admin, int approvalId) {
        ApprovalDataVO retval = null;
        ApprovalData data = findNonExpiredApprovalDataLocal(approvalId);
        if (data != null) {
            retval = getApprovalDataVO(data);
        }
        return retval;
    }

    private ApprovalData findNonExpiredApprovalDataLocal(int approvalId) {
        ApprovalData retval = null;
        Collection<ApprovalData> result = ApprovalData.findByApprovalIdNonExpired(entityManager, approvalId);
        log.debug("Found number of approvalIdNonExpired: " + result.size());
        Iterator<ApprovalData> iter = result.iterator();
        while (iter.hasNext()) {
        	ApprovalData next = iter.next();
        	ApprovalDataVO data = getApprovalDataVO(next);
        	if (data.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL || data.getStatus() == ApprovalDataVO.STATUS_APPROVED
        			|| data.getStatus() == ApprovalDataVO.STATUS_REJECTED) {
        		retval = next;
        	}
        }
        return retval;
    }

    /**
     * Method that takes an approvalId and returns all approval requests for this.
     * 
     * @param admin
     * @param approvalId
     * @return and collection of ApprovalDataVO, empty if no approvals exists.
     * 
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public Collection<ApprovalDataVO> findApprovalDataVO(Admin admin, int approvalId) {
        log.trace(">findApprovalDataVO");
        ArrayList<ApprovalDataVO> retval = new ArrayList<ApprovalDataVO>();
        Collection<ApprovalData> result = ApprovalData.findByApprovalId(entityManager, approvalId);
        Iterator<ApprovalData> iter = result.iterator();
        while (iter.hasNext()) {
        	ApprovalData adl = iter.next();
        	retval.add(getApprovalDataVO(adl));
        }
        log.trace("<findApprovalDataVO");
        return retval;
    }

    /**
     * Method returning a list of approvals from the give query
     * 
     * @param admin
     * @param query
     *            should be a Query object containing ApprovalMatch and
     *            TimeMatch
     * @param index
     *            where the resultset should start.
     * @param caAuthorizationString
     *            a list of auhtorized CA Ids in the form 'cAId=... OR cAId=...'
     * @param endEntityProfileAuthorizationString
     *            a list of authorized end entity profile ids in the form
     *            '(endEntityProfileId=... OR endEntityProfileId=...) objects
     *            only
     * @return a List of ApprovalDataVO, never null
     * @throws AuthorizationDeniedException
     * @throws IllegalQueryException
     * 
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<ApprovalDataVO> query(Admin admin, Query query, int index, int numberofrows, String caAuthorizationString, String endEntityProfileAuthorizationString)
            throws AuthorizationDeniedException, IllegalQueryException {
        log.trace(">query()");
        String customQuery = "";
        // Check if query is legal.
        if (query != null && !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }
        if (query != null) {
            customQuery += query.getQueryString();
        }
        if (!caAuthorizationString.equals("") && query != null) {
            customQuery += " AND " + caAuthorizationString;
        } else {
            customQuery += caAuthorizationString;
        }
        if (StringUtils.isNotEmpty(endEntityProfileAuthorizationString)) {
            if (caAuthorizationString.equals("") && query == null) {
                customQuery += endEntityProfileAuthorizationString;
            } else {
                customQuery += " AND " + endEntityProfileAuthorizationString;
            }
        }
        final List<ApprovalData> approvalDataList = ApprovalData.findByCustomQuery(entityManager, index, numberofrows, customQuery);
        final List<ApprovalDataVO> returnData = new ArrayList<ApprovalDataVO>(approvalDataList.size());
        for (ApprovalData approvalData : approvalDataList) {
        	returnData.add(getApprovalDataVO(approvalData));
        }
        log.trace("<query()");
        return returnData;
    }

    /**
     * Get a list of all pending approvals ids. This was written for the upgrade
     * to EJBCA 3.10.
     * 
     * @return a List<Integer> with all pending approval ids, never null
     */
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public List<Integer> getAllPendingApprovalIds() {
    	return ApprovalData.findByApprovalIdsByStatus(entityManager, ApprovalDataVO.STATUS_WAITINGFORAPPROVAL);
    }

    public void sendApprovalNotification(Admin admin, String approvalAdminsEmail, String approvalNotificationFromAddress, String approvalURL,
            String notificationSubject, String notificationMsg, Integer id, int numberOfApprovalsLeft, Date requestDate, ApprovalRequest approvalRequest,
            Approval approval) {
        if (log.isTraceEnabled()) {
            log.trace(">sendNotification approval notification: id=" + id);
        }
        try {
            Admin sendAdmin = admin;
            if (admin.getAdminType() == Admin.TYPE_CLIENTCERT_USER) {
                sendAdmin = new ApprovedActionAdmin(admin.getAdminInformation().getX509Certificate(), admin.getUsername(), admin.getEmail());
            }
            Certificate requestAdminCert = approvalRequest.getRequestAdminCert();
            String requestAdminDN = null;
            String requestAdminUsername = null;
            if (requestAdminCert != null) {
                requestAdminDN = CertTools.getSubjectDN(requestAdminCert);
                requestAdminUsername = sendAdmin.getUsername();
            } else {
                requestAdminUsername = intres.getLocalizedMessage("CLITOOL");
                requestAdminDN = "CN=" + requestAdminUsername;
            }
            if (approvalAdminsEmail.equals("") || approvalNotificationFromAddress.equals("")) {
                logSession
                        .log(sendAdmin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(), requestAdminUsername, null,
                                LogConstants.EVENT_ERROR_NOTIFICATION,
                                "Error sending approval notification. The email-addresses, either to approval administrators or from-address isn't configured properly");
            } else {
                String approvalTypeText = intres.getLocalizedMessage(ApprovalDataVO.APPROVALTYPENAMES[approvalRequest.getApprovalType()]);

                String approvalAdminUsername = null;
                String approvalAdminDN = null;
                String approveComment = null;
                if (approval != null) {
                    approvalAdminUsername = approval.getAdmin().getUsername();
                    approvalAdminDN = CertTools.getSubjectDN(approval.getAdmin().getAdminInformation().getX509Certificate());
                    approveComment = approval.getComment();
                }
                Integer numAppr = Integer.valueOf(numberOfApprovalsLeft);
                ApprovalNotificationParamGen paramGen = new ApprovalNotificationParamGen(requestDate, id, approvalTypeText, numAppr, approvalURL,
                        approveComment, requestAdminUsername, requestAdminDN, approvalAdminUsername, approvalAdminDN);
                String subject = paramGen.interpolate(notificationSubject);
                String message = paramGen.interpolate(notificationMsg);
                List<String> toList = Arrays.asList(approvalAdminsEmail);
                if (sendAdmin.getEmail() == null || sendAdmin.getEmail().length() == 0) {
                    logSession.log(sendAdmin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(), requestAdminUsername, null,
                            LogConstants.EVENT_ERROR_NOTIFICATION,
                            "Error sending notification to administrator requesting approval. Set a correct email to the administrator");
                } else {
                    toList = Arrays.asList(approvalAdminsEmail, sendAdmin.getEmail());
                }
                MailSender.sendMailOrThrow(approvalNotificationFromAddress, toList, MailSender.NO_CC, subject, message, MailSender.NO_ATTACHMENTS);
                logSession.log(sendAdmin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(), requestAdminUsername, null,
                        LogConstants.EVENT_INFO_NOTIFICATION, "Approval notification with id " + id + " was sent successfully.");
            }
        } catch (Exception e) {
           log.error("Error when sending notification approving notification", e);
            try {
                logSession.log(admin, approvalRequest.getCAId(), LogConstants.MODULE_APPROVAL, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_NOTIFICATION, "Error sending approval notification with id " + id + ".");
            } catch (Exception f) {
                throw new EJBException(f);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<sendNotification approval notification: id=" + id);
        }
    }

    private Integer findFreeApprovalId() {
        Random ran = new Random((new Date()).getTime());
        int id = ran.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
                if (id > 1) {
                	if (ApprovalData.findByApprovalId(entityManager, id).size() == 0) {
                        foundfree = true;
                	}
                }
                id = ran.nextInt();
        }
        return Integer.valueOf(id);
    }

	/**
	 * Method that rejects an apporval.
	 * After someone have rejected the request noone else can approve it
	 * 
s	 * @throws ApprovalRequestExpiredException 
	 * @throws ApprovalException 
	 */
	private void reject(final ApprovalData approvalData, final Approval approval) throws ApprovalRequestExpiredException,  ApprovalException {
		if(approvalData.haveRequestOrApprovalExpired()){
			throw new ApprovalRequestExpiredException();
		}
		if(approvalData.getStatus() != ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
			throw new ApprovalException("Wrong status of approval request.");
		}
		final int numberofapprovalsleft = approvalData.getRemainingapprovals() -1;
		if(numberofapprovalsleft < 0){
			throw new ApprovalException("Error already enough approvals have been done on this request.");
		}
		approvalData.setRemainingapprovals(0);
		final Collection<Approval> approvals = getApprovals(approvalData);
		approvals.add(approval);
		setApprovals(approvalData, approvals);
		if(getApprovalRequest(approvalData).isExecutable()){
			approvalData.setStatus(ApprovalDataVO.STATUS_EXECUTIONDENIED);
			approvalData.setExpireDate(new Date());    		    		
		}else{
			approvalData.setStatus(ApprovalDataVO.STATUS_REJECTED);
			approvalData.setExpiredate((new Date()).getTime() + getApprovalRequest(approvalData).getApprovalValidity());   		
		}
	} 

	/**
	 * Method used to mark an non-executable approval as done
	 * if the last step is performed will the status be set as
	 * expired.
	 *
	 * @throws ApprovalRequestExpiredException if the step have already been executed
	 */
	private void markStepAsDone(final ApprovalData approvalData, final int step) throws ApprovalRequestExpiredException {
		final ApprovalRequest ar = getApprovalRequest(approvalData);
		if (!ar.isExecutable() && approvalData.getStatus() == ApprovalDataVO.STATUS_APPROVED) {
			if (!ar.isStepDone(step)) {
				ar.markStepAsDone(step);
				setApprovalRequest(approvalData, ar);
				if (step == ar.getNumberOfApprovalSteps()-1) {
					approvalData.setStatus(ApprovalDataVO.STATUS_EXPIRED);
				}
			} else {
				throw new ApprovalRequestExpiredException("Error step " + step + " of approval with id " + approvalData.getApprovalid() + " have alread been performed");
			}
		}
	}

	/**
	 * Method used by the requestadmin to check if an approval request have been approved
	 *
	 * @return the number of approvals left, 0 if approved othervis is the ApprovalDataVO.STATUS constants returned indicating the statys.
	 * @throws ApprovalRequestExpiredException if the request or approval have expired, the status will be EXPIREDANDNOTIFIED in this case. 
	 */
	public int isApproved(final ApprovalData approvalData, final int step) throws ApprovalRequestExpiredException {    	
		if(getApprovalRequest(approvalData).isStepDone(step)){
			return ApprovalDataVO.STATUS_EXPIRED;
		}
		if(approvalData.haveRequestOrApprovalExpired()){
			if(approvalData.getStatus() != ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED &&
					approvalData.getStatus() != ApprovalDataVO.STATUS_EXECUTED &&
					approvalData.getStatus() != ApprovalDataVO.STATUS_EXECUTIONDENIED &&
					approvalData.getStatus() != ApprovalDataVO.STATUS_EXECUTIONFAILED){
				approvalData.setStatus(ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED);
				throw new ApprovalRequestExpiredException();
			}
			return ApprovalDataVO.STATUS_EXPIREDANDNOTIFIED;
		}
		if(approvalData.getStatus() == ApprovalDataVO.STATUS_WAITINGFORAPPROVAL){
			return approvalData.getRemainingapprovals();
		}
		return approvalData.getStatus();
	} 

    /**
     * Method that returns the approval data. This method currently extracts the ApprovalRequest object.
     */
    private String getRequestAdminUsername(final ApprovalData approvalData) {
    	return getApprovalRequest(approvalData).getRequestAdmin().getUsername();
    }

    public ApprovalRequest getApprovalRequest(final ApprovalData approvalData) {
		return ApprovalDataUtil.getApprovalRequest(approvalData.getRequestdata());
	}

	private final void setApprovalRequest(final ApprovalData approvalData, final ApprovalRequest approvalRequest){
		try{
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			final ObjectOutputStream oos = new ObjectOutputStream(baos);
			oos.writeObject(approvalRequest);
			oos.flush();
			approvalData.setRequestdata(new String(Base64.encode(baos.toByteArray(),false)));
		}catch(IOException e){
			log.error("Error building approval request.",e);
			throw new RuntimeException(e);   		
		}
	}

	/** Method that returns the approval data value object. */
	public ApprovalDataVO getApprovalDataVO(ApprovalData approvalData) {
		approvalData.haveRequestOrApprovalExpired();
		return new ApprovalDataVO(approvalData.getId(), approvalData.getApprovalid(), approvalData.getApprovaltype(),
				approvalData.getEndentityprofileid(), approvalData.getCaid(), approvalData.getReqadmincertissuerdn(),
				approvalData.getReqadmincertsn(), approvalData.getStatus(), getApprovals(approvalData), getApprovalRequest(approvalData),
				approvalData.getRequestDate(), approvalData.getExpireDate(), approvalData.getRemainingapprovals());
	}

	public Collection<Approval> getApprovals(ApprovalData approvalData) {   
		return ApprovalDataUtil.getApprovals(approvalData.getApprovaldata());
	}

	/**
	 * Collection of Approval
	 * @param approvals cannot be null.
	 * @throws IOException
	 */
	public void setApprovals(ApprovalData approvalData, final Collection<Approval> approvals){
		try{
			final ByteArrayOutputStream baos = new ByteArrayOutputStream();
			final ObjectOutputStream oos = new ObjectOutputStream(baos);
			final int size = approvals.size();
			oos.writeInt(size);
			final Iterator<Approval> iter = approvals.iterator();
			while(iter.hasNext()){
				final Approval next = iter.next();
				oos.writeObject(next);
			}
			oos.flush();
			approvalData.setApprovaldata(new String(Base64.encode(baos.toByteArray(),false)));
		} catch (IOException e) {
			log.error("Error building approvals.",e);
			throw new RuntimeException(e);
		}
	}
}
