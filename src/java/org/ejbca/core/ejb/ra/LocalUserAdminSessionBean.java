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

package org.ejbca.core.ejb.ra;

import java.awt.print.PrinterException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import javax.ejb.CreateException;
import javax.ejb.DuplicateKeyException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;
import javax.naming.InvalidNameException;

import org.apache.commons.lang.StringUtils;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.approval.IApprovalSessionLocal;
import org.ejbca.core.ejb.approval.IApprovalSessionLocalHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalExecutorUtil;
import org.ejbca.core.model.approval.ApprovalOveradableClassName;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.FieldValidator;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.UserAdminConstants;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataFiller;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.UserNotificationParamGen;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.ICustomNotificationRecipient;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.raadmin.UserNotification;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;
import org.ejbca.util.PrinterManager;
import org.ejbca.util.StringTools;
import org.ejbca.util.dn.DistinguishedName;
import org.ejbca.util.dn.DnComponents;
import org.ejbca.util.mail.MailSender;
import org.ejbca.util.query.BasicMatch;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;

/**
 * Administrates users in the database using UserData Entity Bean.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id$
 * 
 * @ejb.bean
 *   display-name="UserAdminSB"
 *   name="UserAdminSession"
 *   jndi-name="UserAdminSession"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 *
 * @ejb.env-entry
 *  name="DataSource"
 *  type="java.lang.String"
 *  value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ra.IUserAdminSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ra.IUserAdminSessionRemote"
 *   
 * @ejb.ejb-external-ref
 *   description="The Certificate Store session bean"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Authorization session bean"
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
 *   description="The Key Recovery session bean"
 *   view-type="local"
 *   ref-name="ejb/KeyRecoverySessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome"
 *   business="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal"
 *   link="KeyRecoverySession"
 *   
 * @ejb.ejb-external-ref description="The Approval Session Bean"
 *   view-type="local"
 *   ref-name="ejb/ApprovalSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.approval.IApprovalSessionLocalHome"
 *   business="org.ejbca.core.ejb.approval.IApprovalSessionLocal"
 *   link="ApprovalSession"
 *   
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The User entity bean"
 *   view-type="local"
 *   ref-name="ejb/UserDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ra.UserDataLocalHome"
 *   business="org.ejbca.core.ejb.ra.UserDataLocal"
 *   link="UserData"
 *
 * @ejb.resource-ref
 *   res-ref-name="mail/DefaultMail"
 *   res-type="javax.mail.Session"
 *   res-auth="Container"
 *
 * @weblogic.resource-description
 *   res-ref-name="mail/DefaultMail"
 *   jndi-name="EjbcaMail"
 * 
 * @jboss.method-attributes
 *   pattern = "find*"
 *   read-only = "true"
 *   
 * @jboss.method-attributes
 *   pattern = "check*"
 *   read-only = "true"
 *   
 */
public class LocalUserAdminSessionBean extends BaseSessionBean {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /**
     * The local interface of RaAdmin Session Bean.
     */
    private IRaAdminSessionLocal raadminsession;

    /**
     * The local interface of the certificate store session bean
     */
    private ICertificateStoreSessionLocal certificatesession;

    /**
     * The local interface of the authorization session bean
     */
    private IAuthorizationSessionLocal authorizationsession;

    /**
     * The local interface of the authorization session bean
     */
    private IKeyRecoverySessionLocal keyrecoverysession;
    
    /**
     * The local interface of the caadmin session bean
     */
    private ICAAdminSessionLocal caadminsession;
    
    /**
     * The local interface of the certificatestore session bean
     */
    private ICertificateStoreSessionLocal certificatestoresession;
    
    /**
     * The local interface of the approval session bean
     */
    private IApprovalSessionLocal approvalsession;

    /**
     * The remote interface of the log session bean
     */
    private ILogSessionLocal logsession;

    private UserDataLocalHome home = null;
    /**
     * Columns in the database used in select
     */
    private static final String USERDATA_COL = "username, subjectDN, subjectAltName, subjectEmail, status, type, clearPassword, timeCreated, timeModified, endEntityProfileId, certificateProfileId, tokenType, hardTokenIssuerId, cAId, extendedInformationData, cardnumber";
    private static final String USERDATA_CREATED_COL = "timeCreated";

    /**
     * Default create for SessionBean.
     *
     * @throws CreateException if bean instance can't be created
     * @see org.ejbca.core.model.log.Admin
     */
    public void ejbCreate() throws CreateException {
        try {
            home = (UserDataLocalHome) getLocator().getLocalHome(UserDataLocalHome.COMP_NAME);

            ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
            logsession = logsessionhome.create();

            IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) getLocator().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
            authorizationsession = authorizationsessionhome.create();

            IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) getLocator().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
            raadminsession = raadminsessionhome.create();

            ICertificateStoreSessionLocalHome certificatesessionhome = (ICertificateStoreSessionLocalHome) getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
            certificatesession = certificatesessionhome.create();
            
            
            ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
            caadminsession = caadminsessionhome.create();
            

        } catch (Exception e) {
            error("Error creating session bean:", e);
            throw new EJBException(e);
        }

    }
    
    private IApprovalSessionLocal getApprovalSession(){
      if(approvalsession == null){
          try {
            IApprovalSessionLocalHome approvalsessionhome = (IApprovalSessionLocalHome) getLocator().getLocalHome(IApprovalSessionLocalHome.COMP_NAME);
			approvalsession = approvalsessionhome.create();
		} catch (CreateException e) {
			throw new EJBException(e);
		}  
      }
      return approvalsession;
    }

    private IKeyRecoverySessionLocal getKeyRecoverySession(){
        if(keyrecoverysession == null){
            try {
            	IKeyRecoverySessionLocalHome keyrecoverysessionhome = (IKeyRecoverySessionLocalHome) getLocator().getLocalHome(IKeyRecoverySessionLocalHome.COMP_NAME);
                keyrecoverysession = keyrecoverysessionhome.create();
  		} catch (CreateException e) {
  			throw new EJBException(e);
  		}  
        }
        return keyrecoverysession;
      }

    
    /**
     * Gets the Global Configuration from ra admin session bean-
     */
    private GlobalConfiguration getGlobalConfiguration(Admin admin) {
        return raadminsession.loadGlobalConfiguration(admin);
    }

    private boolean authorizedToCA(Admin admin, int caid) {
        boolean returnval = false;
        try {
            returnval = authorizationsession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid);
        } catch (AuthorizationDeniedException e) {
        	log.info(e.getMessage()); // be sure to log the full real resource we are denied
        }
        return returnval;
    }

    private boolean authorizedToEndEntityProfile(Admin admin, int profileid, String rights) {
        boolean returnval = false;
        try {
            if (profileid == SecConst.EMPTY_ENDENTITYPROFILE && (rights.equals(AccessRulesConstants.CREATE_RIGHTS) || rights.equals(AccessRulesConstants.EDIT_RIGHTS))) {
                returnval = authorizationsession.isAuthorizedNoLog(admin, "/super_administrator");
            } else {
                returnval = authorizationsession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + profileid + rights) &&
                            authorizationsession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
            }
        } catch (AuthorizationDeniedException e) {
        	log.info(e.getMessage()); // be sure to log the full real resource we are denied
        }
        return returnval;
    }


    /**
     * Implements IUserAdminSession::addUser.
     * Implements a mechanism that uses UserDataEntity Bean.
     * 
     * Important, this method is old and shouldn't be used, user addUser(..UserDataVO...) instead.
     *
     * @param admin                 the administrator pwrforming the action
     * @param username              the unique username.
     * @param password              the password used for authentication.
     * @param subjectdn             the DN the subject is given in his certificate.
     * @param subjectaltname        the Subject Alternative Name to be used.
     * @param email                 the email of the subject or null.
     * @param clearpwd              true if the password will be stored in clear form in the db, otherwise it is
     *                              hashed.
     * @param endentityprofileid    the id number of the end entity profile bound to this user.
     * @param certificateprofileid  the id number of the certificate profile that should be
     *                              generated for the user.
     * @param type                  of user i.e administrator, keyrecoverable and/or sendnotification, from SecConst.USER_XX.
     * @param tokentype             the type of token to be generated, one of SecConst.TOKEN constants
     * @param hardwaretokenissuerid , if token should be hard, the id of the hard token issuer,
     *                              else 0.
     * @param caid					the CA the user should be issued from.
     * @throws WaitingForApprovalException 
     * @throws UserDoesntFullfillEndEntityProfile 
     * @throws AuthorizationDeniedException 
     * @throws DuplicateKeyException 
     * @throws EjbcaException 
     * @ejb.interface-method
     */
    public void addUser(Admin admin, String username, String password, String subjectdn, String subjectaltname, String email, boolean clearpwd, int endentityprofileid, int certificateprofileid,
                        int type, int tokentype, int hardwaretokenissuerid, int caid) throws DuplicateKeyException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException {
    	
    	UserDataVO userdata = new UserDataVO(username, subjectdn, caid, subjectaltname, 
    			                             email, UserDataConstants.STATUS_NEW, type, endentityprofileid, certificateprofileid,
    			                             null,null, tokentype, hardwaretokenissuerid, null);
    	userdata.setPassword(password);
    	addUser(admin, userdata, clearpwd);
    }

	private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_ADDUSER = {
		new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest.class.getName(),null),
	};
	/**
     * addUserFromWS is called from EjbcaWS
     * if profile specifies merge data from profile to user we merge them before calling addUser
     *
     * @param admin                 the administrator pwrforming the action
     * @param userdata 	            a UserDataVO object, the fields status, timecreated and timemodified will not be used.
     * @param clearpwd              true if the password will be stored in clear form in the db, otherwise it is
     *                              hashed.
     * @throws AuthorizationDeniedException if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile if data doesn't fullfil requirements of end entity profile 
     * @throws DuplicateKeyException if user already exists
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.  
	 * @throws EjbcaException with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the SubjectDN Serialnumber already exists when it is specified in the CA that it should be unique.
     * 
     * @ejb.interface-method
     */
	public void addUserFromWS(Admin admin, UserDataVO userdata, boolean clearpwd) throws AuthorizationDeniedException,
			UserDoesntFullfillEndEntityProfile, DuplicateKeyException,
			WaitingForApprovalException, EjbcaException {
		int profileId = userdata.getEndEntityProfileId();
		EndEntityProfile profile = raadminsession.getEndEntityProfile(admin,profileId);
		if (profile.getAllowMergeDnWebServices()) {
			userdata = UserDataFiller.fillUserDataWithDefaultValues(userdata,profile);
		}	
		addUser(admin, userdata, clearpwd);
	}
    /**
     * Implements IUserAdminSession::addUser.
     * Implements a mechanism that uses UserDataEntity Bean. 
     *
     * @param admin                 the administrator pwrforming the action
     * @param userdata 	            a UserDataVO object, the fields status, timecreated and timemodified will not be used.
     * @param clearpwd              true if the password will be stored in clear form in the db, otherwise it is
     *                              hashed.
     * @throws AuthorizationDeniedException if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile if data doesn't fullfil requirements of end entity profile 
     * @throws DuplicateKeyException if user already exists
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.  	
	 * @throws EjbcaException with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the SubjectDN Serialnumber already exists when it is specified in the CA that it should be unique.
     * @ejb.interface-method
     */
    public void addUser(Admin admin, UserDataVO userdata, boolean clearpwd) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, DuplicateKeyException, WaitingForApprovalException, EjbcaException {
        try {
			FieldValidator.validate(userdata, userdata.getEndEntityProfileId(), raadminsession.getEndEntityProfileName(admin, userdata.getEndEntityProfileId()));
		} catch (CustomFieldException e1) {
			throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, e1.getMessage(), e1);
		}
        String dn = CertTools.stringToBCDNString(StringTools.strip(userdata.getDN()));
    	String altName = StringTools.strip(userdata.getSubjectAltName());
    	String username = StringTools.strip(userdata.getUsername());
    	String email = StringTools.strip(userdata.getEmail());
    	userdata.setUsername(username);
    	userdata.setDN(dn);
    	userdata.setSubjectAltName(altName);
    	userdata.setEmail(email);
        int type = userdata.getType();
        String newpassword = userdata.getPassword();
        int profileId = userdata.getEndEntityProfileId();
        if (log.isTraceEnabled()) {
            log.trace(">addUser(" + userdata.getUsername() + ", password, " + dn + ", "+ userdata.getDN() + ", " + userdata.getSubjectAltName()+", "+userdata.getEmail() + ", profileId: "+profileId+")");
        }
        String profileName = raadminsession.getEndEntityProfileName(admin, profileId);
        EndEntityProfile profile = raadminsession.getEndEntityProfile(admin, profileId);
        

        if (profile.useAutoGeneratedPasswd() && userdata.getPassword() == null) {
            // special case used to signal regeneraton of password
            newpassword = profile.getAutoGeneratedPasswd();
        }


        if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
            // Check if user fulfills it's profile.
            try {
                profile.doesUserFullfillEndEntityProfile(userdata.getUsername(), userdata.getPassword(), dn, userdata.getSubjectAltName(), userdata.getExtendedinformation().getSubjectDirectoryAttributes(), userdata.getEmail(), userdata.getCertificateProfileId(), clearpwd,
                        (type & SecConst.USER_KEYRECOVERABLE) != 0, (type & SecConst.USER_SENDNOTIFICATION) != 0,
                        userdata.getTokenType(), userdata.getHardTokenIssuerId(), userdata.getCAId(), userdata.getExtendedinformation());
            } catch (UserDoesntFullfillEndEntityProfile udfp) {
                String msg = intres.getLocalizedMessage("ra.errorfullfillprofile", profileName, dn, udfp.getMessage());            	
                logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_ERROR_ADDEDENDENTITY, msg);
                throw new UserDoesntFullfillEndEntityProfile(udfp.getMessage());
            }

            // Check if administrator is authorized to add user.
            if (!authorizedToEndEntityProfile(admin, userdata.getEndEntityProfileId(), AccessRulesConstants.CREATE_RIGHTS)) {
                String msg = intres.getLocalizedMessage("ra.errorauthprofile", profileName);            	
                logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_ERROR_ADDEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }

        // Check if administrator is authorized to add user to CA.
        if (!authorizedToCA(admin, userdata.getCAId())) {
            String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(userdata.getCAId()));            	
            logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_ERROR_ADDEDENDENTITY, msg);
            throw new AuthorizationDeniedException(msg);
        }

        // Check if approvals is required.
        int numOfApprovalsRequired = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_ADDEDITENDENTITY, userdata.getCAId(), userdata.getCertificateProfileId());
        AddEndEntityApprovalRequest ar = new AddEndEntityApprovalRequest(userdata,clearpwd,admin,null,numOfApprovalsRequired,userdata.getCAId(),userdata.getEndEntityProfileId());
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_ADDUSER)) {       		    		
        	getApprovalSession().addApprovalRequest(admin, ar, getGlobalConfiguration(admin));
            String msg = intres.getLocalizedMessage("ra.approvalad");            	
        	throw new WaitingForApprovalException(msg);
        }
        
        // Check if the subjectDN serialnumber already exists.
        if(caadminsession.getCAInfoOrThrowException(admin, userdata.getCAId()).isDoEnforceUniqueSubjectDNSerialnumber()){
            String serialnumber = getSerialnumber(userdata.getDN());
            if(serialnumber != null){
            	if(!serialnumberIsUnique(admin, userdata.getCAId(), serialnumber)){
   		 			throw new EjbcaException(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, "Error: SubjectDN Serialnumber already exists.");
            	}
            }
        }    
        
        try {
            UserDataLocal data1 = home.create(userdata.getUsername(), newpassword, dn, userdata.getCAId(), userdata.getCardNumber());
            if (userdata.getSubjectAltName() != null) {
                data1.setSubjectAltName(userdata.getSubjectAltName());
            }
            if (userdata.getEmail() != null) {
                data1.setSubjectEmail(userdata.getEmail());
            }
            data1.setType(type);
            data1.setEndEntityProfileId(userdata.getEndEntityProfileId());
            data1.setCertificateProfileId(userdata.getCertificateProfileId());
            data1.setTokenType(userdata.getTokenType());
            data1.setHardTokenIssuerId(userdata.getHardTokenIssuerId());
            data1.setExtendedInformation(userdata.getExtendedinformation());

            if (clearpwd) {
                try {
                    if (newpassword == null) {
                        data1.setClearPassword("");
                    } else {
                        data1.setOpenPassword(newpassword);
                    }
                } catch (java.security.NoSuchAlgorithmException nsae) {
                    debug("NoSuchAlgorithmException while setting password for user " + userdata.getUsername());
                    throw new EJBException(nsae);
                }
            }
            
            // Although UserDataVO should always have a null password for autogenerated end entities, the notification framework
            // expect it to exist. Since nothing else but printing is done after this point it is safe to set the password
            userdata.setPassword(newpassword);
            // Send notifications, if they should be sent
            sendNotification(admin, userdata, UserDataConstants.STATUS_NEW);
            
            if ((type & SecConst.USER_PRINT) != 0) {
            	print(admin,profile,userdata);
            }
            String msg = intres.getLocalizedMessage("ra.addedentity", userdata.getUsername());            	
            logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_INFO_ADDEDENDENTITY, msg);

        } catch (DuplicateKeyException e) {
            String msg = intres.getLocalizedMessage("ra.errorentityexist", userdata.getUsername());            	
            logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_ERROR_ADDEDENDENTITY, msg);
            throw e;
        } catch (CreateException e) {
            String msg = intres.getLocalizedMessage("ra.errorentityexist", userdata.getUsername());            	
            logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_ERROR_ADDEDENDENTITY, msg);
            throw new DuplicateKeyException(e.getMessage());
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("ra.erroraddentity", userdata.getUsername());            	
            logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_ERROR_ADDEDENDENTITY, msg, e);
            error(msg, e);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<addUser(" + userdata.getUsername() + ", password, " + dn + ", " + userdata.getEmail() + ")");
        }
    } // addUser
    
    private String getSerialnumber(String subjectDN){
    	String elements[] = subjectDN.split(",");
    	for(int i=0; i<elements.length; i++){
    		if(elements[i].trim().startsWith("SN=")){
    			String parts[] = elements[i].split("=");
    			if(parts.length == 2){
    				return parts[1];
    			} else {
    				return null;
    			}
    		}
    	}
    	return null;
    }
    
    private boolean serialnumberIsUnique(Admin admin, int caid, String serialnumber) {
    	UserDataVO user = null;
    	String sn = null;
    	Iterator itr = findAllUsersByCaId(admin, caid).iterator();
    	while(itr.hasNext()){
    		user = (UserDataVO) itr.next();
    		sn = getSerialnumber(user.getDN());
    		if(sn != null){
    			if(sn.equals(serialnumber)) {
    				return false;
    			}
    		}
    	}
    	return true;
    }

    /**
     * Help method that checks the CA data config if specified action 
     * requires approvals and how many
     * @param action one of CAInfo.REQ_APPROVAL_ constants
     * @param caid of the ca to check
     * @param certprofileid of the certificate profile to check
     * @return 0 of no approvals is required or no such CA exists, othervise the number of approvals
     */
    private int getNumOfApprovalRequired(Admin admin,int action, int caid, int certprofileid) {
    	return caadminsession.getNumOfApprovalRequired(admin, action, caid, certprofileid);
	}
    
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
     * Changes data for a user in the database speciefied by username.
     * 
     * Important, this method is old and shouldn't be used, user changeUser(..UserDataVO...) instead.
     *
     * @param username              the unique username.
     * @param password              the password used for authentication.*
     * @param subjectdn             the DN the subject is given in his certificate.
     * @param subjectaltname        the Subject Alternative Name to be used.
     * @param email                 the email of the subject or null.
     * @param endentityprofileid    the id number of the end entity profile bound to this user.
     * @param certificateprofileid  the id number of the certificate profile that should be generated for the user.
     * @param type                  of user i.e administrator, keyrecoverable and/or sendnotification
     * @param tokentype             the type of token to be generated, one of SecConst.TOKEN constants
     * @param hardwaretokenissuerid if token should be hard, the id of the hard token issuer, else 0.
     * @param status 				the status of the user, from UserDataConstants.STATUS_X
     * @param caid                  the id of the CA that should be used to issue the users certificate
     * 
     * @throws AuthorizationDeniedException if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile if data doesn't fullfil requirements of end entity profile 
     * @throws ApprovalException if an approval already is waiting for specified action 
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.
	 * @throws EjbcaException with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the SubjectDN Serialnumber already exists when it is specified in the CA that it should be unique.
     * @throws EJBException if a communication or other error occurs.
     * 
     * @deprecated use {@link #changeUser(Admin, UserDataVO, boolean)} instead
     * 
     * @ejb.interface-method
     */
    public void changeUser(Admin admin, String username, String password, String subjectdn, String subjectaltname, String email, boolean clearpwd, int endentityprofileid, int certificateprofileid,
            int type, int tokentype, int hardwaretokenissuerid, int status, int caid)
throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException {
    	UserDataVO userdata = new UserDataVO(username, subjectdn, caid, subjectaltname, 
                email, status, type, endentityprofileid, certificateprofileid,
                null,null, tokentype, hardwaretokenissuerid, null);
        
    	userdata.setPassword(password);
        changeUser(admin, userdata, clearpwd);    	
    }

	private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_CHANGEUSER = {
		new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest.class.getName(),null),
		/** can not use .class.getName() below, because it is not part of base EJBCA dist */
		new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
	};

	/**
     * Implements IUserAdminSession::changeUser.. 
     *
     * @param admin                 the administrator performing the action
     * @param userdata 	            a UserDataVO object,  timecreated and timemodified will not be used.
     * @param clearpwd              true if the password will be stored in clear form in the db, otherwise it is
     *                              hashed.
     *                              
     * @throws AuthorizationDeniedException if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile if data doesn't fullfil requirements of end entity profile 
     * @throws ApprovalException if an approval already is waiting for specified action 
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.
	 * @throws EjbcaException with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the SubjectDN Serialnumber already exists when it is specified in the CA that it should be unique.
     * @ejb.interface-method
     */
    public void changeUser(Admin admin, UserDataVO userdata, boolean clearpwd)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException {
    	changeUser(admin, userdata,clearpwd, false);
    }
	/**
     * Implements IUserAdminSession::changeUser.. 
     *
     * @param admin                 the administrator performing the action
     * @param userdata 	            a UserDataVO object,  timecreated and timemodified will not be used.
     * @param clearpwd              true if the password will be stored in clear form in the db, otherwise it is
     *                              hashed.
     * @param fromWebService    	The service is called from webService
     *                              
     * @throws AuthorizationDeniedException if administrator isn't authorized to add user
     * @throws UserDoesntFullfillEndEntityProfile if data doesn't fullfil requirements of end entity profile 
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.
	 * @throws EjbcaException with ErrorCode "SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS" if the SubjectDN Serialnumber already exists when it is specified in the CA that it should be unique.
     * @throws EJBException if the user does not exist
	 *
     * @ejb.interface-method
     */
    public void changeUser(Admin admin, UserDataVO userdata, boolean clearpwd, boolean fromWebService)
            throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException {
        try {
			FieldValidator.validate(userdata, userdata.getEndEntityProfileId(), raadminsession.getEndEntityProfileName(admin, userdata.getEndEntityProfileId()));
		} catch (CustomFieldException e1) {
			throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, e1.getMessage(), e1);
		}
        String dn = CertTools.stringToBCDNString(StringTools.strip(userdata.getDN()));
        String altName = userdata.getSubjectAltName();    
        String newpassword = userdata.getPassword();
        int type = userdata.getType();
        if (log.isTraceEnabled()) {
            log.trace(">changeUser(" + userdata.getUsername() + ", " + dn + ", " + userdata.getEmail() + ")");
        }
        int oldstatus;
        EndEntityProfile profile = raadminsession.getEndEntityProfile(admin, userdata.getEndEntityProfileId());
        UserDataPK pk = new UserDataPK(userdata.getUsername());
		UserDataLocal userDataLocal = null;
		try {
			userDataLocal = home.findByPrimaryKey(pk);
		} catch (Exception e) {
			String msg = intres.getLocalizedMessage("ra.erroreditentity", userdata.getUsername());
			logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
			error("ChangeUser:", e);
			throw new EJBException(e);
		}

        // if required, we merge the existing user dn into the dn provided by the web service.
        if (fromWebService && profile.getAllowMergeDnWebServices()) {

			if (userDataLocal != null) {
                if (userDataLocal.getSubjectDN() != null) {
                    Map dnMap = new HashMap();
                    if (profile.getUse(DnComponents.DNEMAIL, 0)) {
                        dnMap.put(DnComponents.DNEMAIL, userdata.getEmail());
                    }
                    try {
                        dn = (new DistinguishedName(userDataLocal.getSubjectDN())).mergeDN(new DistinguishedName(dn), true, dnMap).toString();
                    } catch (InvalidNameException e) {
                        log.debug("Invalid dn. We make it empty");
                        dn = "";
                    }
                }
				if (userDataLocal.getSubjectAltName() != null) {
                    Map dnMap = new HashMap();
                    if (profile.getUse(DnComponents.RFC822NAME, 0)) {
                        dnMap.put(DnComponents.RFC822NAME, userdata.getEmail());
                    }
					try {
						//SubjectAltName is not mandatory so
						if(altName==null) {
							altName="";
						}
						altName = (new DistinguishedName(userDataLocal.getSubjectAltName()))
                             .mergeDN(new DistinguishedName(altName), true, dnMap).toString();
					} catch (InvalidNameException e) {
						log.debug("Invalid altName. We make it empty");
						altName = "";
					}
				}
			}
		}
        if (profile.useAutoGeneratedPasswd() && userdata.getPassword() != null) {
            // special case used to signal regeneraton of password
            newpassword = profile.getAutoGeneratedPasswd();
        }

        // Check if user fulfills it's profile.
        if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
            try {
                profile.doesUserFullfillEndEntityProfileWithoutPassword(userdata.getUsername(), dn, altName, userdata.getExtendedinformation().getSubjectDirectoryAttributes(), userdata.getEmail(), userdata.getCertificateProfileId(),
                        (type & SecConst.USER_KEYRECOVERABLE) != 0, (type & SecConst.USER_SENDNOTIFICATION) != 0,
                        userdata.getTokenType(), userdata.getHardTokenIssuerId(), userdata.getCAId(), userdata.getExtendedinformation());
            } catch (UserDoesntFullfillEndEntityProfile udfp) {
                String msg = intres.getLocalizedMessage("ra.errorfullfillprofile", new Integer(userdata.getEndEntityProfileId()), dn, udfp.getMessage());            	
                logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw udfp;
            }
            // Check if administrator is authorized to edit user.
            if (!authorizedToEndEntityProfile(admin, userdata.getEndEntityProfileId(), AccessRulesConstants.EDIT_RIGHTS)) {
                String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(userdata.getEndEntityProfileId()));            	
                logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }

        // Check if administrator is authorized to edit user to CA.
        if (!authorizedToCA(admin, userdata.getCAId())) {
            String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(userdata.getCAId()));            	
            logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw new AuthorizationDeniedException(msg);
        }
        // Check if approvals is required.
        int numOfApprovalsRequired = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_ADDEDITENDENTITY, userdata.getCAId(), userdata.getCertificateProfileId());
        if (numOfApprovalsRequired > 0){
        	UserDataVO orguserdata = userDataLocal.toUserDataVO();
        	EditEndEntityApprovalRequest ar = new EditEndEntityApprovalRequest(userdata, clearpwd, orguserdata, admin,null,numOfApprovalsRequired,userdata.getCAId(),userdata.getEndEntityProfileId());
        	if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_CHANGEUSER)){       		    		
        		getApprovalSession().addApprovalRequest(admin, ar, getGlobalConfiguration(admin));
        		String msg = intres.getLocalizedMessage("ra.approvaledit");            	
        		throw new WaitingForApprovalException(msg);
        	}
        }
        
        // Check if the subjectDN serialnumber already exists.
        if(caadminsession.getCAInfoOrThrowException(admin, userdata.getCAId()).isDoEnforceUniqueSubjectDNSerialnumber()){
            String serialnumber = getSerialnumber(userdata.getDN());
            if(serialnumber != null){
				if(!serialnumberIsUnique(admin, userdata.getCAId(), serialnumber)){
					throw new EjbcaException(ErrorCode.SUBJECTDN_SERIALNUMBER_ALREADY_EXISTS, "Error: SubjectDN Serialnumber already exists.");
				}
            }
        }
        
        try {
        	userDataLocal.setDN(dn);
        	userDataLocal.setSubjectAltName(altName);
        	userDataLocal.setSubjectEmail(userdata.getEmail());
        	userDataLocal.setCaId(userdata.getCAId());
        	userDataLocal.setType(type);
        	userDataLocal.setEndEntityProfileId(userdata.getEndEntityProfileId());
        	userDataLocal.setCertificateProfileId(userdata.getCertificateProfileId());
        	userDataLocal.setTokenType(userdata.getTokenType());
        	userDataLocal.setHardTokenIssuerId(userdata.getHardTokenIssuerId());
        	userDataLocal.setCardNumber(userdata.getCardNumber());
            ExtendedInformation ei = userdata.getExtendedinformation();
            userDataLocal.setExtendedInformation(ei);
            oldstatus = userDataLocal.getStatus();
            if(oldstatus == UserDataConstants.STATUS_KEYRECOVERY && !(userdata.getStatus() == UserDataConstants.STATUS_KEYRECOVERY || userdata.getStatus() == UserDataConstants.STATUS_INPROCESS)){
              getKeyRecoverySession().unmarkUser(admin,userdata.getUsername());	
            }
            String requestCounter = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
    		if ( StringUtils.equals(requestCounter, "0") && (userdata.getStatus() == UserDataConstants.STATUS_NEW) && (oldstatus != UserDataConstants.STATUS_NEW) ) {
                // If status is set to new, we should re-set the allowed request counter to the default values
    			// But we only do this if no value is specified already, i.e. 0 or null
    			resetRequestCounter(admin, userDataLocal, false);
    		} else {
    			// If status is not new, we will only remove the counter if the profile does not use it
    			resetRequestCounter(admin, userDataLocal, true);    			
    		}
    		userDataLocal.setStatus(userdata.getStatus());
            if(newpassword != null){
                if(clearpwd) {
                    try {
                    	userDataLocal.setOpenPassword(newpassword);
                    } catch (java.security.NoSuchAlgorithmException nsae) {
                        debug("NoSuchAlgorithmException while setting password for user "+userdata.getUsername());
                        throw new EJBException(nsae);
                    }
                } else {
                	userDataLocal.setPassword(newpassword);
                }
            }
            // We want to create this object before re-setting the time modified, because we may want to 
            // Use the old time modified in any notifications
            UserDataVO udata = userDataLocal.toUserDataVO();
            userDataLocal.setTimeModified((new java.util.Date()).getTime());

        	// We also want to be able to handle non-clear generated passwords in the notifiction, although UserDataVO
            // should always have a null password for autogenerated end entities the notification framework expects it to
            // exist.
            if (newpassword != null) {
                udata.setPassword(newpassword);
            }
            // Send notification if it should be sent. 
            sendNotification(admin, udata, userdata.getStatus());
            
            boolean statuschanged = userdata.getStatus() != oldstatus;
            // Only print stuff on a printer on the same conditions as for notifications, we also only print if the status changes, not for every time we press save
            if ((type & SecConst.USER_PRINT) != 0 && statuschanged && (userdata.getStatus() == UserDataConstants.STATUS_NEW || userdata.getStatus() == UserDataConstants.STATUS_KEYRECOVERY || userdata.getStatus() == UserDataConstants.STATUS_INITIALIZED)) {
            	print(admin,profile,userdata);
            }
            if (statuschanged) {
                String msg = intres.getLocalizedMessage("ra.editedentitystatus", userdata.getUsername(), new Integer(userdata.getStatus()));            	
                logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg );
            } else {
                String msg = intres.getLocalizedMessage("ra.editedentity", userdata.getUsername());            	
                logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("ra.erroreditentity", userdata.getUsername());            	
            logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), userdata.getUsername(), null, LogConstants.EVENT_ERROR_CHANGEDENDENTITY, msg);
            error("ChangeUser:", e);
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changeUser(" + userdata.getUsername() + ", password, " + dn + ", " + userdata.getEmail() + ")");
        }
    } // changeUser


    /**
     * Deletes a user from the database. The users certificates must be revoked BEFORE this method is called.
     *
     * @param username the unique username.
     * @throws NotFoundException if the user does not exist
     * @throws RemoveException   if the user could not be removed
     * @ejb.interface-method
     */
    public void deleteUser(Admin admin, String username) throws AuthorizationDeniedException, NotFoundException, RemoveException {
        if (log.isTraceEnabled()) {
            log.trace(">deleteUser(" + username + ")");
        }
        // Check if administrator is authorized to delete user.
        int caid = LogConstants.INTERNALCAID;
        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);
            caid = data1.getCaId();

            if (!authorizedToCA(admin, caid)) {
                String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_DELETEENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }

            if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
                if (!authorizedToEndEntityProfile(admin, data1.getEndEntityProfileId(), AccessRulesConstants.DELETE_RIGHTS)) {
                    String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data1.getEndEntityProfileId()));            	
                    logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_DELETEENDENTITY, msg);
                    throw new AuthorizationDeniedException(msg);
                }
            }
        } catch (FinderException e) {
            String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_DELETEENDENTITY, msg);
            throw new NotFoundException(msg);
        }
        try {
            UserDataPK pk = new UserDataPK(username);
            home.remove(pk);
            String msg = intres.getLocalizedMessage("ra.removedentity", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_DELETEDENDENTITY, msg);
        } catch (EJBException e) {
            String msg = intres.getLocalizedMessage("ra.errorremoveentity", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_DELETEENDENTITY, msg);
            throw new RemoveException(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<deleteUser(" + username + ")");
        }
    } // deleteUser

	private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_SETUSERSTATUS = {
		new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.ChangeStatusEndEntityApprovalRequest.class.getName(),null),
		new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.LocalUserAdminSessionBean.class.getName(),"revokeUser"),
		new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.LocalUserAdminSessionBean.class.getName(),"revokeCert"),
		new ApprovalOveradableClassName(org.ejbca.core.ejb.ca.auth.LocalAuthenticationSessionBean.class.getName(),"finishUser"),
		new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.LocalUserAdminSessionBean.class.getName(),"unrevokeCert"),
		new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.LocalUserAdminSessionBean.class.getName(),"prepareForKeyRecovery"),
		/** can not use .class.getName() below, because it is not part of base EJBCA dist */
		new ApprovalOveradableClassName("org.ejbca.extra.caservice.ExtRACAProcess","processExtRARevocationRequest"),
		new ApprovalOveradableClassName("se.primeKey.cardPersonalization.ra.connection.ejbca.EjbcaConnection",null)
	};
    
	/**
	 * Resets the remaining failed login attempts counter to the user's max login attempts value.  
	 * @param admin the administrator performing the action
     * @param username the unique username of the user
	 * @throws AuthorizationDeniedException if administrator isn't authorized to edit user
	 * @throws FinderException if the entity does not exist
	 * @ejb.interface-method
	 */
	public void resetRemainingLoginAttempts(Admin admin, String username) throws AuthorizationDeniedException, FinderException {
		if (log.isTraceEnabled()) {
            log.trace(">resetRamainingLoginAttempts(" + username + ")");
        }
		int resetValue = -1;
        int caid = LogConstants.INTERNALCAID;
        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);
            caid = data1.getCaId();
            if (!authorizedToCA(admin, caid)) {
                String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
            
            ExtendedInformation ei = data1.getExtendedInformation();
        	if (ei == null) {
        		ei = new ExtendedInformation();
        		data1.setExtendedInformation(ei);
        	}
        		
    		resetValue = ei.getMaxLoginAttempts();
    		
    		if(resetValue != -1 || ei.getRemainingLoginAttempts() != -1) {
    			ei.setRemainingLoginAttempts(resetValue);
				data1.setExtendedInformation(ei);
				data1.setTimeModified((new java.util.Date()).getTime());
				String msg = intres.getLocalizedMessage("ra.resettedloginattemptscounter", username, resetValue);            	
				logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
    		}
        } catch (FinderException e) {
            String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace("<resetRamainingLoginAttempts(" + username + "): "+resetValue);
        }
	}
	
	/**
	 * Decrements the remaining failed login attempts counter. If the counter 
	 * already was zero the status for the user is set to {@link UserDataConstants#STATUS_GENERATED} 
	 * if it wasn't that already. This method does nothing if the counter value is set to UNLIMITED (-1). 
	 * @param admin the administrator performing the action
     * @param username the unique username of the user
	 * @throws AuthorizationDeniedException if administrator isn't authorized to edit user
	 * @throws FinderException if the entity does not exist
	 * @ejb.interface-method
	 */
	public void decRemainingLoginAttempts(Admin admin, String username) throws AuthorizationDeniedException, FinderException {
		if (log.isTraceEnabled()) {
            log.trace(">decRemainingLoginAttempts(" + username + ")");
        }
		int counter;
        int caid = LogConstants.INTERNALCAID;
        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);
            caid = data1.getCaId();
            if (!authorizedToCA(admin, caid)) {
                String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
            
        	ExtendedInformation ei = data1.getExtendedInformation();
        	if (ei == null) {
        		ei = new ExtendedInformation();
        		data1.setExtendedInformation(ei);
        	}
        	
    		counter = ei.getRemainingLoginAttempts();
    		
    		// If we get to 0 we must set status to generated
    		if(counter == 0) {
    			// if it isn't already
    			if(data1.getStatus() != UserDataConstants.STATUS_GENERATED) {
        			data1.setStatus(UserDataConstants.STATUS_GENERATED);
        			data1.setTimeModified((new java.util.Date()).getTime());
        			String msg = intres.getLocalizedMessage("ra.decreasedloginattemptscounter", username, counter);
					logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
					resetRemainingLoginAttempts(admin, username);
    			}
    		} else if(counter != -1) {
				log.debug("Found a remaining login counter with value "+counter);
				ei.setRemainingLoginAttempts(--counter);
				data1.setExtendedInformation(ei);
				String msg = intres.getLocalizedMessage("ra.decreasedloginattemptscounter", username, counter);            	
				logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
			} else {
				log.debug("Found a remaining login counter with value UNLIMITED, not decreased in db.");
				counter = Integer.MAX_VALUE;
			}
        } catch (FinderException e) {
            String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace("<decRemainingLoginAttempts(" + username + "): "+counter);
        }
	} //decRemainingLoginAttempts
	
    /**
     * Decreases (the optional) request counter by 1, until it reaches 0. Returns the new value. If the value is already 0, -1 is returned, but the 
     * -1 is not stored in the database.
     *
     * @param username the unique username.
     * @param status   the new status, from 'UserData'.
     * @ejb.interface-method
     */
    public int decRequestCounter(Admin admin, String username) throws AuthorizationDeniedException, FinderException {
        if (log.isTraceEnabled()) {
            log.trace(">decRequestCounter(" + username + ")");
        }
        // Default return value is as if the optional value does not exist for the user, i.e. the default values is 0
        // because the default number of allowed requests are 1
        int counter = 0;
        // Check if administrator is authorized to edit user.
        int caid = LogConstants.INTERNALCAID;
        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);
            caid = data1.getCaId();
            if (!authorizedToCA(admin, caid)) {
                String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
            if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
                if (!authorizedToEndEntityProfile(admin, data1.getEndEntityProfileId(), AccessRulesConstants.EDIT_RIGHTS)) {
                    String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data1.getEndEntityProfileId()));            	
                    logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                    throw new AuthorizationDeniedException(msg);
                }
            }
            
            // Do the work of decreasing the counter
        	ExtendedInformation ei = data1.getExtendedInformation();
        	if (ei != null) {
        		String counterstr = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
        		if (StringUtils.isNotEmpty(counterstr)) {
        			try {
        				counter = Integer.valueOf(counterstr);
        				log.debug("Found a counter with value "+counter);
        				// decrease the counter, if we get to 0 we must set status to generated
        				counter--;
        				if (counter >= 0) {
        					ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, String.valueOf(counter));
        					data1.setExtendedInformation(ei);
        					data1.setTimeModified((new java.util.Date()).getTime());
        					String msg = intres.getLocalizedMessage("ra.decreasedentityrequestcounter", username, counter);            	
        					logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
        				} else {
        					log.debug("Counter value was already 0, not decreased in db.");
        				}
        			} catch (NumberFormatException e) {
        				String msg = intres.getLocalizedMessage("ra.errorrequestcounterinvalid", username, counterstr, e.getMessage());            	        		
        				log.error(msg, e);
        			}        		
        		} else {
        			log.debug("No (optional) request counter exists for end entity: "+username);
        		}
        	} else {
        		debug("No extended information exists for user: "+data1.getUsername());
        	}
        } catch (FinderException e) {
            String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace("<decRequestCounter(" + username + "): "+counter);
        }
        return counter;
    } // decRequestCounter

    /**
     * Changes status of a user.
     *
     * @param username the unique username.
     * @param status   the new status, from 'UserData'.
     * @throws ApprovalException if an approval already is waiting for specified action 
     * @throws WaitingForApprovalException if approval is required and the action have been added in the approval queue.
     * @ejb.interface-method
     */
    public void setUserStatus(Admin admin, String username, int status) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException {
        if (log.isTraceEnabled()) {
            log.trace(">setUserStatus(" + username + ", " + status + ")");
        }
        // Check if administrator is authorized to edit user.
        int caid = LogConstants.INTERNALCAID;
        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);
            caid = data1.getCaId();

            if (!authorizedToCA(admin, caid)) {
                String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }


            if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
                if (!authorizedToEndEntityProfile(admin, data1.getEndEntityProfileId(), AccessRulesConstants.EDIT_RIGHTS)) {
                    String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data1.getEndEntityProfileId()));            	
                    logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                    throw new AuthorizationDeniedException(msg);
                }
            }
            
            // Check if approvals is required.
            int numOfApprovalsRequired = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_ADDEDITENDENTITY, caid, data1.getCertificateProfileId());
            ChangeStatusEndEntityApprovalRequest ar = new ChangeStatusEndEntityApprovalRequest(username, data1.getStatus(), status ,  admin,null,numOfApprovalsRequired,data1.getCaId(),data1.getEndEntityProfileId());
            if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_SETUSERSTATUS)){       		    		
            	getApprovalSession().addApprovalRequest(admin, ar, getGlobalConfiguration(admin));
	            String msg = intres.getLocalizedMessage("ra.approvaledit");            	
            	throw new WaitingForApprovalException(msg);
            }  
            
            if(data1.getStatus() == UserDataConstants.STATUS_KEYRECOVERY && !(status == UserDataConstants.STATUS_KEYRECOVERY || status == UserDataConstants.STATUS_INPROCESS || status == UserDataConstants.STATUS_INITIALIZED)){
                getKeyRecoverySession().unmarkUser(admin,username);	
            }
    		if ( (status == UserDataConstants.STATUS_NEW) && (data1.getStatus() != UserDataConstants.STATUS_NEW) ) {
                // If status is set to new, when it is not already new, we should re-set the allowed request counter to the default values
    			resetRequestCounter(admin, data1, false);
    			// Reset remaining login counter
    			resetRemainingLoginAttempts(admin, username);
    		} else {
    			log.debug("Status not changing from something else to new, not resetting requestCounter.");
    		}
            data1.setStatus(status);
            data1.setTimeModified((new java.util.Date()).getTime());
            String msg = intres.getLocalizedMessage("ra.editedentitystatus", username, new Integer(status));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            
            // Send notifications when transitioning user through work-flow, if they should be sent
            UserDataVO userdata = data1.toUserDataVO();
            sendNotification(admin, userdata, status);

        } catch (FinderException e) {
            String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw e;
        }
        if (log.isTraceEnabled()) {
            log.trace("<setUserStatus(" + username + ", " + status + ")");
        }
    } // setUserStatus

    /**
     * Sets a new password for a user.
     *
     * @param admin    the administrator pwrforming the action
     * @param username the unique username.
     * @param password the new password for the user, NOT null.
     * @ejb.interface-method
     */
    public void setPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException {
        setPassword(admin, username, password, false);
    } // setPassword

    /**
     * Sets a clear text password for a user.
     *
     * @param admin    the administrator pwrforming the action
     * @param username the unique username.
     * @param password the new password to be stored in clear text. Setting password to 'null'
     *                 effectively deletes any previous clear text password.
     * @ejb.interface-method
     */
    public void setClearTextPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException {
        setPassword(admin, username, password, true);
    } // setClearTextPassword

    /**
     * Sets a password, hashed or clear text, for a user.
     *
     * @param admin     the administrator pwrforming the action
     * @param username  the unique username.
     * @param password  the new password to be stored in clear text. Setting password to 'null'
     *                  effectively deletes any previous clear text password.
     * @param cleartext true gives cleartext password, false hashed
     */
    private void setPassword(Admin admin, String username, String password, boolean cleartext) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException {
        if (log.isTraceEnabled()) {
            log.trace(">setPassword(" + username + ", hiddenpwd), " + cleartext);
        }
        // Find user
        String newpasswd = password;
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        int caid = data.getCaId();
        String dn = data.getSubjectDN();

        EndEntityProfile profile = raadminsession.getEndEntityProfile(admin, data.getEndEntityProfileId());

        if (profile.useAutoGeneratedPasswd()) {
            newpasswd = profile.getAutoGeneratedPasswd();
        }
        if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
            // Check if user fulfills it's profile.
            try {
                profile.doesPasswordFulfillEndEntityProfile(password, true);
            } catch (UserDoesntFullfillEndEntityProfile ufe) {
                String msg = intres.getLocalizedMessage("ra.errorfullfillprofile", new Integer(data.getEndEntityProfileId()), dn, ufe.getMessage());            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw ufe;
            }

            // Check if administrator is authorized to edit user.
            if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.EDIT_RIGHTS)) {
                String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data.getEndEntityProfileId()));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }

        if (!authorizedToCA(admin, caid)) {
            String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw new AuthorizationDeniedException(msg);
        }

        try {
            if ((newpasswd == null) && (cleartext)) {
                data.setClearPassword("");
                data.setTimeModified((new java.util.Date()).getTime());
            } else {
                if (cleartext) {
                    data.setOpenPassword(newpasswd);
                } else {
                    data.setPassword(newpasswd);
                }
                data.setTimeModified((new java.util.Date()).getTime());
            }
            String msg = intres.getLocalizedMessage("ra.editpwdentity", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
        } catch (java.security.NoSuchAlgorithmException nsae) {
            error("NoSuchAlgorithmException while setting password for user " + username);
            throw new EJBException(nsae);
        }
        if (log.isTraceEnabled()) {
            log.trace("<setPassword(" + username + ", hiddenpwd), " + cleartext);
        }
    } // setPassword

    /**
     * Verifies a password for a user.
     *
     * @param admin    the administrator pwrforming the action
     * @param username the unique username.
     * @param password the password to be verified.
     * @ejb.interface-method
     */
    public boolean verifyPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException {
        if (log.isTraceEnabled()) {
            log.trace(">verifyPassword(" + username + ", hiddenpwd)");
        }
        boolean ret = false;
        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        int caid = data.getCaId();

        if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
            // Check if administrator is authorized to edit user.
            if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.EDIT_RIGHTS)) {
                String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data.getEndEntityProfileId()));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }

        if (!authorizedToCA(admin, caid)) {
            String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw new AuthorizationDeniedException(msg);
        }

        try {
            ret = data.comparePassword(password);
        } catch (java.security.NoSuchAlgorithmException nsae) {
            debug("NoSuchAlgorithmException while verifying password for user " + username);
            throw new EJBException(nsae);
        }
        if (log.isTraceEnabled()) {
            log.trace("<verifyPassword(" + username + ", hiddenpwd)");
        }
        return ret;
    } // verifyPassword

	private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_REVOKEANDDELETEUSER = {
		new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest.class.getName(),null),
	};

    /**
     * @ejb.interface-method
     */
    public void revokeAndDeleteUser(Admin admin, String username, int reason) throws AuthorizationDeniedException,
		ApprovalException, WaitingForApprovalException, RemoveException, NotFoundException {
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data;
        try {
            data = home.findByPrimaryKey(pk);
		} catch (FinderException e) {
			throw new NotFoundException ("User '" + username + "' not found."); 
        }
    	// Authorized?
        int caid = data.getCaId();
        if (!authorizedToCA(admin, caid)) {
            String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_REVOKEDENDENTITY, msg);
            throw new AuthorizationDeniedException(msg);
        }

        if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
            if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.REVOKE_RIGHTS)) {
                String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data.getEndEntityProfileId()));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_REVOKEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }
    	try {
	        if ( getUserStatus(admin, username) != UserDataConstants.STATUS_REVOKED ) {
		        // Check if approvals is required.
		        int numOfReqApprovals = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_REVOCATION, data.getCaId(), data.getCertificateProfileId());
		        RevocationApprovalRequest ar = new RevocationApprovalRequest(true, username, reason, admin,
		        		numOfReqApprovals, data.getCaId(), data.getEndEntityProfileId());
		        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_REVOKEANDDELETEUSER)) {
		        	getApprovalSession().addApprovalRequest(admin, ar, getGlobalConfiguration(admin));
		            String msg = intres.getLocalizedMessage("ra.approvalrevoke");            	
		        	throw new WaitingForApprovalException(msg);
		        }
		    	try {
		    		revokeUser(admin, username, reason);
		    	} catch (AlreadyRevokedException e) {
		    		// This just means that the end endtity was revoked before this request could be completed. No harm.
		    	}
	        }
		} catch (FinderException e) {
			throw new NotFoundException ("User " + username + "not found."); 
		}
		deleteUser(admin, username);
    }

	private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_REVOKEUSER = {
		new ApprovalOveradableClassName(org.ejbca.core.ejb.ra.LocalUserAdminSessionBean.class.getName(),"revokeAndDeleteUser"),
		new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest.class.getName(),null),
	};

    /**
     * Method that revokes a user.
     *
     * @param username the username to revoke.
     * @throws AlreadyRevokedException 
     * @ejb.interface-method
     */
    public void revokeUser(Admin admin, String username, int reason) throws AuthorizationDeniedException, FinderException,
    	ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        if (log.isTraceEnabled()) {
            log.trace(">revokeUser(" + username + ")");
        }
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);

        int caid = data.getCaId();
        if (!authorizedToCA(admin, caid)) {
            String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_REVOKEDENDENTITY, msg);
            throw new AuthorizationDeniedException(msg);
        }

        if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
            if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.REVOKE_RIGHTS)) {
                String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data.getEndEntityProfileId()));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_REVOKEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }
        if ( getUserStatus(admin, username) == UserDataConstants.STATUS_REVOKED ) {
            String msg = intres.getLocalizedMessage("ra.errorbadrequest", new Integer(data.getEndEntityProfileId()));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_REVOKEDENDENTITY, msg);
            throw new AlreadyRevokedException(msg);
        }
        // Check if approvals is required.
        int numOfReqApprovals = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_REVOCATION, data.getCaId(), data.getCertificateProfileId());
        RevocationApprovalRequest ar = new RevocationApprovalRequest(false, username, reason, admin,
        		numOfReqApprovals, data.getCaId(), data.getEndEntityProfileId());
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_REVOKEUSER)) {
        	getApprovalSession().addApprovalRequest(admin, ar, getGlobalConfiguration(admin));
            String msg = intres.getLocalizedMessage("ra.approvalrevoke");            	
        	throw new WaitingForApprovalException(msg);
        }
        // Perform revokation
        
        Collection certs = this.certificatesession.findCertificatesByUsername(admin, username);
        // Revoke all certs
        Iterator j = certs.iterator();
        while (j.hasNext()) {
        	Certificate cert = (Certificate)j.next();
        	// Revoke one certificate at a time
        	try {
            	revokeCert(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), username, reason);        		
        	} catch (AlreadyRevokedException e) {
        		if (log.isDebugEnabled()) {
        			log.debug("Certificate from issuer '"+CertTools.getIssuerDN(cert)+"' with serial "+CertTools.getSerialNumber(cert)+" was already revoked.");
        		}
        	}
        }
        // Finally set revoke status on the user as well
        try {
			setUserStatus(admin, username, UserDataConstants.STATUS_REVOKED);
		} catch (ApprovalException e) {
			throw new EJBException("This should never happen",e);
		} catch (WaitingForApprovalException e) {
			throw new EJBException("This should never happen",e);
		}
        String msg = intres.getLocalizedMessage("ra.revokedentity", username);            	
        logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_REVOKEDENDENTITY, msg);
        log.trace("<revokeUser()");
    }

	private static final ApprovalOveradableClassName[] NONAPPROVABLECLASSNAMES_REVOKECERT = {
		new ApprovalOveradableClassName(org.ejbca.core.model.approval.approvalrequests.RevocationApprovalRequest.class.getName(),null),
	};

	/**
     * Method that revokes a certificate for a user.
     *
     * @param admin the administrator performing the action
     * @param certserno the serno of certificate to revoke.
     * @param username  the username to revoke.
     * @param reason    the reason of revokation, one of the RevokedCertInfo.XX constants.
	 * @throws AlreadyRevokedException if the certificate was already revoked
     * @ejb.interface-method
     */
    public void revokeCert(Admin admin, BigInteger certserno, String issuerdn, String username, int reason) throws AuthorizationDeniedException,
    		FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        if (log.isTraceEnabled()) {
            log.trace(">revokeCert(" + certserno + ", IssuerDN: " + issuerdn + ", username, " + username + ")");
        }
        UserDataPK pk = new UserDataPK(username);	// TODO: Fetch this from certstoresession instead
        UserDataLocal data;
        try {
            data = home.findByPrimaryKey(pk);
        } catch (ObjectNotFoundException oe) {
            throw new FinderException(oe.getMessage()+": username");
        }
        // Check that the user have revokation rigths.
        authorizationsession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_REVOKEENDENTITY);
        int caid = data.getCaId();
        if (!authorizedToCA(admin, caid)) {
            String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_REVOKEDENDENTITY, msg);
            throw new AuthorizationDeniedException(msg);
        }
        if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
            if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.REVOKE_RIGHTS)) {
                String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data.getEndEntityProfileId()));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_REVOKEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }
        Certificate cert = certificatesession.findCertificateByIssuerAndSerno(admin, issuerdn, certserno);
        if ( cert == null ) {
            String msg = intres.getLocalizedMessage("ra.errorfindentitycert", issuerdn, certserno.toString(16));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_REVOKEDENDENTITY, msg);
        	throw new FinderException(msg);
        }
        CertificateStatus revinfo = certificatesession.getStatus(issuerdn, certserno);
        if ( revinfo == null ) {
            String msg = intres.getLocalizedMessage("ra.errorfindentitycert", issuerdn, certserno.toString(16));            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_REVOKEDENDENTITY, msg);
        	throw new FinderException(msg);
        }
        // Check that unrevocation is not done on anything that can not be unrevoked
        if (reason == RevokedCertInfo.NOT_REVOKED) {
            if ( revinfo.revocationReason != RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD ) {
                String msg = intres.getLocalizedMessage("ra.errorunrevokenotonhold", issuerdn, certserno.toString(16));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_REVOKEDENDENTITY, msg);
                throw new AlreadyRevokedException(msg);
            }            
        } else {
            if ( revinfo.revocationReason != RevokedCertInfo.NOT_REVOKED ) {
                String msg = intres.getLocalizedMessage("ra.errorrevocationexists");            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_REVOKEDENDENTITY, msg);
                throw new AlreadyRevokedException(msg);
            }            
        }
        // Check if approvals is required.
        int numOfReqApprovals = getNumOfApprovalRequired(admin, CAInfo.REQ_APPROVAL_REVOCATION, data.getCaId(), data.getCertificateProfileId());
        RevocationApprovalRequest ar = new RevocationApprovalRequest(certserno, issuerdn, username, reason, admin,
        		numOfReqApprovals, data.getCaId(), data.getEndEntityProfileId());
        if (ApprovalExecutorUtil.requireApproval(ar, NONAPPROVABLECLASSNAMES_REVOKECERT)) {
        	getApprovalSession().addApprovalRequest(admin, ar, getGlobalConfiguration(admin));
            String msg = intres.getLocalizedMessage("ra.approvalrevoke");            	
        	throw new WaitingForApprovalException(msg);
        }
        // Perform revokation, first we try to find the certificate profile the certificate was issued under
        // Get it first from the certificate itself. This should be the correct one
        CertificateInfo info = certificatesession.getCertificateInfo(admin, CertTools.getFingerprintAsString(cert));
        int certificateProfileId = 0;
        if (info != null) {
        	certificateProfileId = info.getCertificateProfileId();
        }
        // If for some reason the certificate profile id was not set in the certificate data, try to get it from the certreq history
        if (certificateProfileId == 0) {
            CertReqHistory certReqHistory = certificatesession.getCertReqHistory(admin, certserno, issuerdn);
            if (certReqHistory != null) {
            	certificateProfileId = certReqHistory.getUserDataVO().getCertificateProfileId();
            }
        }
        // Finally find the publishers for the certificate profileId that we found
        Collection publishers = new ArrayList();        
        CertificateProfile prof = certificatesession.getCertificateProfile(admin, certificateProfileId);
        if (prof != null) {
        	publishers = prof.getPublisherList();
        }
        
        // Revoke certificate in database and all publishers
        certificatesession.setRevokeStatus(admin, issuerdn, certserno, publishers, reason, data.getSubjectDN());
        // Reset the revocation code identifier used in XKMS
        ExtendedInformation inf = data.getExtendedInformation();
        if (inf != null) {
            inf.setRevocationCodeIdentifier(null);        	
        }
        log.trace("<revokeCert()");
    } // revokeCert

    /** 
     * Reactivates the certificate with certificate serno.
     *
     * @param admin the adminsitrator performing the action
     * @param certserno serial number of certificate to reactivate.
     * @param issuerdn the issuerdn of certificate to reactivate.
     * @param username the username joined to the certificate.
     * @throws WaitingForApprovalException 
     * @throws ApprovalException 
     * @throws AlreadyRevokedException 
     * @ejb.interface-method
     */
    public void unRevokeCert(Admin admin, BigInteger certserno, String issuerdn, String username) throws AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        log.trace(">unrevokeCert()");
        revokeCert(admin, certserno, issuerdn, username, RevokedCertInfo.NOT_REVOKED);
        log.trace("<unrevokeCert()");
    }

    /**
     * Method that looks up the username and email address for a administrator and returns the populated Admin object.
     * @param certificate is the administrators certificate
     *
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public Admin getAdmin(Certificate certificate) {
		String adminUsername = getCertificateStoreSession().findUsernameByCertSerno(new Admin(Admin.TYPE_INTERNALUSER),CertTools.getSerialNumber(certificate),CertTools.getIssuerDN(certificate));
		String adminEmail = null;
		if (adminUsername != null) {
			Connection con = null;
			PreparedStatement ps = null;
			ResultSet rs = null;
			try {
				con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
				String sql="SELECT subjectEmail FROM UserData WHERE username=?";
				ps = con.prepareStatement(sql);
				ps.setString(1, adminUsername);
				ps.setFetchSize(1);
				ps.setMaxRows(1);
				rs = ps.executeQuery();
				if (rs.next()) {
					adminEmail = rs.getString(1);
				}
			} catch (Exception e) {
				log.error("", e);
				throw new EJBException(e);
			} finally {
				JDBCUtil.close(con, ps, rs);
			}
		}
		return new Admin(certificate, adminUsername, adminEmail);
    }

    /**
     * Finds a user.
     *
     * @param admin the administrator performing the action
     * @param username username.
     * @return UserDataVO or null if the user is not found.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public UserDataVO findUser(Admin admin, String username) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUser(" + username + ")");
        }
        UserDataPK pk = new UserDataPK(username);
        UserDataVO ret = null;
        try {
            UserDataLocal data = home.findByPrimaryKey(pk);
            if (data != null) {
                if (!authorizedToCA(admin, data.getCaId())) {
                    String msg = intres.getLocalizedMessage("ra.errorauthcaexist", new Integer(data.getCaId()), username);
                    throw new AuthorizationDeniedException(msg);
                }

                if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
                    // Check if administrator is authorized to view user.
                    if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.VIEW_RIGHTS)){
                        String msg = intres.getLocalizedMessage("ra.errorauthprofileexist", new Integer(data.getEndEntityProfileId()), username);
                        throw new AuthorizationDeniedException(msg);            	
                    }
                }

                ret = new UserDataVO(data.getUsername(), data.getSubjectDN(), data.getCaId(), data.getSubjectAltName(), data.getSubjectEmail(), data.getStatus()
                        , data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId()
                        , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified())
                        , data.getTokenType(), data.getHardTokenIssuerId(), data.getExtendedInformation());
                ret.setPassword(data.getClearPassword());
                ret.setCardNumber(data.getCardNumber());        	
            }
        } catch (ObjectNotFoundException oe) {
            // NOPMD ignore will return null 
        } catch (FinderException fe) {
            // NOPMD ignore will return null
        }
        if (log.isTraceEnabled()) {
            log.trace("<findUser(" + username + "): " + (ret == null ? "null":ret.getDN()));
        }
        return ret;
    } // findUser

    /**
     * Finds a user by its subject and issuer DN.
     *
     * @param admin
     * @param subjectdn
     * @param issuerdn
     * @return UserDataVO or null if the user is not found.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public UserDataVO findUserBySubjectAndIssuerDN(Admin admin, String subjectdn, String issuerdn) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserBySubjectAndIssuerDN(" + subjectdn + ", "+issuerdn+")");
        }
        // String used in SQL so strip it
        String dn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
        debug("Looking for users with subjectdn: " + dn + ", issuerdn : " + issuerdn);
        UserDataVO returnval = null;

        UserDataLocal data = null;

        try {
            data = home.findBySubjectDNAndCAId(dn, issuerdn.hashCode());
        } catch (FinderException e) {
            log.debug("Cannot find user with DN='" + dn + "'");
        }
        returnval = returnUserDataVO(admin, returnval, data);
        if (log.isTraceEnabled()) {
            log.trace("<findUserBySubjectAndIssuerDN(" + subjectdn + ", "+issuerdn+")");
        }
        return returnval;
    } // findUserBySubjectDN

    /**
     * Finds a user by its subject DN.
     *
     * @param admin
     * @param subjectdn
     * @return UserDataVO or null if the user is not found.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public UserDataVO findUserBySubjectDN(Admin admin, String subjectdn) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserBySubjectDN(" + subjectdn + ")");
        }
        // String used in SQL so strip it
        String dn = CertTools.stringToBCDNString(StringTools.strip(subjectdn));
        debug("Looking for users with subjectdn: " + dn);
        UserDataVO returnval = null;

        UserDataLocal data = null;

        try {
            data = home.findBySubjectDN(dn);
        } catch (FinderException e) {
            log.debug("Cannot find user with DN='" + dn + "'");
        }
        returnval = returnUserDataVO(admin, returnval, data);
        if (log.isTraceEnabled()) {
            log.trace("<findUserBySubjectDN(" + subjectdn + ")");
        }
        return returnval;
    } // findUserBySubjectDN

	private UserDataVO returnUserDataVO(Admin admin, UserDataVO returnval, UserDataLocal data) throws AuthorizationDeniedException {
		if (data != null) {
        	if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
        		// Check if administrator is authorized to view user.
        		if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.VIEW_RIGHTS)) {
                    String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data.getEndEntityProfileId()));
        			throw new AuthorizationDeniedException(msg);
        		}
        	}

            if (!authorizedToCA(admin, data.getCaId())) {
                String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(data.getCaId()));
                throw new AuthorizationDeniedException(msg);
            }

            returnval = new UserDataVO(data.getUsername(), data.getSubjectDN(), data.getCaId(), data.getSubjectAltName(), data.getSubjectEmail(), data.getStatus()
                    , data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId()
                    , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified())
                    , data.getTokenType(), data.getHardTokenIssuerId(), data.getExtendedInformation());

            returnval.setPassword(data.getClearPassword());
            returnval.setCardNumber(data.getCardNumber());
        }
		return returnval;
	}

    /**
     * Finds a user by its Email.
     *
     * @param email
     * @return UserDataVO or null if the user is not found.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public Collection findUserByEmail(Admin admin, String email) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">findUserByEmail(" + email + ")");
        }
        debug("Looking for user with email: " + email);
        ArrayList returnval = new ArrayList();

        Collection result = null;
        try {
            result = home.findBySubjectEmail(email);
        } catch (FinderException e) {
            log.debug("Cannot find user with Email='" + email + "'");
        }

        Iterator iter = result.iterator();
        while (iter.hasNext()) {
            UserDataLocal data = (UserDataLocal) iter.next();

            if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
                // Check if administrator is authorized to view user.
                if (!authorizedToEndEntityProfile(admin, data.getEndEntityProfileId(), AccessRulesConstants.VIEW_RIGHTS)) {
                    break;
                }
            }

            if (!authorizedToCA(admin, data.getCaId())) {
                break;
            }

            UserDataVO user = new UserDataVO(data.getUsername(), data.getSubjectDN(), data.getCaId(), data.getSubjectAltName(), data.getSubjectEmail(), data.getStatus()
                    , data.getType(), data.getEndEntityProfileId(), data.getCertificateProfileId()
                    , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified())
                    , data.getTokenType(), data.getHardTokenIssuerId(), data.getExtendedInformation());
            user.setPassword(data.getClearPassword());
            user.setCardNumber(data.getCardNumber());
            returnval.add(user);
        }
        if (log.isTraceEnabled()) {
            log.trace("<findUserByEmail(" + email + ")");
        }
        return returnval;
    } // findUserBySubjectDN

   	/**
     * Method that checks if user with specified users certificate exists in database
     * @deprecated This method no longer verifies the admin-flag of end entities since this feature was dropped in EJBCA 3.8.0 
     *
     * @param subjectdn
     * @throws AuthorizationDeniedException if user doesn't exist
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public void checkIfCertificateBelongToAdmin(Admin admin, BigInteger certificatesnr, String issuerdn) throws AuthorizationDeniedException {
    	checkIfCertificateBelongToUser(admin, certificatesnr, issuerdn);
    }

   	/**
     * Method that checks if user with specified users certificate exists in database
     *
     * @param subjectdn
     * @throws AuthorizationDeniedException if user doesn't exist
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public void checkIfCertificateBelongToUser(Admin admin, BigInteger certificatesnr, String issuerdn) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">checkIfCertificateBelongToUser(" + certificatesnr.toString(16) + ")");
        }
        if (!WebConfiguration.getRequireAdminCertificateInDatabase()) {
        	log.trace("<checkIfCertificateBelongToUser Configured to ignore if cert belongs to user.");
        	return;
        }
        String username = certificatesession.findUsernameByCertSerno(admin, certificatesnr, issuerdn);
        if (username != null) {
            UserDataPK pk = new UserDataPK(username);
            try {
            	home.findByPrimaryKey(pk);
            } catch (FinderException e) {
                String msg = intres.getLocalizedMessage("ra.errorcertnouser", issuerdn, certificatesnr.toString(16));
                logsession.log(admin, LogConstants.INTERNALCAID, LogConstants.MODULE_RA, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_ADMINISTRATORLOGGEDIN, msg);
                throw new AuthorizationDeniedException(msg);
            }
        }
        log.trace("<checkIfCertificateBelongToUser()");
    }

    /**
     * Finds all users with a specified status.
     *
     * @param status the status to look for, from 'UserData'.
     * @return Collection of UserDataVO
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public Collection findAllUsersByStatus(Admin admin, int status) throws FinderException {
        if (log.isTraceEnabled()) {
            log.trace(">findAllUsersByStatus(" + status + ")");
        }
        debug("Looking for users with status: " + status);

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(status));
        Collection returnval = null;

        try {
            returnval = query(admin, query, false, null, null, false,0);
        } catch (IllegalQueryException e) {
        }
        debug("found " + returnval.size() + " user(s) with status=" + status);
        if (log.isTraceEnabled()) {
            log.trace("<findAllUsersByStatus(" + status + ")");
        }
        return returnval;
    }
    /**
     * Finds all users registered to a specified ca.
     *
     * @param caid the caid of the CA, from 'UserData'.
     * @return Collection of UserDataVO, or empty collection if the query is illegal or no users exist
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
     public Collection findAllUsersByCaId(Admin admin, int caid) {
         if (log.isTraceEnabled()) {
             log.trace(">findAllUsersByCaId("+caid+")");
         }
         if (log.isDebugEnabled()) {
        	 debug("Looking for users with caid: " + caid);
         }
         Query query = new Query(Query.TYPE_USERQUERY);
         query.add(UserMatch.MATCH_WITH_CA, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(caid));
         Collection returnval = null;
         try{
           returnval = query(admin, query, false, null, null, false,0);  
         }catch(IllegalQueryException e){
        	 // Ignore ??
        	 debug("Illegal query", e);
        	 returnval = new ArrayList();
         }
         if (log.isDebugEnabled()) {
             debug("found "+returnval.size()+" user(s) with caid="+caid);        	 
         }
         if (log.isTraceEnabled()) {
             log.trace("<findAllUsersByCaId("+caid+")");
         }
         return returnval;         
     }


    /**
     * Finds all users and returns the first MAXIMUM_QUERY_ROWCOUNT.
     *
     * @return Collection of UserDataVO
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public Collection findAllUsersWithLimit(Admin admin) throws FinderException {
        trace(">findAllUsersWithLimit()");
        Collection returnval = null;
        try {
            returnval = query(admin, null, true, null, null, false, 0);
        } catch (IllegalQueryException e) {
        }
        trace("<findAllUsersWithLimit()");
        return returnval;
    }

    /**
     * Finds all users with a specified status and returns the first MAXIMUM_QUERY_ROWCOUNT.
     *
     * @param status the new status, from 'UserData'.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public Collection findAllUsersByStatusWithLimit(Admin admin, int status, boolean onlybatchusers) throws FinderException {
        trace(">findAllUsersByStatusWithLimit()");

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_STATUS, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(status));
        Collection returnval = null;

        try {
            returnval = query(admin, query, false, null, null, onlybatchusers, 0);
        } catch (IllegalQueryException e) {
        }

        trace("<findAllUsersByStatusWithLimit()");
        return returnval;
    }


    /**
     * Method to execute a customized query on the ra user data. The parameter query should be a legal Query object.
     *
     * @param query                  a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @param caauthorizationstring  is a string placed in the where clause of SQL query indication which CA:s the administrator is authorized to view.
     * @param endentityprofilestring is a string placed in the where clause of SQL query indication which endentityprofiles the administrator is authorized to view.
     * @param numberofrows  the number of rows to fetch, use 0 for default UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT 
     * @return a collection of UserDataVO. Maximum size of Collection is defined i IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     * @see se.anatom.ejbca.util.query.Query
     */
    public Collection query(Admin admin, Query query, String caauthorizationstring, String endentityprofilestring, int numberofrows) throws IllegalQueryException {
        return query(admin, query, true, caauthorizationstring, endentityprofilestring, false, numberofrows);
    }

    /**
     * Help function used to retrieve user information. A query parameter of null indicates all users.
     * If caauthorizationstring or endentityprofilestring are null then the method will retrieve the information
     * itself.
     * 
     * @param numberofrows  the number of rows to fetch, use 0 for default UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT 
     */
    private Collection query(Admin admin, Query query, boolean withlimit, String caauthorizationstr, String endentityprofilestr, boolean onlybatchusers, int numberofrows) throws IllegalQueryException {
        if (log.isTraceEnabled()) {
            log.trace(">query(): withlimit="+withlimit);
        }
        boolean authorizedtoanyprofile = true;
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        String caauthorizationstring = StringTools.strip(caauthorizationstr);
        String endentityprofilestring = StringTools.strip(endentityprofilestr);
        ArrayList returnval = new ArrayList();
        GlobalConfiguration globalconfiguration = getGlobalConfiguration(admin);
        RAAuthorization raauthorization = null;
        String caauthstring = caauthorizationstring;
        String endentityauth = endentityprofilestring;
        String sqlquery = "select " + USERDATA_COL + " from UserData where ";
        int fetchsize = UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT;
        
        if(numberofrows != 0){
        	fetchsize = numberofrows;
        }

        // Check if query is legal.
        if (query != null && !query.isLegalQuery()) {
            throw new IllegalQueryException();
        }

        if (query != null) {
            sqlquery = sqlquery + query.getQueryString();
        }

        if (caauthorizationstring == null || endentityprofilestring == null) {
            raauthorization = new RAAuthorization(admin, raadminsession, authorizationsession, caadminsession);
            caauthstring = raauthorization.getCAAuthorizationString();
            if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
                endentityauth = raauthorization.getEndEntityProfileAuthorizationString(true);
            } else {
                endentityauth = "";
            }
        }

        if (!caauthstring.trim().equals("") && query != null) {
            sqlquery = sqlquery + " AND " + caauthstring;
        } else {
            sqlquery = sqlquery + caauthstring;
        }


        if (globalconfiguration.getEnableEndEntityProfileLimitations()) {
            if (caauthstring.trim().equals("") && query == null) {
                sqlquery = sqlquery + endentityauth;
            } else {
                sqlquery = sqlquery + " AND " + endentityauth;
            }
            if (endentityauth == null || endentityauth.trim().equals("")) {
                authorizedtoanyprofile = false;
            }
        }
		// Finally order the return values
        sqlquery += " order by "+USERDATA_CREATED_COL+" desc";
		if (log.isDebugEnabled()) {
			log.debug("generated query: " + sqlquery);
		}

        try {
            if (authorizedtoanyprofile) {
                // Construct SQL query.
                con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
                ps = con.prepareStatement(sqlquery);
    			ps.setFetchSize(fetchsize + 1);

                // Execute query.
                rs = ps.executeQuery();

                // Assemble result.
                while (rs.next() && (!withlimit || returnval.size() <= fetchsize)) {
                    // Read the variables in order, some databases (i.e. MS-SQL) 
                    // seems to not like out-of-order read of columns (i.e. nr 15 before nr 1) 
                    String user = rs.getString(1);
                    String dn = rs.getString(2);
                    String subaltname = rs.getString(3);
                    String email = rs.getString(4);
                    int status = rs.getInt(5);
                    int type = rs.getInt(6);
                    String pwd = rs.getString(7);
                    Date timecreated = new java.util.Date(rs.getLong(8));
                    Date timemodified = new java.util.Date(rs.getLong(9));
                    int eprofileid = rs.getInt(10);
                    int cprofileid = rs.getInt(11);
                    int tokentype = rs.getInt(12);
                    int tokenissuerid = rs.getInt(13);
                    int caid = rs.getInt(14);
                    String extendedInformation = rs.getString(15);
                    String cardnumber = rs.getString(16);
                    UserDataVO data = new UserDataVO(user, dn, caid, subaltname, email, status, type
                            , eprofileid, cprofileid, timecreated, timemodified, tokentype, tokenissuerid,
							UserDataVO.getExtendedInformation(extendedInformation));
                    data.setPassword(pwd);
                    data.setCardNumber(cardnumber);

                    if (!onlybatchusers || (data.getPassword() != null && data.getPassword().length() > 0)) {
                        returnval.add(data);
                    }
                }
            }
            log.trace("<query()");
            return returnval;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    } // query
    

    /**
     * Methods that checks if a user exists in the database having the given endentityprofileid. This function is mainly for avoiding
     * desyncronisation when a end entity profile is deleted.
     *
     * @param endentityprofileid the id of end entity profile to look for.
     * @return true if endentityprofileid exists in userdatabase.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public boolean checkForEndEntityProfileId(Admin admin, int endentityprofileid) {
        log.trace(">checkForEndEntityProfileId()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_ENDENTITYPROFILE, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(endentityprofileid));

        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }
            log.trace("<checkForEndEntityProfileId()");
            return count > 0;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    }

    /**
     * Methods that checks if a user exists in the database having the given certificateprofileid. This function is mainly for avoiding
     * desyncronisation when a certificateprofile is deleted.
     *
     * @param certificateprofileid the id of certificateprofile to look for.
     * @return true if certificateproileid exists in userdatabase.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public boolean checkForCertificateProfileId(Admin admin, int certificateprofileid) {
        log.trace(">checkForCertificateProfileId()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_CERTIFICATEPROFILE, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(certificateprofileid));

        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }
            log.trace("<checkForCertificateProfileId()");
            return count > 0;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    } // checkForCertificateProfileId

    /**
     * Methods that checks if a user exists in the database having the given caid. This function is mainly for avoiding
     * desyncronisation when a CAs is deleted.
     *
     * @param caid the id of CA to look for.
     * @return true if caid exists in userdatabase.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public boolean checkForCAId(Admin admin, int caid) {
        log.trace(">checkForCAId()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_CA, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(caid));

        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }
            boolean exists = count > 0;
            if (log.isTraceEnabled()) {
                log.trace("<checkForCAId(): "+exists);
            }
            return exists;
        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    } // checkForCAId


    /**
     * Methods that checks if a user exists in the database having the given hard token profile id. This function is mainly for avoiding
     * desyncronisation when a hard token profile is deleted.
     *
     * @param profileid of hardtokenprofile to look for.
     * @return true if proileid exists in userdatabase.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public boolean checkForHardTokenProfileId(Admin admin, int profileid) {
        trace(">checkForHardTokenProfileId()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        int count = 1; // return true as default.

        Query query = new Query(Query.TYPE_USERQUERY);
        query.add(UserMatch.MATCH_WITH_TOKEN, BasicMatch.MATCH_TYPE_EQUALS, Integer.toString(profileid));

        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select COUNT(*) from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            if (rs.next()) {
                count = rs.getInt(1);
            }
            trace("<checkForHardTokenProfileId()");
            return count > 0;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    } // checkForHardTokenProfileId


    private void  print(Admin admin, EndEntityProfile profile, UserDataVO userdata){
    	try{
      	  if(profile.getUsePrinting()){
      	    String[] pINs = new String[1];
      	    pINs[0] = userdata.getPassword();
              PrinterManager.print(profile.getPrinterName(), profile.getPrinterSVGFileName(), profile.getPrinterSVGData(), profile.getPrintedCopies(), 0, userdata, pINs, new String[0], "", "", "");
      	  }
    	}catch(PrinterException e){
    		String msg = intres.getLocalizedMessage("ra.errorprint", userdata.getUsername(), e.getMessage());
    		error(msg, e);
    		try{
    			logsession.log(admin, userdata.getCAId(), LogConstants.MODULE_RA, new java.util.Date(),userdata.getUsername(), null, LogConstants.EVENT_ERROR_NOTIFICATION, msg);
    		}catch(Exception f){
    			throw new EJBException(f);
    		}
    	}
    }
    
    private void sendNotification(Admin admin, UserDataVO data, int newstatus) {
    	if (data == null) {
        	log.debug("No UserData, no notification sent.");
    		return;
    	}
        String useremail = data.getEmail();
        if (log.isTraceEnabled()) {
            log.trace(">sendNotification: user="+data.getUsername()+", email="+useremail);
        }

        // Make check if we should send notifications at all
        if ( ((data.getType() & SecConst.USER_SENDNOTIFICATION) != 0) ) {
            int profileId = data.getEndEntityProfileId();
            EndEntityProfile profile = raadminsession.getEndEntityProfile(admin, profileId);
            Collection l = profile.getUserNotifications();
            debug("Number of user notifications: "+l.size()); 
            Iterator i = l.iterator();
        	String rcptemail = useremail; // Default value
            while (i.hasNext()) {
            	UserNotification not = (UserNotification)i.next(); 
            	Collection events = not.getNotificationEventsCollection();
            	if (events.contains(String.valueOf(newstatus))) {
                	debug("Status is "+newstatus+", notification sent for notificationevents: "+not.getNotificationEvents());
                    try {
                    	if (StringUtils.equals(not.getNotificationRecipient(), UserNotification.RCPT_USER)) {
                    		rcptemail = useremail;
                    	} else if (StringUtils.contains(not.getNotificationRecipient(), UserNotification.RCPT_CUSTOM)) {
                    		rcptemail = "custom"; // Just if this fail it will say that sending to user with email "custom" failed.
                    		// Plug-in mechanism for retrieving custom notification email recipient addresses
                    		if (not.getNotificationRecipient().length() < 6) {
                        		String msg = intres.getLocalizedMessage("ra.errorcustomrcptshort", not.getNotificationRecipient());
                    			error(msg);
                    		} else {
                        		String cp = not.getNotificationRecipient().substring(7);
                        		if (StringUtils.isNotEmpty(cp)) {
                        			ICustomNotificationRecipient plugin = (ICustomNotificationRecipient) Thread.currentThread().getContextClassLoader().loadClass(cp).newInstance();
                        			rcptemail = plugin.getRecipientEmails(data);
                        			if (StringUtils.isEmpty(rcptemail)) {
                                		String msg = intres.getLocalizedMessage("ra.errorcustomnoemail", not.getNotificationRecipient());
                            			error(msg);
                        			} else {
                        				debug("Custom notification recipient plugin returned email: "+ rcptemail);
                        			}
                        		} else {
                            		String msg = intres.getLocalizedMessage("ra.errorcustomnoclasspath", not.getNotificationRecipient());
                        			error(msg);
                        		}
                    		}
                    	} else {
                    		// Just a plain email address specified in the recipient field
                    		rcptemail = not.getNotificationRecipient();            		
                    	}
                        if (StringUtils.isEmpty(rcptemail)) {
                    		String msg = intres.getLocalizedMessage("ra.errornotificationnoemail", data.getUsername());
                            throw new Exception(msg);
                        }
                        // Get the administrators DN from the admin certificate, if one exists
                        // When approvals is used, this will be the DN of the admin that approves the request
                        Certificate adminCert = admin.getAdminInformation().getX509Certificate();
                        String approvalAdminDN = CertTools.getSubjectDN(adminCert);
                        log.debug("approvalAdminDN: "+approvalAdminDN);
                        UserNotificationParamGen paramGen = new UserNotificationParamGen(data, approvalAdminDN);
                        /* substitute any $ fields in the receipient and from fields */
                        rcptemail = paramGen.interpolate(rcptemail);
                        String fromemail = paramGen.interpolate(not.getNotificationSender());
                        String subject = paramGen.interpolate(not.getNotificationSubject());
                        String message = paramGen.interpolate(not.getNotificationMessage());
                        MailSender.sendMailOrThrow(fromemail, Arrays.asList(rcptemail), MailSender.NO_CC, subject, message, MailSender.NO_ATTACHMENTS);
                        String logmsg = intres.getLocalizedMessage("ra.sentnotification", data.getUsername(), rcptemail);
                        logsession.log(admin, data.getCAId(), LogConstants.MODULE_RA, new java.util.Date(), data.getUsername(), null, LogConstants.EVENT_INFO_NOTIFICATION, logmsg);
                    } catch (Exception e) {
                    	String msg = intres.getLocalizedMessage("ra.errorsendnotification", data.getUsername(), rcptemail);
                    	error(msg, e);
                        try{
                            logsession.log(admin, data.getCAId(), LogConstants.MODULE_RA, new java.util.Date(),data.getUsername(), null, LogConstants.EVENT_ERROR_NOTIFICATION, msg);
                        }catch(Exception f){
                            throw new EJBException(f);
                        }
                    }        		
            	} else { // if (events.contains(String.valueOf(newstatus)))
                	log.debug("Status is "+newstatus+", no notification sent for notificationevents: "+not.getNotificationEvents());
            	}
            }
        } else { // if ( ((data.getType() & SecConst.USER_SENDNOTIFICATION) != 0) )
        	log.debug("Type does not contain SecConst.USER_SENDNOTIFICATION, no notification sent.");
        }
        if (log.isTraceEnabled()) {
            log.trace("<sendNotification: user="+data.getUsername()+", email="+useremail);
        }
    } // sendNotification

    /**
     * Method checking if username already exists in database.
     * WARNING: do not use this method where an authorization check is needed, use findUser there instead.
     *
     * @return true if username already exists.
     * @ejb.interface-method
     * @ejb.transaction type="Supports"
     */
    public boolean existsUser(Admin admin, String username) {
        boolean returnval = true;
        try {
            home.findByPrimaryKey(new UserDataPK(username));
        } catch (FinderException fe) {
            returnval = false;
        }
        return returnval;
    }

    /**
     * Ḿark a user's certificate for key recovery and set the user status to UserDataConstants.STATUS_KEYRECOVERY.
     *
     * @param admin used to authorize this action
     * @param username is the user to key recover a certificate for
     * @param certificate is the certificate to recover the keys for. Use 'null' to recovery the certificate with latest not before date.
     * @return true if the operation was succesful
     * @throws WaitingForApprovalException 
     * @throws ApprovalException 
     * @throws AuthorizationDeniedException 
     * 
     * @ejb.interface-method
     * @ejb.transaction type="Required"
     */
    public boolean prepareForKeyRecovery(Admin admin, String username, int endEntityProfileId, Certificate certificate) throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException {
    	boolean ret;
    	GlobalConfiguration gc = raadminsession.loadGlobalConfiguration(admin);
    	if (certificate == null) {
    		ret = getKeyRecoverySession().markNewestAsRecoverable(admin, username, endEntityProfileId, gc);
    	} else {
    		ret = getKeyRecoverySession().markAsRecoverable(admin, certificate, endEntityProfileId, gc);
    	}
        try {
			setUserStatus(admin, username, UserDataConstants.STATUS_KEYRECOVERY);
		} catch (FinderException e) {
			ret = false;
			log.info("prepareForKeyRecovery: No such user: " + username);
		}
    	return ret;
    }

    //
    // Private helper methods
    //
    /** re-sets the optional request counter of a user to the default value specified by the end entity profile.
     * If the profile does not specify that request counter should be used, the counter is removed.
     * @param admin administrator
     * @param data1 UserDataLocal, the new user
     */
    private void resetRequestCounter(Admin admin, UserDataLocal data1, boolean onlyRemoveNoUpdate) {
    	if (log.isTraceEnabled()) {
        	log.trace(">resetRequestCounter("+data1.getUsername()+", "+onlyRemoveNoUpdate+")");    		
    	}
    	int epid = data1.getEndEntityProfileId();
    	EndEntityProfile prof = raadminsession.getEndEntityProfile(admin, epid);
    	String value = null;
    	if (prof != null) {
        	value = prof.getValue(EndEntityProfile.ALLOWEDREQUESTS, 0);    		
        	if (!prof.getUse(EndEntityProfile.ALLOWEDREQUESTS, 0)) {
        		value = null;
        	}
    	} else {
    		log.debug("Can not fetch entity profile with id "+epid);
    	}
    	ExtendedInformation ei = data1.getExtendedInformation();
    	if (ei != null) {
    		String counter = ei.getCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER);
    		debug("Old counter is: "+counter+", new counter will be: "+value);
    		// If this end entity profile does not use ALLOWEDREQUESTS, this value will be set to null
    		// We only re-set this value if the COUNTER was used in the first place, if never used, we will not fiddle with it
    		if (counter != null) {
    			if ( (!onlyRemoveNoUpdate) || (onlyRemoveNoUpdate && (value==null)) ) {
    				ei.setCustomData(ExtendedInformation.CUSTOM_REQUESTCOUNTER, value);
    				data1.setExtendedInformation(ei);    			
    				debug("Re-set request counter for user '"+data1.getUsername()+"' to:"+value);
    			} else {
    				debug("No re-setting counter because we should only remove");
    			}
    		} else {
    			debug("Request counter not used, not re-setting it.");
    		}
    	} else {
    		debug("No extended information exists for user: "+data1.getUsername());
    	}
    	if (log.isTraceEnabled()) {
        	log.trace("<resetRequestCounter("+data1.getUsername()+", "+onlyRemoveNoUpdate+")");    		
    	}

    }

    /**
     * Get the current status of a user. 
     * @param admin is the requesting admin
     * @param username is the user to get the status for
     * @return one of the UserDataConstants.STATUS_
     */
    private int getUserStatus(Admin admin, String username) throws AuthorizationDeniedException, FinderException {
    	if (log.isTraceEnabled()) {
            log.trace(">getUserStatus(" + username + ")");
    	}
        // Check if administrator is authorized to edit user.
        int caid = LogConstants.INTERNALCAID;
        int status;
        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1 = home.findByPrimaryKey(pk);
            caid = data1.getCaId();
            if (!authorizedToCA(admin, caid)) {
                String msg = intres.getLocalizedMessage("ra.errorauthca", new Integer(caid));            	
                logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                throw new AuthorizationDeniedException(msg);
            }
            if (getGlobalConfiguration(admin).getEnableEndEntityProfileLimitations()) {
                if (!authorizedToEndEntityProfile(admin, data1.getEndEntityProfileId(), AccessRulesConstants.EDIT_RIGHTS)) {
                    String msg = intres.getLocalizedMessage("ra.errorauthprofile", new Integer(data1.getEndEntityProfileId()));            	
                    logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
                    throw new AuthorizationDeniedException(msg);
                }
            }
             status = data1.getStatus();
        } catch (FinderException e) {
            String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
            logsession.log(admin, caid, LogConstants.MODULE_RA, new java.util.Date(), username, null, LogConstants.EVENT_INFO_CHANGEDENDENTITY, msg);
            throw e;
        }
    	if (log.isTraceEnabled()) {
            log.trace("<getUserStatus(" + username + ", " + status + ")");
    	}
        return status;
    } // getUserStatus

} // LocalUserAdminSessionBean
