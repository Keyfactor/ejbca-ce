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

package org.ejbca.ui.web.admin.rainterface;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AlwaysAllowLocalAuthenticationToken;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.StringTools;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.CouldNotRemoveEndEntityException;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.RAAuthorization;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * A java bean handling the interface between EJBCA ra module and JSP pages.
 * <p>
 * Semi-deprecated, we should try to move the methods here into session beans.
 *
 * @version $Id$
 */
public class RAInterfaceBean implements Serializable {

	private static final long serialVersionUID = 1L;
	private static Logger log = Logger.getLogger(RAInterfaceBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    public static final String[] tokentexts = SecConst.TOKENTEXTS;
    public static final int[]    tokenids   = SecConst.TOKENIDS;

    private EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();

    private AuthorizationSessionLocal authorizationSession;
	private CaSessionLocal caSession;
    private CertificateProfileSession certificateProfileSession;
    private CertificateStoreSession certificatesession;
    private EndEntityAccessSessionLocal endEntityAccessSession;
    private EndEntityManagementSessionLocal endEntityManagementSession;
    private EndEntityProfileSessionLocal endEntityProfileSession;
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    private HardTokenSessionLocal hardtokensession;
    private KeyRecoverySession keyrecoverysession;

    private UsersView usersView;
    private CertificateView[]                  certificates;
    private AddedUserMemory              addedusermemory;
    private AuthenticationToken administrator;
    private RAAuthorization raauthorization;
    private boolean initialized=false;

    /** Creates new RaInterfaceBean */
    public RAInterfaceBean()  {
        usersView = new UsersView();
        addedusermemory = new AddedUserMemory();
    }

    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) {
    	log.trace(">initialize()");
    	if (!initialized) {
    		if (request.getAttribute( "javax.servlet.request.X509Certificate" ) != null) {
    			administrator = ejbcawebbean.getAdminObject();
    		} else {
                administrator = new AlwaysAllowLocalAuthenticationToken(new WebPrincipal("RAInterface", request.getRemoteAddr()));
    		}
    		endEntityManagementSession = ejbLocalHelper.getEndEntityManagementSession();
    		certificatesession = ejbLocalHelper.getCertificateStoreSession();
    		caSession = ejbLocalHelper.getCaSession();
    		authorizationSession = ejbLocalHelper.getAuthorizationSession();
    		endEntityProfileSession = ejbLocalHelper.getEndEntityProfileSession();
    		hardtokensession = ejbLocalHelper.getHardTokenSession();
    		keyrecoverysession = ejbLocalHelper.getKeyRecoverySession();
    		certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
    		this.endEntityAccessSession = ejbLocalHelper.getEndEntityAccessSession();
    		globalConfigurationSession = ejbLocalHelper.getGlobalConfigurationSession();
    		raauthorization = new RAAuthorization(administrator, globalConfigurationSession, authorizationSession, caSession, endEntityProfileSession);
    		initialized =true;
    	} else {
    		log.debug("=initialize(): already initialized");
    	}
    	log.trace("<initialize()");
    }
    
    private GlobalConfiguration getGlobalConfiguration() {
        return (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
    }

    /** Adds a user to the database, the string array must be in format defined in class UserView.
     * @throws WaitingForApprovalException The request ID will be included as a field in this exception. 
     * @throws EndEntityProfileValidationException
     * @throws AuthorizationDeniedException
     * @throws CADoesntExistsException
     * @throws EndEntityExistsException
     * @return added user as EndEntityInformation
     * @throws CertificateSerialNumberException  if SubjectDN serial number already exists.
     * @throws ApprovalException  if an approval already exists for this request.
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     * @throws IllegalNameException  if the Subject DN failed constraints
     */
    public EndEntityInformation addUser(UserView userdata) throws EndEntityExistsException, CADoesntExistsException, AuthorizationDeniedException,
            EndEntityProfileValidationException, WaitingForApprovalException, IllegalNameException, CustomFieldException, ApprovalException, CertificateSerialNumberException {
        log.trace(">addUser()");
        if (userdata.getEndEntityProfileId() != 0) {
            EndEntityInformation uservo = new EndEntityInformation(userdata.getUsername(), userdata.getSubjectDN(), userdata.getCAId(), userdata.getSubjectAltName(),
        		userdata.getEmail(), EndEntityConstants.STATUS_NEW, userdata.getType(), userdata.getEndEntityProfileId(), userdata.getCertificateProfileId(),
        		null,null, userdata.getTokenType(), userdata.getHardTokenIssuerId(), null);
            EndEntityProfile endEntityProfile = endEntityProfileSession.getEndEntityProfile(userdata.getEndEntityProfileId());
            if(StringUtils.isEmpty(userdata.getPassword()) && endEntityProfile.isPasswordPreDefined()) {
                uservo.setPassword(endEntityProfile.getPredefinedPassword());
            } else {
                uservo.setPassword(userdata.getPassword());
            }
            uservo.setExtendedInformation(userdata.getExtendedInformation());
            uservo.setCardNumber(userdata.getCardNumber());
            endEntityManagementSession.addUser(administrator, uservo, userdata.getClearTextPassword());
            addedusermemory.addUser(userdata);
            return uservo;
        } else {
            log.debug("=addUser(): profile id not set, user not created");
        }
        log.trace("<addUser()");
        return null;
    }

    /** Removes a number of users from the database.
     *
     * @param usernames an array of usernames to delete.
     * @return false if administrator wasn't authorized to delete all of given users.
     * @throws CouldNotRemoveEndEntityException if the user could not be deleted.
     * 
     * */
    public boolean deleteUsers(String[] usernames) throws NoSuchEndEntityException, CouldNotRemoveEndEntityException {
      log.trace(">deleteUsers()");
      boolean success = true;
      for (String username : usernames) {
    	  try {
    	      endEntityManagementSession.deleteUser(administrator, username);
    		  addedusermemory.removeUser(username);
    	  } catch(AuthorizationDeniedException e) {
    		  success = false;
    	  }
      }
      log.trace("<deleteUsers(): " + success);
      return success;
    }

    /**
     * Revokes the given user.
     * @param username username of user to revoke.
     * @param reason reason(s) of revocation.
     */
    public void revokeUser(String username, int reason) throws AuthorizationDeniedException,
        NoSuchEndEntityException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
        log.trace(">revokeUser()");
        endEntityManagementSession.revokeUser(administrator, username, reason);
        log.trace("<revokeUser()");
    }

    public void revokeAndDeleteUser(String username, int reason) throws AuthorizationDeniedException,
    		ApprovalException, WaitingForApprovalException, NoSuchEndEntityException, CouldNotRemoveEndEntityException {
		log.trace(">revokeUser()");
		endEntityManagementSession.revokeAndDeleteUser(administrator, username, reason);
		log.trace("<revokeUser()");
    }

    /** Revokes the  certificate with certificate serno.
     *
     * @param serno serial number of certificate to revoke.
     * @param issuerdn the issuerdn of certificate to revoke.
     * @param reason reason(s) of revocation.
     * @return false if administrator wasn't authorized to revoke the given certificate.
     */
    public boolean revokeCert(BigInteger serno, String issuerdn, String username, int reason) throws ApprovalException, WaitingForApprovalException {
    	if (log.isTraceEnabled()) {
        	log.trace(">revokeCert(): "+username+", "+reason);
    	}
    	boolean success = false;
    	try {
    		endEntityManagementSession.revokeCert(administrator, serno, issuerdn, reason);
    		success = true;
    	} catch (AuthorizationDeniedException e) {
    	} catch (NoSuchEndEntityException e) {
    	} catch (AlreadyRevokedException e) {
		}
    	if (log.isTraceEnabled()) {
    		log.trace("<revokeCert(): " + success);
    	}
    	return success;
    }

    /**
     * Reactivates the certificate with certificate serno.
     *
     * @param serno serial number of certificate to reactivate.
     * @param issuerdn the issuerdn of certificate to reactivate.
     * @param username the username joined to the certificate.
     * @return false if administrator wasn't authorized to unrevoke the given certificate.
     */
    public boolean unrevokeCert(BigInteger serno, String issuerdn, String username) throws ApprovalException, WaitingForApprovalException {
    	// Method needed because it is used as an ApprovalOveradableClassName
    	return revokeCert(serno, issuerdn, username, RevokedCertInfo.NOT_REVOKED);
    }

    /** Changes the userdata
     * @param userdata the UserView object with the desired changes
     * @param newUsername the new username if it should be changed
     * @throws CADoesntExistsException if CA with ID in userdata does not exist
     * @throws AuthorizationDeniedException if admin is not authorized to CA
     * @throws EndEntityProfileValidationException if End Entity doesn't match profile
     * @throws WaitingForApprovalException if the request requires approval. The request ID will be included as a field in this exception. 
     * @throws IllegalNameException  if the Subject DN failed constraints
     * @throws CertificateSerialNumberException if SubjectDN serial number already exists.
     * @throws ApprovalException if an approval already is waiting for specified action
     * @throws NoSuchEndEntityException if the end entity could not be found.
     * @throws CustomFieldException if the end entity was not validated by a locally defined field validator
     */
    public void changeUserData(UserView userdata, String newUsername) throws CADoesntExistsException, AuthorizationDeniedException, EndEntityProfileValidationException,
            WaitingForApprovalException, ApprovalException, CertificateSerialNumberException, IllegalNameException, NoSuchEndEntityException, CustomFieldException {
        log.trace(">changeUserData()");
        addedusermemory.changeUser(userdata);
        if (userdata.getPassword() != null && userdata.getPassword().trim().equals("")) {
            userdata.setPassword(null);
        }
        EndEntityInformation uservo = new EndEntityInformation(userdata.getUsername(), userdata.getSubjectDN(), userdata.getCAId(),
                userdata.getSubjectAltName(), userdata.getEmail(), userdata.getStatus(), userdata.getType(), userdata.getEndEntityProfileId(),
                userdata.getCertificateProfileId(), null, null, userdata.getTokenType(), userdata.getHardTokenIssuerId(), null);
        uservo.setPassword(userdata.getPassword());
        uservo.setExtendedInformation(userdata.getExtendedInformation());
        uservo.setCardNumber(userdata.getCardNumber());
        if (userdata.getUsername().equals(newUsername)) {
            endEntityManagementSession.changeUser(administrator, uservo, userdata.getClearTextPassword());
        } else {
            endEntityManagementSession.changeUser(administrator, uservo, userdata.getClearTextPassword(), newUsername);
        }
        log.trace("<changeUserData()");
    }

    /** Method to filter out a user by it's username */
    public UserView[] filterByUsername(String username) {
    	log.trace(">filterByUserName()");
    	EndEntityInformation[] userarray = new EndEntityInformation[1];
    	EndEntityInformation user = null;
    	try {
    		user = endEntityAccessSession.findUser(administrator, username);
    	} catch(AuthorizationDeniedException e) {
    	}
    	if (user != null) {
    		userarray[0]=user;
    		usersView.setUsers(userarray, caSession.getCAIdToNameMap());
    	} else {
    		usersView.setUsers((EndEntityInformation[]) null, caSession.getCAIdToNameMap());
    	}
    	log.trace("<filterByUserName()");
    	return usersView.getUsers(0,1);
    }

    /** Method used to check if user exists */
    public boolean userExist(String username) throws Exception{
    	return endEntityManagementSession.existsUser(username);
    }

    /** Method to retrieve a user from the database without inserting it into users data, used by 'viewuser.jsp' and page*/
    public UserView findUser(String username) throws Exception{
    	if (log.isTraceEnabled()) {
    		log.trace(">findUser(" + username + ")");
    	}
    	EndEntityInformation user = endEntityAccessSession.findUser(administrator, username);
    	UserView userview = null;
    	if (user != null) {
    		userview = new UserView(user, caSession.getCAIdToNameMap());
    	}
    	if (log.isTraceEnabled()) {
    		log.trace("<findUser(" + username + "): " + userview);
    	}
    	return userview;
    }

    /** Method to retrieve a user from the database without inserting it into users data, used by 'edituser.jsp' and page*/
    public UserView findUserForEdit(String username) throws AuthorizationDeniedException {
    	UserView userview = null;
    	EndEntityInformation user = endEntityAccessSession.findUser(administrator, username);
    	if (user != null) {
    	    if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
    	        if (!endEntityAuthorization(administrator, user.getEndEntityProfileId(),AccessRulesConstants.EDIT_END_ENTITY, false)) {
    	            throw new AuthorizationDeniedException("Not authorized to edit user.");
    	        }
    	    }
    	    userview = new UserView(user, caSession.getCAIdToNameMap());
    	}
    	return userview;
    }

    /** Method to find all users in database */
    public UserView[] findAllUsers(int index, int size) {
       usersView.setUsers(endEntityAccessSession.findAllUsersWithLimit(administrator), caSession.getCAIdToNameMap());
       return usersView.getUsers(index,size);
    }

    /** Method to find all users in database */
    public UserView[] filterByTokenSN(String tokensn, int index,int size) {
    	UserView[] returnval = null;
    	ArrayList<EndEntityInformation> userlist = new ArrayList<>();
    	Collection<String> usernames = hardtokensession.matchHardTokenByTokenSerialNumber(tokensn);
    	Iterator<String> iter = usernames.iterator();
    	while (iter.hasNext()) {
    		EndEntityInformation user = null;
    		try {
    			user = endEntityAccessSession.findUser(administrator, iter.next());
    		} catch(AuthorizationDeniedException e) {}
    		if (user!=null) {
    			userlist.add(user);
    		}
    	}
    	usersView.setUsers(userlist, caSession.getCAIdToNameMap());
    	returnval = usersView.getUsers(index,size);
    	return returnval;
    }

    /** Method that fetches a certificate by serialnumber and returns the user(s), else a null value if no certificate/user exists. */
    public UserView[] filterByCertificateSerialNumber(final String serialnumber, final int index, final int size) throws NumberFormatException {
    	final BigInteger serno = new BigInteger(StringTools.stripWhitespace(serialnumber), 16);
    	final List<CertificateDataWrapper> cdws = certificatesession.getCertificateDataBySerno(serno);
    	final List<EndEntityInformation> userlist = new ArrayList<>();
    	for (final CertificateDataWrapper next : cdws) {
    	    final CertificateData certdata = next.getCertificateData();
    	    try {
    	        final String username = certdata.getUsername();
    	        if (username != null) {
    	            final EndEntityInformation user = endEntityAccessSession.findUser(administrator, username);
    	            if (user != null) {
    	                userlist.add(user);
    	            }
    	        }
    	        if (userlist.isEmpty()) {
    	            // Perhaps it's such an old installation that we don't have username in the CertificateData table (has it even ever been like that?, I don't think so)
    	            final List<EndEntityInformation> users = endEntityAccessSession.findUserBySubjectAndIssuerDN(administrator, certdata.getSubjectDnNeverNull(), certdata.getIssuerDN());
    	            userlist.addAll(users);
    	        }
    	    } catch(AuthorizationDeniedException e) {}
    	}
    	usersView.setUsers(userlist, caSession.getCAIdToNameMap());
    	return usersView.getUsers(index, size);
    }

    /** Method that lists all users with certificate's that expires within given days. */
    public UserView[] filterByExpiringCertificates(String days, int index, int size) throws NumberFormatException {
    	ArrayList<EndEntityInformation> userlist = new ArrayList<>();
    	UserView[] returnval = null;
    	long d = Long.parseLong(days);
    	Date finddate = new Date();
    	long millis = (d * 86400000); // One day in milliseconds.
    	finddate.setTime(finddate.getTime() + millis);
    	Collection<String> usernames = certificatesession.findUsernamesByExpireTimeWithLimit(finddate);
    	if (!usernames.isEmpty()) {
    		Iterator<String> i = usernames.iterator();
    		while (i.hasNext() && userlist.size() <= getMaximumQueryRowCount()+1 ) {
    			EndEntityInformation user = null;
    			try {
    				user = endEntityAccessSession.findUser(administrator, i.next());
    				if (user != null) {
    					userlist.add(user);
    				}
    			} catch(AuthorizationDeniedException e) {}
    		}
    		usersView.setUsers(userlist, caSession.getCAIdToNameMap());
    		returnval= usersView.getUsers(index,size);
    	}
    	return returnval;
    }

    public UserView[] filterByQuery(Query query, int index, int size, final String endentityAccessRule) throws IllegalQueryException {
        Collection<EndEntityInformation> userlist = endEntityAccessSession.query(administrator, query,
                raauthorization.getCAAuthorizationString(),
                raauthorization.getEndEntityProfileAuthorizationString(true, endentityAccessRule), 0, endentityAccessRule);
    	usersView.setUsers(userlist, caSession.getCAIdToNameMap());
    	return usersView.getUsers(index,size);
    }

    public int getResultSize(){
    	return usersView.size();
    }

    public boolean isAuthorizedToViewUserHistory(String username) throws AuthorizationDeniedException {
    	EndEntityInformation user = endEntityAccessSession.findUser(administrator, username);
    	return endEntityAuthorization(administrator, user.getEndEntityProfileId(),AccessRulesConstants.VIEW_END_ENTITY_HISTORY, false);
    }

    public boolean isAuthorizedToEditUser(String username) throws AuthorizationDeniedException {
    	EndEntityInformation user = endEntityAccessSession.findUser(administrator, username);
        return endEntityAuthorization(administrator, user.getEndEntityProfileId(),AccessRulesConstants.EDIT_END_ENTITY, false);
    }

    /** Method to resort filtered user data. */
    public void sortUserData(int sortby, int sortorder) {
    	usersView.sortBy(sortby,sortorder);
    }

    /** Method to return the users between index and size, if userdata is smaller than size, a smaller array is returned. */
    public UserView[] getUsers(int index, int size) {
    	return usersView.getUsers(index, size);
    }

    /** Method that clears the userview memory. */
    public void clearUsers() {
    	usersView.clear();
    }

    public boolean nextButton(int index, int size) {
    	return index + size < usersView.size();
    }
    public boolean previousButton(int index) {
    	return index > 0 ;
    }

    // Method dealing with added user memory.
    /** A method to get the last added users in adduser.jsp.
     *
     * @see org.ejbca.ui.web.admin.rainterface.AddedUserMemory
     */
    public UserView[] getAddedUsers(int size){
    	return addedusermemory.getUsers(size);
    }

    // Methods dealing with profiles.
    public TreeMap<String, String> getAuthorizedEndEntityProfileNames(final String endentityAccessRule) {
    	return raauthorization.getAuthorizedEndEntityProfileNames(endentityAccessRule);
    }

    /** Returns the profile name from id proxied */
    public String getEndEntityProfileName(int profileid) {
    	return endEntityProfileSession.getEndEntityProfileName(profileid);
    }

    /**
     *
     * @param profilename the name of the sought profile
     * @return the ID of the sought profile
     * @throws EndEntityProfileNotFoundException if no such profile exists
     */
    public int getEndEntityProfileId(String profilename) throws EndEntityProfileNotFoundException {
        return endEntityProfileSession.getEndEntityProfileId(profilename);
    }

    public EndEntityProfile getEndEntityProfile(int id) {
    	return endEntityProfileSession.getEndEntityProfile(id);
    }

    public void loadCertificates(final String username) {
        loadTokenCertificates(certificatesession.getCertificateDataByUsername(username, false, null));
    }

    public void loadTokenCertificates(final String tokensn) {
        loadTokenCertificates(hardtokensession.getCertificateDatasFromHardToken(tokensn));
    }

    private void loadTokenCertificates(final List<CertificateDataWrapper> cdws) {
        if (!cdws.isEmpty()) {
            if (cdws.size() <= 50) {
                Collections.sort(cdws);
            } else {
                log.debug("User has more than 50 certificates, we will not sort them");
            }
            certificates = new CertificateView[cdws.size()];
            for (int i=0; i<certificates.length; i++) {
                certificates[i] = new CertificateView(cdws.get(i));
            }
        } else{
            certificates = null;
        }
    }

    public boolean revokeTokenCertificates(String tokensn, String username, int reason) throws ApprovalException, WaitingForApprovalException, AlreadyRevokedException {
       boolean success = true;
       ApprovalException lastAppException = null;
       WaitingForApprovalException lastWaitException = null;
       AlreadyRevokedException lastRevokedException = null;
       Collection<Certificate> certs = hardtokensession.findCertificatesInHardToken(tokensn);
       Iterator<Certificate> i = certs.iterator();
       // Extract and revoke collection
       while ( i.hasNext() ) {
    	   Certificate cert = i.next();
           try {
        	   endEntityManagementSession.revokeCert(administrator, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert), reason);
        	// Ignore errors if some were successful
           } catch (ApprovalException e) {
        	   lastAppException = e;
           } catch (WaitingForApprovalException e) {
        	   lastWaitException = e;
           } catch (AlreadyRevokedException e) {
        	   lastRevokedException = e;
           } catch (AuthorizationDeniedException e) {
        	   success = false;
           } catch (NoSuchEndEntityException e) {
        	   success = false;
           }
       }
       if ( lastWaitException != null ) {
    	   throw lastWaitException;
       }
       if ( lastAppException != null ) {
    	   throw lastAppException;
       }
       if ( lastRevokedException != null ) {
    	   throw lastRevokedException;
       }
       return success;
    }

    public boolean isAllTokenCertificatesRevoked(String tokensn, String username) {
    	Collection<Certificate> certs = hardtokensession.findCertificatesInHardToken(tokensn);
    	boolean allrevoked = true;
    	if(!certs.isEmpty()){
    		Iterator<Certificate> j = certs.iterator();
    		while(j.hasNext()){
    			Certificate cert = j.next();
    			boolean isrevoked = certificatesession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
    			if (!isrevoked) {
    				allrevoked = false;
    			}
    		}
    	}
    	return allrevoked;
    }

    public void loadCACertificates(CertificateView[] cacerts) {
        certificates = cacerts;
    }

    public void loadCertificates(BigInteger serno, int caId) throws AuthorizationDeniedException {
			loadCertificates(serno, caSession.getCAInfo(administrator, caId).getSubjectDN());
    }

    public void loadCertificates(BigInteger serno, String issuerdn) throws AuthorizationDeniedException {
    	if (!authorizationSession.isAuthorizedNoLogging(administrator, AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.REGULAR_VIEWCERTIFICATE, "Not authorized to view certificate.");
	        throw new AuthorizationDeniedException(msg);
        }
    	final CertificateDataWrapper cdw = certificatesession.getCertificateDataByIssuerAndSerno(issuerdn, serno);
        if (cdw != null) {
            final String username = cdw.getCertificateData().getUsername();
            if (endEntityAccessSession.findUser(administrator, username) != null) {
                final int endentityprofileid = endEntityAccessSession.findUser(administrator, username).getEndEntityProfileId();
                endEntityAuthorization(administrator, endentityprofileid, AccessRulesConstants.VIEW_END_ENTITY, true);
            }
            certificates = new CertificateView[] { new CertificateView(cdw) };
        } else {
            certificates = null;
        }
    }

    /** @return the maximum size of the result from SQL select queries */
    public int getMaximumQueryRowCount() {
        GlobalCesecoreConfiguration globalConfiguration = (GlobalCesecoreConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        return globalConfiguration.getMaximumQueryCount();
    }

    public int getNumberOfCertificates() {
    	int returnval=0;
    	if (certificates != null) {
    		returnval=certificates.length;
    	}
    	return returnval;
    }

    public CertificateView getCertificate(int index) {
    	CertificateView returnval = null;
    	if(certificates != null){
    		returnval = certificates[index];
    	}
    	return returnval;
    }

    public boolean authorizedToEditUser(int profileid) {
    	return endEntityAuthorization(administrator, profileid, AccessRulesConstants.EDIT_END_ENTITY, false);
    }

    public boolean authorizedToViewHistory(int profileid) {
    	return endEntityAuthorization(administrator, profileid, AccessRulesConstants.VIEW_END_ENTITY_HISTORY, false);
    }

    public boolean authorizedToViewHardToken(String username) throws AuthorizationDeniedException {
    	int profileid = endEntityAccessSession.findUser(administrator, username).getEndEntityProfileId();
    	if (!endEntityAuthorization(administrator, profileid, AccessRulesConstants.HARDTOKEN_RIGHTS, false)) {
    		throw new AuthorizationDeniedException();
    	}
    	if (!WebConfiguration.getHardTokenDiplaySensitiveInfo()) {
    		return false;
    	}
    	return endEntityAuthorization(administrator, profileid, AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS, false);
    }

    public boolean authorizedToViewHardToken(int profileid) {
    	return endEntityAuthorization(administrator, profileid, AccessRulesConstants.HARDTOKEN_RIGHTS, false);
    }

    public boolean authorizedToRevokeCert(String username) throws AuthorizationDeniedException{
    	boolean returnval=false;
    	EndEntityInformation data = endEntityAccessSession.findUser(administrator, username);
    	if (data == null) {
    		return false;
    	}
    	int profileid = data.getEndEntityProfileId();
    	if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
    		returnval= endEntityAuthorization(administrator, profileid, AccessRulesConstants.REVOKE_END_ENTITY, false);
    	} else {
    		returnval=true;
    	}
    	return returnval;
    }

    public boolean keyRecoveryPossible(Certificate cert, String username) throws AuthorizationDeniedException {
    	boolean returnval = true;
    	returnval = authorizationSession.isAuthorizedNoLogging(administrator, AccessRulesConstants.REGULAR_KEYRECOVERY);
    	if (getGlobalConfiguration().getEnableEndEntityProfileLimitations()) {
    		EndEntityInformation data = endEntityAccessSession.findUser(administrator, username);
    		if (data != null) {
    			int profileid = data.getEndEntityProfileId();
    			returnval = endEntityAuthorization(administrator, profileid, AccessRulesConstants.KEYRECOVERY_RIGHTS, false);
    		} else {
    			returnval = false;
    		}
    	}
    	return returnval && keyrecoverysession.existsKeys(EJBTools.wrap(cert)) && !keyrecoverysession.isUserMarked(username);
    }

    public void markForRecovery(String username, Certificate cert) throws AuthorizationDeniedException, ApprovalException,
                    WaitingForApprovalException, CADoesntExistsException {
    	boolean authorized = true;
    	int endEntityProfileId = endEntityAccessSession.findUser(administrator, username).getEndEntityProfileId();
    	if(getGlobalConfiguration().getEnableEndEntityProfileLimitations()){
    		authorized = endEntityAuthorization(administrator, endEntityProfileId, AccessRulesConstants.KEYRECOVERY_RIGHTS, false);
    	}
    	if(authorized){
    		endEntityManagementSession.prepareForKeyRecovery(administrator, username, endEntityProfileId, cert);
    	}
    }

    public String getCertificateProfileName(int certificateprofileid) {
    	return certificateProfileSession.getCertificateProfileName(certificateprofileid);
    }

    /** Help function used to check end entity profile authorization. */
    private boolean endEntityAuthorization(AuthenticationToken admin, int profileid, String rights, boolean log) {
    	boolean returnval = false;
    	if (log) {
    		returnval = authorizationSession.isAuthorized(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + Integer.toString(profileid) + rights,
    		        AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
    	} else {
    		returnval = authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + Integer.toString(profileid)
    				+ rights, AccessRulesConstants.REGULAR_RAFUNCTIONALITY + rights);
    	}
    	return returnval;
    }

    public String getFormatedCertSN(CertificateView certificateData) {

    	String serialnumber = certificateData.getSerialNumber();
    	if(StringUtils.equals(certificateData.getType(), "X.509")) {
    		if((serialnumber.length()%2) != 0) {
    			serialnumber = "0" + serialnumber;
    		}

    		int octetChar = serialnumber.charAt(0) - '0';
    		if(octetChar > 7) {
    			serialnumber = "00" + serialnumber;
    		}

    	}
    	return serialnumber;

    }
    
    /**
     * Method that calculates the available CAs to an end entity. Used in add/edit end entity pages. It calculates a set of available CAs as an
     * intersection of: - The administrator's authorized CAs, the end entity profile's available CAs and the certificate profile's available CAs.
     *
     * @param endentityprofileid the EE profile of the end entity
     * @returns a HashMap of CertificateProfileIds mapped to Lists if CA IDs. It returns a set of available CAs per end entity profile.
     */

    public Map<Integer, List<Integer>> getCasAvailableToEndEntity(int endentityprofileid, final String endentityAccessRule) {
        final Map<Integer, List<Integer>> ret = new HashMap<>();
        // Create a TreeMap to get a sorted list.
        final TreeMap<CAInfo, Integer> sortedMap = new TreeMap<>(new Comparator<CAInfo>() {
            @Override
            public int compare(CAInfo o1, CAInfo o2) {
                return o1.getName().compareToIgnoreCase(o2.getName());
            }
        });
        // 1. Retrieve a list of all CA's the current user is authorized to
        for (CAInfo caInfo : caSession.getAuthorizedAndNonExternalCaInfos(administrator)) {
            sortedMap.put(caInfo, caInfo.getCAId());
        }
        final Collection<Integer> authorizedCas = sortedMap.values();
        // 2. Retrieve the list of CA's available to the end entity profile
        final EndEntityProfile endentityprofile = endEntityProfileSession.getEndEntityProfile(endentityprofileid);
        final List<Integer> casDefineInEndEntityProfile = new ArrayList<>(endentityprofile.getAvailableCAs());
        boolean allCasDefineInEndEntityProfile = false;
        if (casDefineInEndEntityProfile.contains(Integer.valueOf(SecConst.ALLCAS))) {
            allCasDefineInEndEntityProfile = true;
        }
        // 3. Next retrieve all certificate profiles defined in the end entity profile
        for (final Integer certificateProfileId : endentityprofile.getAvailableCertificateProfileIds()) {
            final CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(certificateProfileId.intValue());
            // 4. Retrieve all CAs defined in the current certificate profile
            final Collection<Integer> casDefinedInCertificateProfile;
            if (certprofile != null) {
                casDefinedInCertificateProfile = certprofile.getAvailableCAs();
            } else {
                casDefinedInCertificateProfile = new ArrayList<>();
            }
            // First make a clone of the full list of available CAs
            final List<Integer> authorizedCasClone = new ArrayList<>(authorizedCas);
            if (!casDefinedInCertificateProfile.contains(Integer.valueOf(CertificateProfile.ANYCA))) {
                //If ANYCA wasn't defined among the list from the cert profile, only keep the intersection
                authorizedCasClone.retainAll(casDefinedInCertificateProfile);
            }
            if (!allCasDefineInEndEntityProfile) {
                //If ALL wasn't defined in the EE profile, only keep the intersection
                authorizedCasClone.retainAll(casDefineInEndEntityProfile);
            }
            ret.put(certificateProfileId, authorizedCasClone);
        }
        return ret;
    }
}
