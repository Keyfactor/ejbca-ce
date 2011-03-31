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
package org.ejbca.core.protocol.ws;

import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ErrorCode;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.authorization.AuthenticationFailedException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.Authorizer;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.core.protocol.ws.logger.TransactionTags;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.PinDataWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.util.CertTools;
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.dn.DNFieldsUtil;
import org.ejbca.util.query.Query;

/** Helper class for other classes that wants to call remote EJBs.
 * Methods for fetching ejb session bean interfaces.
 * 
 * @version $Id$
 */
public class EjbcaWSHelper {

    private static final Logger log = Logger.getLogger(EjbcaWSHelper.class);

    private static final InternalResources intres = InternalResources.getInstance();

    private WebServiceContext wsContext;
    private AuthorizationSession authorizationSession;
    private CAAdminSession caAdminSession;
    private CertificateStoreSession certificateStoreSession;
    private CertificateProfileSession certificateProfileSession;
    private HardTokenSession hardTokenSession;
    private EndEntityProfileSession endEntityProfileSession;
    private UserAdminSession userAdminSession;

    protected EjbcaWSHelper(WebServiceContext wsContext, AuthorizationSession authorizationSession, CAAdminSession caAdminSession,
            CertificateProfileSession certificateProfileSession, CertificateStoreSession certificateStoreSession,
            EndEntityProfileSession endEntityProfileSession, HardTokenSession hardTokenSession, UserAdminSession userAdminSession) {
    	this.wsContext = wsContext;
		this.authorizationSession = authorizationSession;
		this.caAdminSession = caAdminSession;
		this.certificateProfileSession = certificateProfileSession;
		this.certificateStoreSession = certificateStoreSession;
		this.hardTokenSession = hardTokenSession;
		this.endEntityProfileSession = endEntityProfileSession;
		this.userAdminSession = userAdminSession;
	}
	
	//
	// Helper methods for various tasks done from the WS interface
	//

	/**
	 * Gets an Admin object for a WS-API administrator authenticated with client certificate SSL.
	 * Also checks that the admin, if it exists in EJCBA, have access to /administrator, i.e. really is an administrator.
	 * Does not check any other authorization though, other than that it is an administrator.
	 * Also checks that the admin certificate is not revoked.
	 * 
	 * @param wsContext web service context that contains the SSL information
	 * @return Admin object based on the SSL client certificate
	 */
	protected Admin getAdmin() throws AuthorizationDeniedException, EjbcaException{		  
		  return getAdmin(false);
	}
	
	/**
	 * Gets an Admin object for a WS-API administrator authenticated with client certificate SSL.
	 * Also, optionally (if allowNonAdmin == false), checks that the admin, if it exists in EJCBA, have access to /administrator, i.e. really is an administrator.
	 * Does not check any other authorization though, other than that it is an administrator.
	 * Also checks that the admin certificate is not revoked.
	 * 
	 * @param allowNonAdmins true if we should verify that it is a real administrator, false only extracts the certificate and checks that it is not revoked.
	 * @param wsContext web service context that contains the SSL information
	 * @return Admin object based on the SSL client certificate
	 */
	protected Admin getAdmin(boolean allowNonAdmins) throws AuthorizationDeniedException, EjbcaException {
		Admin admin = null;
		try {
			MessageContext msgContext = wsContext.getMessageContext();
			HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
			X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

			if ((certificates == null) || (certificates[0] == null)) {
				throw new AuthorizationDeniedException("Error no client certificate recieved used for authentication.");
			}

			X509Certificate cert = certificates[0];
			admin = userAdminSession.getAdmin(cert);
			// Check that user have the administrator flag set.
			if(!allowNonAdmins){
				userAdminSession.checkIfCertificateBelongToUser(admin, CertTools.getSerialNumber(cert), CertTools.getIssuerDN(cert));
				if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_ADMINISTRATOR)) {
				    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_ADMINISTRATOR, null);
				}
			}

			try {
				certificateStoreSession.authenticate(cert, WebConfiguration.getRequireAdminCertificateInDatabase());
			} catch (AuthenticationFailedException e) {
				// The message from here is usually the same as we used to hardcode here...
            	//String msg = intres.getLocalizedMessage("authentication.revokedormissing");
				// But it can also be that the certificate has expired, very unlikely since the SSL server checks that
				throw new AuthorizationDeniedException(e.getMessage());
			}
		} catch (EJBException e) {
			log.error("EJBCA WebService error: ",e);
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
		}

		return admin;
	}
	
	/**
	 * Method used to check if the admin is an administrator
	 * i.e have administrator flag set and access to resource
	 * /administrator
	 * @return
	 * @throws AuthorizationDeniedException 
	 */
	protected boolean isAdmin() throws EjbcaException {
		boolean retval = false;
		MessageContext msgContext = wsContext.getMessageContext();
		HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
		X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

		if(certificates == null){
			throw new EjbcaException(ErrorCode.AUTH_CERT_NOT_RECEIVED, 
                "Error no client certificate recieved used for authentication.");
		}

		try{
			Admin admin = userAdminSession.getAdmin(certificates[0]);
			userAdminSession.checkIfCertificateBelongToUser(admin, CertTools.getSerialNumber(certificates[0]), CertTools.getIssuerDN(certificates[0]));
			if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ROLE_ADMINISTRATOR)) {
			    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ROLE_ADMINISTRATOR, null);
			}
			retval = true;
		}catch(AuthorizationDeniedException e){
		} catch (EJBException e) {			
			log.error("Error checking if isAdmin: ", e);
		} 
		
		return retval;
	}

	protected void isAuthorizedToRepublish(Admin admin, String username, int caid) throws AuthorizationDeniedException, EjbcaException {
		try {
			if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
			    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_VIEWCERTIFICATE, null);
			}
			UserDataVO userdata = userAdminSession.findUser(admin, username);
			if(userdata == null){
				String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
				throw new EjbcaException(ErrorCode.USER_NOT_FOUND, msg);
			}
			if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.VIEW_RIGHTS)) {
			    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.VIEW_RIGHTS, null);
			}
			if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.CAPREFIX + caid )){
			    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.CAPREFIX + caid, null);
			}

		} catch (EJBException e) {
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e);
		}

	}
	
	
	protected void isAuthorizedToHardTokenData(Admin admin, String username, boolean viewPUKData) throws AuthorizationDeniedException, EjbcaException {
		try {
			if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_VIEWHARDTOKENS)) {
			    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_VIEWHARDTOKENS, null);
			}
			UserDataVO userdata = userAdminSession.findUser(admin, username);
			if(userdata == null){
				String msg = intres.getLocalizedMessage("ra.errorentitynotexist", username);            	
				throw new EjbcaException(ErrorCode.USER_NOT_FOUND, msg);
			}

			if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_VIEWHARDTOKENS)) {
			    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_VIEWHARDTOKENS, null);
			}
			if(viewPUKData){
				if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.REGULAR_VIEWPUKS)) {
				    Authorizer.throwAuthorizationException(admin, AccessRulesConstants.REGULAR_VIEWPUKS, null);
				}
			}

			if(userdata != null){
			    if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_RIGHTS)) {
			        Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_RIGHTS, null);
			    }
				if(viewPUKData){
				    if(!authorizationSession.isAuthorizedNoLog(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS)) {	
				        Authorizer.throwAuthorizationException(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS, null);
				    }
				}
			}

		} catch (EJBException e) {
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e);
		}		
	}
	
	protected UserDataVO convertUserDataVOWS(Admin admin, UserDataVOWS userdata) throws CADoesntExistsException, EjbcaException, ClassCastException {
		final CAInfo cainfo = caAdminSession.getCAInfoOrThrowException(admin,userdata.getCaName());
		final int caid = cainfo.getCAId();
		if (caid == 0) {
			throw new CADoesntExistsException("Error CA " + userdata.getCaName() + " have caid 0, which is impossible.");
		}
		
		final int endentityprofileid = endEntityProfileSession.getEndEntityProfileId(admin,userdata.getEndEntityProfileName());
		if(endentityprofileid == 0){
			throw new EjbcaException(ErrorCode.EE_PROFILE_NOT_EXISTS, 
                "Error End Entity profile " + userdata.getEndEntityProfileName() + " doesn't exists.");
		}

		final int certificateprofileid = certificateProfileSession.getCertificateProfileId(admin,userdata.getCertificateProfileName());
		if(certificateprofileid == 0){
			throw new EjbcaException(ErrorCode.CERT_PROFILE_NOT_EXISTS,
                "Error Certificate profile " + userdata.getCertificateProfileName() + " doesn't exists.");
		}
		
		final int hardtokenissuerid;
		if(userdata.getHardTokenIssuerName() != null){
         hardtokenissuerid = hardTokenSession.getHardTokenIssuerId(admin,userdata.getHardTokenIssuerName());
		   if(hardtokenissuerid == 0){
			  throw new EjbcaException(ErrorCode.HARD_TOKEN_ISSUER_NOT_EXISTS,
                  "Error Hard Token Issuer " + userdata.getHardTokenIssuerName() + " doesn't exists.");
		   }
		} else {
			hardtokenissuerid = 0;
		}
		
		final int tokenid = getTokenId(admin,userdata.getTokenType());
		if(tokenid == 0){
			throw new EjbcaException(ErrorCode.UNKOWN_TOKEN_TYPE,
                "Error Token Type  " + userdata.getTokenType() + " doesn't exists.");
		}

		final ExtendedInformation ei = new ExtendedInformation();
		boolean useEI = false;

		if(userdata.getStartTime() != null) {
			String customStartTime = userdata.getStartTime();
			try {
				if ( customStartTime.length()>0 && !customStartTime.matches("^\\d+:\\d?\\d:\\d?\\d$") && !customStartTime.matches("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$")) {
					// We use the old absolute time format, so we need to upgrade and log deprecation info
					final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
					final String newCustomStartTime = FastDateFormat.getInstance("yyyy-MM-dd HH:mm").format(oldDateFormat.parse(customStartTime));
					log.info("WS client sent userdata with startTime using US Locale date format. yyyy-MM-dd HH:mm should be used for absolute time and any fetched UserDataVOWS will use this format.");
					if (log.isDebugEnabled()) {
						log.debug(" Changed startTime \"" + customStartTime + "\" to \"" + newCustomStartTime + "\" in UserDataVOWS.");
					}
					customStartTime = newCustomStartTime;
				}
				ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, customStartTime);
				useEI = true;
			} catch (ParseException e) {
				log.info("WS client supplied invalid startTime in userData. startTime for this request was ignored. Supplied SubjectDN was \"" + userdata.getSubjectDN() + "\"");
				throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, "Invalid date format in StartTime.");
			}
		}
        if(userdata.getEndTime() != null) {
			String customEndTime = userdata.getEndTime();
			try {
				if ( customEndTime.length()>0 && !customEndTime.matches("^\\d+:\\d?\\d:\\d?\\d$") && !customEndTime.matches("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$")) {
					// We use the old absolute time format, so we need to upgrade and log deprecation info
					final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
					final String newCustomStartTime = FastDateFormat.getInstance("yyyy-MM-dd HH:mm").format(oldDateFormat.parse(customEndTime));
					log.info("WS client sent userdata with endTime using US Locale date format. yyyy-MM-dd HH:mm should be used for absolute time and any fetched UserDataVOWS will use this format.");
					if (log.isDebugEnabled()) {
						log.debug(" Changed endTime \"" + customEndTime + "\" to \"" + newCustomStartTime + "\" in UserDataVOWS.");
					}
					customEndTime = newCustomStartTime;
				}
	            ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, customEndTime);
	            useEI = true;
			} catch (ParseException e) {
				log.info("WS client supplied invalid endTime in userData. endTime for this request was ignored. Supplied SubjectDN was \"" + userdata.getSubjectDN() + "\"");
				throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, "Invalid date format in EndTime.");
			}
        }
        if ( userdata.getCertificateSerialNumber()!=null) {
            ei.setCertificateSerialNumber(userdata.getCertificateSerialNumber());
            useEI = true;
        }

        // Set generic Custom ExtendedInformation from potential data in UserDataVOWS
        List<ExtendedInformationWS> userei = userdata.getExtendedInformation();
        if (userei != null) {
            for (ExtendedInformationWS item : userei) {
            	String key = item.getName();
            	String value = item.getValue ();
            	if ((key != null) && (value != null)) {
            		if (log.isDebugEnabled()) {
            			log.debug("Set generic extended information: "+key+", "+value);
            		}
                    ei.setMapData(key, value);    			            		
                    useEI = true;
            	} else {
            		if (log.isDebugEnabled()) {
            			log.debug("Key or value is null when trying to set generic extended information.");
            		}
            	}
    		}
        }

        final UserDataVO userdatavo = new UserDataVO(userdata.getUsername(),
        		DNFieldsUtil.removeTrailingEmpties(userdata.getSubjectDN()),
				caid,
				userdata.getSubjectAltName(),
				userdata.getEmail(),
				userdata.getStatus(),
				userdata.getType(),
				endentityprofileid,
				certificateprofileid,
				null,
				null,
				tokenid,
				hardtokenissuerid,
				useEI ? ei : null);
		
		userdatavo.setPassword(userdata.getPassword());
		
		return userdatavo;
	}
	
	
	
	protected UserDataVOWS convertUserDataVO(Admin admin, UserDataVO userdata) throws EjbcaException, ClassCastException {
	    UserDataVOWS dataWS = new UserDataVOWS();
		String username = userdata.getUsername();
		String caname = caAdminSession.getCAInfo(admin,userdata.getCAId()).getName();

		dataWS.setUsername(username);

		if(caname == null){
			String message = "Error CA id " + userdata.getCAId() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.CA_NOT_EXISTS, message);
		}
		dataWS.setCaName(caname);
		
		String endentityprofilename = endEntityProfileSession.getEndEntityProfileName(admin,userdata.getEndEntityProfileId());
		if(endentityprofilename == null){
			String message = "Error End Entity profile id " + userdata.getEndEntityProfileId() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.EE_PROFILE_NOT_EXISTS, message);
		}
        dataWS.setEndEntityProfileName(endentityprofilename);

		String certificateprofilename = certificateProfileSession.getCertificateProfileName(admin,userdata.getCertificateProfileId());
		if(certificateprofilename == null){
			String message = "Error Certificate profile id " + userdata.getCertificateProfileId() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.CERT_PROFILE_NOT_EXISTS, message);
		}
	    dataWS.setCertificateProfileName(certificateprofilename);
		
		String hardtokenissuername = null;
		if(userdata.getHardTokenIssuerId() != 0){
		   hardtokenissuername = hardTokenSession.getHardTokenIssuerAlias(admin,userdata.getHardTokenIssuerId());
		   if(hardtokenissuername == null){
			   String message = "Error Hard Token Issuer id " + userdata.getHardTokenIssuerId() + " doesn't exists. User: "+username;
			   log.error(message);
			   throw new EjbcaException(ErrorCode.HARD_TOKEN_ISSUER_NOT_EXISTS, message);
		   }
		   dataWS.setHardTokenIssuerName(hardtokenissuername);
		}
		
		String tokenname = getTokenName(admin,userdata.getTokenType());
		if(tokenname == null){
			String message = "Error Token Type id " + userdata.getTokenType() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.UNKOWN_TOKEN_TYPE, message);
		}
		dataWS.setTokenType(tokenname);

		dataWS.setPassword(null);
		dataWS.setClearPwd(false);
		dataWS.setSubjectDN(userdata.getDN());
		dataWS.setSubjectAltName(userdata.getSubjectAltName());
		dataWS.setEmail(userdata.getEmail());
		dataWS.setStatus(userdata.getStatus());

		ExtendedInformation ei = userdata.getExtendedinformation();
		if(ei != null) {
		    dataWS.setStartTime(ei.getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
            dataWS.setEndTime(ei.getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
    		// Fill custom data in extended information
    		HashMap<String, ?> data = (HashMap<String,?>)ei.getData();
    		if (data != null) {
    			List<ExtendedInformationWS> extendedInfo = new ArrayList<ExtendedInformationWS> ();
    			Set<String> set = data.keySet();
    			for (Iterator<String> iterator = set.iterator(); iterator.hasNext();) {
    				String key = iterator.next();
    				String value = ei.getMapData(key);
    				if (value != null) {
    					extendedInfo.add(new ExtendedInformationWS (key, value));				
    				}
    			}
    			dataWS.setExtendedInformation(extendedInfo);
    		}
		}

		return dataWS;
	}

	XMLGregorianCalendar dateToXMKGregorianCalendar (Date date) throws DatatypeConfigurationException {
		GregorianCalendar cal = new GregorianCalendar ();
		cal.setTime(date);
		return DatatypeFactory.newInstance ().newXMLGregorianCalendar(cal);
	}

	/**
	 * Method used to convert a HardToken data to a WS version
	 * @param data
	 * @throws EjbcaException 
	 */
	protected HardTokenDataWS convertHardTokenToWS(HardTokenData data, Collection<java.security.cert.Certificate> certificates, boolean includePUK) throws EjbcaException {
		HardTokenDataWS retval = new HardTokenDataWS();
		retval.setHardTokenSN(data.getTokenSN());
		retval.setLabel(data.getHardToken().getLabel());
		retval.setCopyOfSN(data.getCopyOf());
		ArrayList<String> copies = new ArrayList<String>();
		if(data.getCopies() != null){
			Iterator<String> iter = data.getCopies().iterator();
			while(iter.hasNext()){
				copies.add(iter.next());

			}
		}
		retval.setCopies(copies);
		try{
			retval.setModifyTime(dateToXMKGregorianCalendar(data.getModifyTime()));
			retval.setCreateTime(dateToXMKGregorianCalendar(data.getCreateTime()));
			retval.setEncKeyKeyRecoverable(false);

			Iterator<java.security.cert.Certificate> iter = certificates.iterator();
			while(iter.hasNext()){
				retval.getCertificates().add(new Certificate(iter.next()));
			}
		}catch(DatatypeConfigurationException e){
			log.error("EJBCA WebService error, getHardToken: ",e);
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
		}catch(CertificateEncodingException e){
			log.error("EJBCA WebService error, getHardToken: ",e);
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
		}


		if(data.getHardToken() instanceof SwedishEIDHardToken){
			SwedishEIDHardToken ht = (SwedishEIDHardToken) data.getHardToken();
			if(includePUK){
			  retval.getPinDatas().add(new PinDataWS(HardTokenConstants.PINTYPE_SIGNATURE,ht.getInitialSignaturePIN(),ht.getSignaturePUK()));
			  retval.getPinDatas().add(new PinDataWS(HardTokenConstants.PINTYPE_BASIC,ht.getInitialAuthEncPIN(),ht.getAuthEncPUK()));
			}
			retval.setTokenType(HardTokenConstants.TOKENTYPE_SWEDISHEID);
			return retval;
		}
		if(data.getHardToken() instanceof EnhancedEIDHardToken){
			EnhancedEIDHardToken ht = (EnhancedEIDHardToken) data.getHardToken();
			retval.setEncKeyKeyRecoverable(ht.getEncKeyRecoverable());
			if(includePUK){
				retval.getPinDatas().add(new PinDataWS(HardTokenConstants.PINTYPE_SIGNATURE,ht.getInitialSignaturePIN(),ht.getSignaturePUK()));
				retval.getPinDatas().add(new PinDataWS(HardTokenConstants.PINTYPE_BASIC,ht.getInitialAuthPIN(),ht.getAuthPUK()));
			}
			retval.setTokenType(HardTokenConstants.TOKENTYPE_ENHANCEDEID);
			return retval;
		}
		if(data.getHardToken() instanceof TurkishEIDHardToken){
			TurkishEIDHardToken ht = (TurkishEIDHardToken) data.getHardToken();
			if(includePUK){
			  retval.getPinDatas().add(new PinDataWS(HardTokenConstants.PINTYPE_BASIC,ht.getInitialPIN(),ht.getPUK()));
			}
			retval.setTokenType(HardTokenConstants.TOKENTYPE_TURKISHEID);
			return retval;
		}
		throw new EjbcaException(ErrorCode.INTERNAL_ERROR,
		                         "Error: only SwedishEIDHardToken, EnhancedEIDHardToken, TurkishEIDHardToken supported.");
	}
	
	/**
	 * Method that converts profilenames etc to corresponding Id's
	 * @param admin
	 * @param usermatch a usermatch containing names of profiles
	 * @return a query containing id's of profiles.
	 * @throws NumberFormatException
	 */
	protected Query convertUserMatch(Admin admin, UserMatch usermatch) throws NumberFormatException {
		Query retval = new Query(Query.TYPE_USERQUERY);		  		
		switch(usermatch.getMatchwith()){
		  case UserMatch.MATCH_WITH_ENDENTITYPROFILE:
			  String endentityprofilename = Integer.toString(endEntityProfileSession.getEndEntityProfileId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),endentityprofilename);
			  break;
		  case UserMatch.MATCH_WITH_CERTIFICATEPROFILE:
			  String certificateprofilename = Integer.toString(certificateProfileSession.getCertificateProfileId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),certificateprofilename);
			  break;			  
		  case UserMatch.MATCH_WITH_CA:
			  String caname = Integer.toString(caAdminSession.getCAInfo(admin,usermatch.getMatchvalue()).getCAId());
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),caname);
			  break;	
		  case UserMatch.MATCH_WITH_TOKEN:
			  String tokenname = Integer.toString(getTokenId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),tokenname);
			  break;
		  default:		
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),usermatch.getMatchvalue());
			  break;
		}
		return retval;
	}
	
	/**
	 * Help method returning a subset of certificates containing only valid certificates
	 * expiredate and revocation status is checked.
	 * @throws ClassCastException 
	 */
	protected Collection<java.security.cert.Certificate> returnOnlyValidCertificates(Admin admin, Collection<java.security.cert.Certificate> certs) {
     ArrayList<java.security.cert.Certificate> retval = new ArrayList<java.security.cert.Certificate>();
     Iterator<java.security.cert.Certificate> iter = certs.iterator();
     while(iter.hasNext()){
    	 java.security.cert.Certificate next = iter.next();
  	   
  	   boolean isrevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(next),CertTools.getSerialNumber(next));
  	   if (!isrevoked) {
  		   try{
  			   CertTools.checkValidity(next, new Date());
  			   retval.add(next);
  		   }catch(CertificateExpiredException e){    			   
  		   }catch (CertificateNotYetValidException e) {    			   
  		   }
  	   }
     }
	
     return retval;
	}
	
	/**
	 * Checks authorization for each certificate and optionally check that it's valid. Does not check revocation status. 
	 * @param admin is the admin used for authorization
	 * @param certs is the collection of certs to verify
	 * @param validate set to true to perform validation of each certificate
	 * @return a List of valid and authorized certificates
	 */
	protected List<Certificate> returnAuthorizedCertificates(final Admin admin, final Collection<java.security.cert.Certificate> certs, final boolean validate) {
		final List<Certificate> retval = new ArrayList<Certificate>();
		final Map<Integer, Boolean> authorizationCache = new HashMap<Integer, Boolean>();
		final Date now = new Date();
		for (final java.security.cert.Certificate next : certs) {
			try {
				if (validate) {
					// Check validity
					CertTools.checkValidity(next, now);
				}
				// Check authorization
				final int caid = CertTools.getIssuerDN(next).hashCode();
				Boolean authorized = authorizationCache.get(caid);
				if (authorized == null) {
					authorized = authorizationSession.isAuthorizedNoLog(admin,AccessRulesConstants.CAPREFIX +caid);
					authorizationCache.put(caid, authorized);
				}
				if (authorized.booleanValue()) {
					retval.add(new Certificate((java.security.cert.Certificate) next));
				}
			} catch (CertificateExpiredException e) {		// Drop invalid cert
			} catch (CertificateNotYetValidException e) {   // Drop invalid cert
			} catch (CertificateEncodingException e) {		// Drop invalid cert
				log.error("A defect certificate was detected.");
			} 
		}
		return retval;
	}
	
	
	private final String[] softtokennames = {UserDataVOWS.TOKEN_TYPE_USERGENERATED,UserDataVOWS.TOKEN_TYPE_P12,
			                                 UserDataVOWS.TOKEN_TYPE_JKS,UserDataVOWS.TOKEN_TYPE_PEM};
	private final int[] softtokenids = {SecConst.TOKEN_SOFT_BROWSERGEN,
			SecConst.TOKEN_SOFT_P12, SecConst.TOKEN_SOFT_JKS, SecConst.TOKEN_SOFT_PEM};
	
	private int getTokenId(Admin admin, String tokenname) {
      int returnval = 0;
      
      // First check for soft token type
      for(int i=0;i< softtokennames.length;i++){
      	if(softtokennames[i].equals(tokenname)){
      		returnval = softtokenids[i];
      		break;
      	}        	
      }
      if (returnval == 0) {
           returnval = hardTokenSession.getHardTokenProfileId(admin , tokenname);
      }

      return returnval;
	}
	
	private String getTokenName(Admin admin, int tokenid) {
      String returnval = null;
      
      // First check for soft token type
      for(int i=0;i< softtokenids.length;i++){
      	if(softtokenids[i] == tokenid){
      		returnval = softtokennames[i];
      		break;
      	}        	
      }
      if (returnval == null) {
           returnval = hardTokenSession.getHardTokenProfileName(admin , tokenid);
      }

      return returnval;
	}

  /**
	 * Web services does not support Collection type so convert it to array.
	 * 
	 * @param mytree TreeMap of name and id pairs to convert to an array
	 * @return array of NameAndId objects
	 */
  protected NameAndId[] convertTreeMapToArray(TreeMap<String, Integer> mytree) {
  	NameAndId[] ret = null;

		if ((mytree == null) || (mytree.size() == 0) ) {
			ret = new NameAndId[0];
		} else {
			ret = new NameAndId[mytree.size()];
			int i = 0;
			for (String name : mytree.keySet()) {
				ret[i++] = new NameAndId(name, mytree.get(name));
			}
		}
		return ret;
	}

	protected void resetUserPasswordAndStatus(Admin admin, String username, int status) {
		try {
			userAdminSession.setPassword(admin, username, null);
			userAdminSession.setUserStatus(admin, username, status);	
			log.debug("Reset user password to null and status to "+status);
		} catch (Exception e) {
			// Catch all because this reset method will be called from withing other catch clauses
			log.error(e);
		}
	}

	protected boolean checkValidityAndSetUserPassword(Admin admin, java.security.cert.Certificate cert, String username, String password) 
	throws ServiceLocatorException, CertificateNotYetValidException, CertificateExpiredException, UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException {
		boolean ret = false;
		try {
			// Check validity of the certificate after verifying the signature
			CertTools.checkValidity(cert, new Date());
			log.debug("The verifying certificate was valid");
			// Verification succeeded, lets set user status to new, the password as passed in and proceed
			String msg = intres.getLocalizedMessage("cvc.info.renewallowed", CertTools.getFingerprintAsString(cert), username);            	
			log.info(msg);
			userAdminSession.setPassword(admin, username, password);
			userAdminSession.setUserStatus(admin, username, UserDataConstants.STATUS_NEW);
			// If we managed to verify the certificate we will break out of the loop									
			ret = true;															
		} catch (CertificateNotYetValidException e) {
			// If verification of outer signature fails because the old certificate is not valid, we don't really care, continue as if it was an initial request  
			log.debug("Certificate we try to verify outer signature with is not yet valid");
			throw e;
		} catch (CertificateExpiredException e) {									
			log.debug("Certificate we try to verify outer signature with has expired");
			throw e;
		}
		return ret;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
	 */
	protected void caCertResponse(EjbcaWSHelper ejbhelper, Admin admin, String caname, byte[] cert, List<byte[]> cachain, String keystorepwd) 
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CertPathValidatorException {
		try {
			CAInfo cainfo = caAdminSession.getCAInfo(admin, caname);
			// create response messages, for CVC certificates we use a regular X509ResponseMessage
			X509ResponseMessage msg = new X509ResponseMessage();
			msg.setCertificate(CertTools.getCertfromByteArray(cert));
			caAdminSession.receiveResponse(admin, cainfo.getCAId(), msg, cachain, keystorepwd);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, null);
		}
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
	 */
	protected byte[] caRenewCertRequest(EjbcaWSHelper ejbhelper, Admin admin, String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepwd) 
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CertPathValidatorException {
		CAInfo cainfo = caAdminSession.getCAInfoOrThrowException(admin, caname);
		return caAdminSession.makeRequest(admin, cainfo.getCAId(), cachain, regenerateKeys, usenextkey, activatekey, keystorepwd);				
	}

	protected  static EjbcaException getInternalException(Throwable t, IPatternLogger logger) {
        return getEjbcaException( t, logger, ErrorCode.INTERNAL_ERROR, Level.ERROR);
	}

	protected static EjbcaException getEjbcaException(Throwable t, IPatternLogger logger, ErrorCode errorCode, Priority p) {
        log.log(p, "EJBCA WebService error", t);
        if (logger != null) {
            logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), errorCode.toString());        	
        }
        return new EjbcaException(errorCode, t.getMessage());
	}

	protected  static EjbcaException getEjbcaException(String s, IPatternLogger logger, ErrorCode errorCode, Priority p) {
        if ( p!=null ) {
            log.log(p, s);
        }
        if (logger != null) {
        	logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), s);
        }
        if ( errorCode!=null ) {
            if (logger != null) {
            	logger.paramPut(TransactionTags.ERROR_MESSAGE.toString(), errorCode.toString());
            }
            return new EjbcaException(errorCode, s);
        }
        return new EjbcaException(s);
    }

}