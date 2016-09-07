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
import java.util.HashSet;
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

import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.EndEntityAccessSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.hardtoken.HardTokenConstants;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.ws.logger.TransactionTags;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.PinDataWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.util.IPatternLogger;
import org.ejbca.util.cert.OID;
import org.ejbca.util.query.Query;

/** Helper class for other classes that wants to call remote EJBs.
 * Methods for fetching ejb session bean interfaces.
 * 
 * @version $Id$
 */
public class EjbcaWSHelper {

    private static final Logger log = Logger.getLogger(EjbcaWSHelper.class);

    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private WebServiceContext wsContext;
    private AccessControlSessionLocal authorizationSession;
    private CAAdminSession caAdminSession;
    private CaSessionLocal caSession;
    private CertificateStoreSession certificateStoreSession;
    private CertificateProfileSession certificateProfileSession;
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    private HardTokenSession hardTokenSession;
    private EndEntityAccessSession endEntityAccessSession;
    private EndEntityProfileSession endEntityProfileSession;
    private EndEntityManagementSession endEntityManagementSession;
    private WebAuthenticationProviderSessionLocal authenticationSession;

    protected EjbcaWSHelper(WebServiceContext wsContext, AccessControlSessionLocal authorizationSession, CAAdminSession caAdminSession, CaSessionLocal caSession,
            CertificateProfileSession certificateProfileSession, CertificateStoreSession certificateStoreSession, EndEntityAccessSession endEntityAccessSession,
            EndEntityProfileSession endEntityProfileSession, HardTokenSession hardTokenSession, EndEntityManagementSession endEntityManagementSession,
            WebAuthenticationProviderSessionLocal authenticationSession, CryptoTokenManagementSessionLocal cryptoTokenManagementSession) {
    	this.wsContext = wsContext;
		this.authorizationSession = authorizationSession;
		this.caAdminSession = caAdminSession;
		this.caSession = caSession;
		this.certificateProfileSession = certificateProfileSession;
		this.certificateStoreSession = certificateStoreSession;
		this.cryptoTokenManagementSession = cryptoTokenManagementSession;
		this.hardTokenSession = hardTokenSession;
		this.endEntityProfileSession = endEntityProfileSession;
		this.endEntityManagementSession = endEntityManagementSession;
		this.endEntityAccessSession = endEntityAccessSession;
		this.authenticationSession = authenticationSession;
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
	protected AuthenticationToken getAdmin() throws AuthorizationDeniedException, EjbcaException{		  
		  return getAdmin(false);
	}
	
	/**
	 * Gets an AuthenticationToken object for a WS-API administrator authenticated with client certificate SSL.
     * - Checks (through authenticationSession.authenticate) that the certificate is valid
     * - If (WebConfiguration.getRequireAdminCertificateInDatabase) checks (through authenticationSession.authenticate) that the admin certificate is not revoked.
	 * - If (allowNonAdmin == false), checks that the admin have access to /administrator, i.e. really is an administrator with the certificate mapped in an admin role. 
	 *   Does not check any other authorization though, other than that it is an administrator.
	 * 
	 * @param allowNonAdmins false if we should verify that it is a real administrator, true only extracts the certificate and checks that it is not revoked.
	 * @return AuthenticationToken object based on the SSL client certificate
	 * @throws AuthorizationDeniedException if no client certificate or allowNonAdmins == false and the cert does not belong to an admin
	 */
	protected AuthenticationToken getAdmin(final boolean allowNonAdmins) throws AuthorizationDeniedException, EjbcaException {
		try {
			final MessageContext msgContext = wsContext.getMessageContext();
			final HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
			final X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

			if ((certificates == null) || (certificates[0] == null)) {
				throw new AuthorizationDeniedException("Error no client certificate recieved used for authentication.");
			}

			final X509Certificate cert = certificates[0];
            final Set<X509Certificate> credentials = new HashSet<X509Certificate>();
            credentials.add(certificates[0]);
            final AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
            final AuthenticationToken admin = authenticationSession.authenticate(subject);
            if ((admin != null) && (!allowNonAdmins)) {
				if(!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ROLE_ADMINISTRATOR)) {
		            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.ROLE_ADMINISTRATOR, null);
			        throw new AuthorizationDeniedException(msg);
				}
            } else if (admin == null) {
                final String msg = intres.getLocalizedMessage("authentication.failed", "No admin authenticated for certificate with serialNumber " +CertTools.getSerialNumber(cert)+" and issuerDN '"+CertTools.getIssuerDN(cert)+"'.");
                throw new AuthorizationDeniedException(msg);
            }
            return admin;
		} catch (EJBException e) {
			log.error("EJBCA WebService error, getAdmin: ",e);
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e.getMessage());
		}
	}
	
	/**
	 * Method used to check if the admin is an administrator
	 * i.e have administrator flag set and access to resource
	 * /administrator
	 * @return
	 * @throws AuthorizationDeniedException 
	 */
	protected boolean isAdmin() {
		boolean retval = false;
		try {
			if (getAdmin(false) != null) {
				retval = true;
			}
		} catch (AuthorizationDeniedException e) {
			if (log.isDebugEnabled()) {
				log.debug("Not an admin: ", e);
			}
		} catch (EjbcaException e) {
			if (log.isDebugEnabled()) {
				log.debug("Not an admin: ", e);
			}
		}
		return retval;
	}

	protected void isAuthorizedToRepublish(AuthenticationToken admin, String username, int caid) throws AuthorizationDeniedException, EjbcaException {
		try {
			if(!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
	            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.REGULAR_VIEWCERTIFICATE, null);
		        throw new AuthorizationDeniedException(msg);
			}
			EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
			if(userdata == null){
			    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
				String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");            	
				throw new EjbcaException(ErrorCode.USER_NOT_FOUND, msg);
			}
			if(!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.VIEW_END_ENTITY)) {
	            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.VIEW_END_ENTITY, null);
		        throw new AuthorizationDeniedException(msg);
			}
			if(!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid )){
	            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", StandardRules.CAACCESS.resource() + caid, null);
		        throw new AuthorizationDeniedException(msg);
			}

		} catch (EJBException e) {
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e);
		}

	}
	
	
	protected void isAuthorizedToHardTokenData(AuthenticationToken admin, String username, boolean viewPUKData) throws AuthorizationDeniedException, EjbcaException {
		try {
			if(!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_VIEWHARDTOKENS)) {
	            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.REGULAR_VIEWHARDTOKENS, null);
		        throw new AuthorizationDeniedException(msg);
			}
			EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
			if(userdata == null){
			    log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
				String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");            	
				throw new EjbcaException(ErrorCode.USER_NOT_FOUND, msg);
			}

			if(viewPUKData){
				if(!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_VIEWPUKS)) {
		            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.REGULAR_VIEWPUKS, null);
			        throw new AuthorizationDeniedException(msg);
				}
			}

			if(userdata != null){
			    if(!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_RIGHTS)) {
		            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_RIGHTS, null);
			        throw new AuthorizationDeniedException(msg);
			    }
				if(viewPUKData){
				    if(!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS)) {	
			            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS, null);
				        throw new AuthorizationDeniedException(msg);
				    }
				}
			}

		} catch (EJBException e) {
			throw new EjbcaException(ErrorCode.INTERNAL_ERROR, e);
		}		
	}

	protected static EndEntityInformation convertUserDataVOWS(final UserDataVOWS userdata, final int caid, final int endentityprofileid, final int certificateprofileid, final int hardtokenissuerid, final int tokenid) throws CADoesntExistsException, EjbcaException, ClassCastException, AuthorizationDeniedException {
        final ExtendedInformation ei = new ExtendedInformation();
        boolean useEI = false;

        if(userdata.getStartTime() != null) {
            String customStartTime = userdata.getStartTime();
            try {
                if (customStartTime.length()>0 && !customStartTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
                    if (!customStartTime.matches("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}.\\d{2}:\\d{2}$")) {
                        // We use the old absolute time format, so we need to upgrade and log deprecation info
                        final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
                        final String newCustomStartTime = ValidityDate.formatAsISO8601(oldDateFormat.parse(customStartTime), ValidityDate.TIMEZONE_UTC);
                        log.info("WS client sent userdata with startTime using US Locale date format. yyyy-MM-dd HH:mm:ssZZ should be used for absolute time and any fetched UserDataVOWS will use this format.");
                        if (log.isDebugEnabled()) {
                            log.debug(" Changed startTime \"" + customStartTime + "\" to \"" + newCustomStartTime + "\" in UserDataVOWS.");
                        }
                        customStartTime = newCustomStartTime;
                    }
                    customStartTime = ValidityDate.getImpliedUTCFromISO8601(customStartTime);
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
                if (customEndTime.length()>0 && !customEndTime.matches("^\\d+:\\d?\\d:\\d?\\d$")){
                    if (!customEndTime.matches("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}.\\d{2}:\\d{2}$")) {
                        // We use the old absolute time format, so we need to upgrade and log deprecation info
                        final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
                        final String newCustomStartTime = ValidityDate.formatAsISO8601(oldDateFormat.parse(customEndTime), ValidityDate.TIMEZONE_UTC);
                        log.info("WS client sent userdata with endTime using US Locale date format. yyyy-MM-dd HH:mm:ssZZ should be used for absolute time and any fetched UserDataVOWS will use this format.");
                        if (log.isDebugEnabled()) {
                            log.debug(" Changed endTime \"" + customEndTime + "\" to \"" + newCustomStartTime + "\" in UserDataVOWS.");
                        }
                        customEndTime = newCustomStartTime;
                    }
                    customEndTime = ValidityDate.getImpliedUTCFromISO8601(customEndTime);
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

        useEI = EjbcaWSHelper.setExtendedInformationFromUserDataVOWS(userdata, ei) || useEI;

        final EndEntityInformation endEntityInformation = new EndEntityInformation(userdata.getUsername(),
                userdata.getSubjectDN(),
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
        
        endEntityInformation.setPassword(userdata.getPassword());
        endEntityInformation.setCardNumber(userdata.getCardNumber());
        
        return endEntityInformation;
	}

	       
	protected EndEntityInformation convertUserDataVOWS(final AuthenticationToken admin, final UserDataVOWS userdata) throws CADoesntExistsException, EjbcaException, ClassCastException, AuthorizationDeniedException {
        // No need to check CA authorization here, we are only converting the user input. The actual authorization check in CA is done when 
        // trying to add/edit the user
		final CAInfo cainfo = caSession.getCAInfoInternal(-1,userdata.getCaName(), true);
		final int caid = cainfo.getCAId();
		if (caid == 0) {
			throw new CADoesntExistsException("Error CA " + userdata.getCaName() + " have caid 0, which is impossible.");
		}
		
		int endentityprofileid;
        try {
            endentityprofileid = endEntityProfileSession.getEndEntityProfileId(userdata.getEndEntityProfileName());
        } catch (EndEntityProfileNotFoundException e) {
            throw new EjbcaException(ErrorCode.EE_PROFILE_NOT_EXISTS, 
                    "Error End Entity profile " + userdata.getEndEntityProfileName() + " does not exist.", e);
        }

		final int certificateprofileid = certificateProfileSession.getCertificateProfileId(userdata.getCertificateProfileName());
		if(certificateprofileid == 0){
			throw new EjbcaException(ErrorCode.CERT_PROFILE_NOT_EXISTS,
                "Error Certificate profile " + userdata.getCertificateProfileName() + " does not exist.");
		}
		
		final int hardtokenissuerid;
		if(userdata.getHardTokenIssuerName() != null){
         hardtokenissuerid = hardTokenSession.getHardTokenIssuerId(userdata.getHardTokenIssuerName());
		   if(hardtokenissuerid == 0){
			  throw new EjbcaException(ErrorCode.HARD_TOKEN_ISSUER_NOT_EXISTS,
                  "Error Hard Token Issuer " + userdata.getHardTokenIssuerName() + " does not exist.");
		   }
		} else {
			hardtokenissuerid = 0;
		}
		
		final int tokenid = getTokenId(admin,userdata.getTokenType());
		if(tokenid == 0){
			throw new EjbcaException(ErrorCode.UNKOWN_TOKEN_TYPE,
                "Error Token Type  " + userdata.getTokenType() + " does not exist.");
		}

		return convertUserDataVOWS(userdata, caid, endentityprofileid, certificateprofileid, hardtokenissuerid, tokenid);
	}


	private static boolean setExtendedInformationFromUserDataVOWS( UserDataVOWS userdata, ExtendedInformation ei ) {
		// Set generic Custom ExtendedInformation from potential data in UserDataVOWS
		final List<ExtendedInformationWS> userei = userdata.getExtendedInformation();
		if ( userei==null ) {
			return false;
		}
		boolean useEI = false;
		for (ExtendedInformationWS item : userei) {
			final String key = item.getName();
			final String value = item.getValue ();
			if ( value==null || key==null ) {
				if (log.isDebugEnabled()) {
					log.debug("Key or value is null when trying to set generic extended information.");
				}
				continue;
			}
			if ( OID.isStartingWithValidOID(key)  ) {
				ei.setExtensionData(key, value);
				if (log.isDebugEnabled()) {
					log.debug("Set certificate extension: "+key+", "+value);
				}
			} else {
				ei.setMapData(key, value);
				if (log.isDebugEnabled()) {
					log.debug("Set generic extended information: "+key+", "+value);
				}
			}
			useEI = true;
		}
		return useEI;
	}

	protected static UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation, final String caname, final String endentityprofilename, 
	        final String certificateprofilename, final String hardtokenissuername, final String tokenname) throws EjbcaException, ClassCastException, CADoesntExistsException, AuthorizationDeniedException {
        final UserDataVOWS dataWS = new UserDataVOWS();
        dataWS.setUsername(endEntityInformation.getUsername());
        dataWS.setCaName(caname);
        dataWS.setEndEntityProfileName(endentityprofilename);
        dataWS.setCertificateProfileName(certificateprofilename);
        dataWS.setHardTokenIssuerName(hardtokenissuername);
        dataWS.setTokenType(tokenname);

        dataWS.setPassword(null);
        dataWS.setClearPwd(false);
        dataWS.setSubjectDN(endEntityInformation.getDN());
        dataWS.setSubjectAltName(endEntityInformation.getSubjectAltName());
        dataWS.setEmail(endEntityInformation.getEmail());
        dataWS.setStatus(endEntityInformation.getStatus());
        dataWS.setCardNumber(endEntityInformation.getCardNumber());

        final ExtendedInformation ei = endEntityInformation.getExtendedinformation();
        if(ei != null) {
            String startTime = ei.getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
            if (startTime!=null && startTime.length()>0 && !startTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
                try {
                    // Always respond with the time formatted in a neutral time zone
                    startTime = ValidityDate.getISO8601FromImpliedUTC(startTime, ValidityDate.TIMEZONE_UTC);
                } catch (ParseException e) {
                    log.info("Failed to convert " + ExtendedInformation.CUSTOM_STARTTIME + " to ISO8601 format.");
                }
            }
            dataWS.setStartTime(startTime);
            String endTime = ei.getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
            if (endTime!=null && endTime.length()>0 && !endTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
                try {
                    // Always respond with the time formatted in a neutral time zone
                    endTime = ValidityDate.getISO8601FromImpliedUTC(endTime, ValidityDate.TIMEZONE_UTC);
                } catch (ParseException e) {
                    log.info("Failed to convert " + ExtendedInformation.CUSTOM_ENDTIME + " to ISO8601 format.");
                }
            }
            dataWS.setEndTime(endTime);
            // Fill custom data in extended information
            @SuppressWarnings("unchecked")
            final HashMap<String, ?> data = (HashMap<String,?>)ei.getData();
            if (data != null) {
                final List<ExtendedInformationWS> extendedInfo = new ArrayList<ExtendedInformationWS> ();
                final Set<String> set = data.keySet();
                for (Iterator<String> iterator = set.iterator(); iterator.hasNext();) {
                    final String key = iterator.next();
                    final String value = ei.getMapData(key);
                    if (value != null) {
                        extendedInfo.add(new ExtendedInformationWS (key, value));               
                    }
                }
                dataWS.setExtendedInformation(extendedInfo);
            }
        }

        return dataWS;
	}
	protected UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation) throws EjbcaException, ClassCastException, CADoesntExistsException, AuthorizationDeniedException {
        final String username = endEntityInformation.getUsername();
		// No need to check CA authorization here, we are only converting the user input. The actual authorization check in CA is done when 
		// trying to add/edit the user
		final String caname = caSession.getCAInfoInternal(endEntityInformation.getCAId(), null, true).getName();
		if (caname == null) {
			final String message = "Error CA id " + endEntityInformation.getCAId() + " does not exist. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.CA_NOT_EXISTS, message);
		}		

		final String endentityprofilename = endEntityProfileSession.getEndEntityProfileName(endEntityInformation.getEndEntityProfileId());
		if(endentityprofilename == null){
			final String message = "Error End Entity profile id " + endEntityInformation.getEndEntityProfileId() + " does not exist. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.EE_PROFILE_NOT_EXISTS, message);
		}

        final String certificateprofilename = certificateProfileSession.getCertificateProfileName(endEntityInformation.getCertificateProfileId());
		if(certificateprofilename == null){
		    final String message = "Error Certificate profile id " + endEntityInformation.getCertificateProfileId() + " does not exist. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.CERT_PROFILE_NOT_EXISTS, message);
		}
		
		final String hardtokenissuername;
		if(endEntityInformation.getHardTokenIssuerId() != 0){
		   hardtokenissuername = hardTokenSession.getHardTokenIssuerAlias(endEntityInformation.getHardTokenIssuerId());
		   if(hardtokenissuername == null){
		       final String message = "Error Hard Token Issuer id " + endEntityInformation.getHardTokenIssuerId() + " does not exist. User: "+username;
			   log.error(message);
			   throw new EjbcaException(ErrorCode.HARD_TOKEN_ISSUER_NOT_EXISTS, message);
		   }
		} else {
		    hardtokenissuername = null;
		}
		
		final String tokenname = getTokenName(endEntityInformation.getTokenType());
		if(tokenname == null){
		    final String message = "Error Token Type id " + endEntityInformation.getTokenType() + " does not exist. User: "+username;
			log.error(message);
			throw new EjbcaException(ErrorCode.UNKOWN_TOKEN_TYPE, message);
		}
		return convertEndEntityInformation(endEntityInformation, caname, endentityprofilename, certificateprofilename, hardtokenissuername, tokenname);
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
	protected HardTokenDataWS convertHardTokenToWS(HardTokenInformation data, Collection<java.security.cert.Certificate> certificates, boolean includePUK) throws EjbcaException {
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
	 * Method that converts profile names etc to corresponding ID's
	 * @param admin
	 * @param usermatch a usermatch containing names of profiles
	 * @return a query containing id's of profiles.
	 * @throws NumberFormatException
	 * @throws AuthorizationDeniedException 
	 * @throws CADoesntExistsException 
	 * @throws EndEntityProfileNotFoundException if usermatch was for and end entity profile, and that profile didn't exist
	 */
    protected Query convertUserMatch(AuthenticationToken admin, UserMatch usermatch) throws CADoesntExistsException,
            AuthorizationDeniedException, EndEntityProfileNotFoundException {
	Query retval = new Query(Query.TYPE_USERQUERY);		  		
		switch(usermatch.getMatchwith()){
		  case UserMatch.MATCH_WITH_ENDENTITYPROFILE:
			  String endentityprofilename = Integer.toString(endEntityProfileSession.getEndEntityProfileId(usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),endentityprofilename);
			  break;
		  case UserMatch.MATCH_WITH_CERTIFICATEPROFILE:
			  String certificateprofilename = Integer.toString(certificateProfileSession.getCertificateProfileId(usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),certificateprofilename);
			  break;			  
		  case UserMatch.MATCH_WITH_CA:
			  String caname = Integer.toString(caSession.getCAInfo(admin,usermatch.getMatchvalue()).getCAId());
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
	protected Collection<java.security.cert.Certificate> returnOnlyValidCertificates(AuthenticationToken admin, Collection<java.security.cert.Certificate> certs) {
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
	 * @param nowMillis current time
	 * @return a List of valid and authorized certificates
	 */
	protected List<Certificate> returnAuthorizedCertificates(final AuthenticationToken admin, final Collection<java.security.cert.Certificate> certs,
	        final boolean validate, final long nowMillis) {
		final List<Certificate> retval = new ArrayList<Certificate>();
		final Map<Integer, Boolean> authorizationCache = new HashMap<Integer, Boolean>();
		final Date now = new Date(nowMillis);
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
					authorized = authorizationSession.isAuthorizedNoLogging(admin,StandardRules.CAACCESS.resource() +caid);
					authorizationCache.put(caid, authorized);
				}
				if (authorized.booleanValue()) {
					retval.add(new Certificate(next));
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
	
	private int getTokenId(AuthenticationToken admin, String tokenname) {
      int returnval = 0;
      
      // First check for soft token type
      for(int i=0;i< softtokennames.length;i++){
      	if(softtokennames[i].equals(tokenname)){
      		returnval = softtokenids[i];
      		break;
      	}        	
      }
      if (returnval == 0) {
           returnval = hardTokenSession.getHardTokenProfileId(tokenname);
      }

      return returnval;
	}
	
	private String getTokenName(int tokenid) {
      String returnval = null;
      
      // First check for soft token type
      for(int i=0;i< softtokenids.length;i++){
      	if(softtokenids[i] == tokenid){
      		returnval = softtokennames[i];
      		break;
      	}        	
      }
      if (returnval == null) {
           returnval = hardTokenSession.getHardTokenProfileName(tokenid);
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

	protected void resetUserPasswordAndStatus(AuthenticationToken admin, String username, int status) {
		try {
			endEntityManagementSession.setPassword(admin, username, null);
			endEntityManagementSession.setUserStatus(admin, username, status);	
			log.debug("Reset user password to null and status to "+status);
		} catch (Exception e) {
			// Catch all because this reset method will be called from withing other catch clauses
			log.error(e);
		}
	}

	protected boolean checkValidityAndSetUserPassword(AuthenticationToken admin, java.security.cert.Certificate cert, String username, String password) 
	throws ServiceLocatorException, CertificateNotYetValidException, CertificateExpiredException, UserDoesntFullfillEndEntityProfile, AuthorizationDeniedException, FinderException, ApprovalException, WaitingForApprovalException {
		boolean ret = false;
		try {
			// Check validity of the certificate after verifying the signature
			CertTools.checkValidity(cert, new Date());
			log.debug("The verifying certificate was valid");
			// Verification succeeded, lets set user status to new, the password as passed in and proceed
			String msg = intres.getLocalizedMessage("cvc.info.renewallowed", CertTools.getFingerprintAsString(cert), username);            	
			log.info(msg);
			endEntityManagementSession.setPassword(admin, username, password);
			endEntityManagementSession.setUserStatus(admin, username, EndEntityConstants.STATUS_NEW);
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
	 * @throws CesecoreException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
	 */
	protected void caCertResponse(EjbcaWSHelper ejbhelper, AuthenticationToken admin, String caname, byte[] cert, List<byte[]> cachain, String keystorepwd, boolean futureRollover) 
		throws AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CertPathValidatorException, CesecoreException {
		try {
			CAInfo cainfo = caSession.getCAInfo(admin, caname);
			// create response messages, for CVC certificates we use a regular X509ResponseMessage
			X509ResponseMessage msg = new X509ResponseMessage();
			msg.setCertificate(CertTools.getCertfromByteArray(cert, java.security.cert.Certificate.class));
			// Activate the CA's token using the provided keystorepwd if any
			if (keystorepwd!=null) {
	            cryptoTokenManagementSession.activate(admin, cainfo.getCAToken().getCryptoTokenId(), keystorepwd.toCharArray());
			}
			caAdminSession.receiveResponse(admin, cainfo.getCAId(), msg, cachain, null, futureRollover);
		} catch (CertificateException e) {
            throw EjbcaWSHelper.getInternalException(e, null);
		}
	}

	/**
	 * @throws CryptoTokenAuthenticationFailedException 
	 * @throws CryptoTokenOfflineException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#caRenewCertRequest 
	 */
	protected byte[] caRenewCertRequest(EjbcaWSHelper ejbhelper, AuthenticationToken admin, String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey, boolean activatekey, String keystorepwd) 
		throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException, CertPathValidatorException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
		CAInfo cainfo = caSession.getCAInfo(admin, caname);
		String nextSignKeyAlias = null;   // null means generate new keypair
		if (!regenerateKeys) {
		    nextSignKeyAlias = cainfo.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN);
	        if (usenextkey) {
	            nextSignKeyAlias = cainfo.getCAToken().getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN_NEXT);
	        }
		}
		// Activate used to mean "move nextsignkeyalias to currentsignkeyalias", we changed the meaning here to be activate the CA's CryptoToken
		if (activatekey) {
	        cryptoTokenManagementSession.activate(admin, cainfo.getCAToken().getCryptoTokenId(), keystorepwd.toCharArray());
		}
        return caAdminSession.makeRequest(admin, cainfo.getCAId(), cachain, nextSignKeyAlias);
	}
	
	public void rolloverCACert(EjbcaWSHelper ejbhelper, AuthenticationToken admin, String caname) throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException {
	    int caid = caSession.getCAInfo(admin, caname).getCAId();
        caAdminSession.rolloverCA(admin, caid);
    }

	protected  static EjbcaException getInternalException(Throwable t, IPatternLogger logger) {
        return getEjbcaException( t, logger, ErrorCode.INTERNAL_ERROR, Level.ERROR);
	}

	protected static EjbcaException getEjbcaException(Throwable t, IPatternLogger logger, ErrorCode errorCode, Priority p) {
		if (p!=null) {
	        log.log(p, "EJBCA WebService error", t);			
		}
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
