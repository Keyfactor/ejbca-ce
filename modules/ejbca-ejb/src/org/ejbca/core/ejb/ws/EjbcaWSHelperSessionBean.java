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
package org.ejbca.core.ejb.ws;

import org.apache.log4j.Logger;
import org.cesecore.CesecoreException;
import org.cesecore.ErrorCode;
import org.cesecore.authentication.oauth.TokenExpiredException;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CmsCertificatePathMissingException;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.OAuthConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.ssh.SshRequestMessage;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.objects.SshRequestMessageWs;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.util.cert.OID;
import org.ejbca.util.query.Query;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Contains methods that are used by both the EjbcaWS, the Ejbca WS tests and by RAMasterApiSessionBean.
 * For instance, methods to convert between EndEntityInformation and UserDataWO.
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "EjbcaWSHelperSessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class EjbcaWSHelperSessionBean implements EjbcaWSHelperSessionLocal, EjbcaWSHelperSessionRemote {

    private static final Logger log = Logger.getLogger(EjbcaWSHelperSessionBean.class);

    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @EJB
    private WebAuthenticationProviderSessionLocal authenticationSession;
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    private final String[] softtokennames = { UserDataVOWS.TOKEN_TYPE_USERGENERATED, UserDataVOWS.TOKEN_TYPE_P12, UserDataVOWS.TOKEN_TYPE_JKS,
            UserDataVOWS.TOKEN_TYPE_PEM, UserDataVOWS.TOKEN_TYPE_BCFKS };
    private final int[] softtokenids = { SecConst.TOKEN_SOFT_BROWSERGEN, SecConst.TOKEN_SOFT_P12, SecConst.TOKEN_SOFT_JKS, SecConst.TOKEN_SOFT_PEM, SecConst.TOKEN_SOFT_BCFKS };

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    @Override
    public AuthenticationToken getAdmin(final boolean allowNonAdmins, final X509Certificate cert, String oauthBearerToken) throws AuthorizationDeniedException {
        if (cert != null) {
            final Set<X509Certificate> credentials = new HashSet<>();
            credentials.add(cert);
            final AuthenticationSubject subject = new AuthenticationSubject(null, credentials);
            final AuthenticationToken admin = authenticationSession.authenticate(subject);
            if ((admin != null) && (!allowNonAdmins)) {
                if (!raMasterApiProxyBean.isAuthorizedNoLogging(admin, AccessRulesConstants.ROLE_ADMINISTRATOR)) {
                    final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.ROLE_ADMINISTRATOR, null);
                    throw new AuthorizationDeniedException(msg);
                }
            } else if (admin == null) {
                final String msg = intres.getLocalizedMessage("authentication.failed", "No admin authenticated for certificate with serialNumber "
                        + CertTools.getSerialNumber(cert) + " and issuerDN '" + CertTools.getIssuerDN(cert) + "'.");
                throw new AuthorizationDeniedException(msg);
            }
            return admin;
        } else if (oauthBearerToken != null) {
            final AuthenticationToken admin;
            final OAuthConfiguration oauthConfiguration = raMasterApiProxyBean.getGlobalConfiguration(OAuthConfiguration.class);
            try {
                admin = authenticationSession.authenticateUsingOAuthBearerToken(oauthConfiguration, oauthBearerToken);
                if (admin == null) {
                    throw new AuthorizationDeniedException("Authentication failed using OAuth Bearer Token.");
                }
            } catch (TokenExpiredException e) {
                throw new AuthorizationDeniedException("Authentication failed using OAuth Bearer Token. JWT token has expired.");
            }

            return admin;
        } else {
            final String msg = "Authorization failed. No certificates or OAuth token provided.";
            throw new AuthorizationDeniedException(msg);
        }

    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED) // authentication failure should not force a rollback
    @Override
    public void isAuthorizedToRepublish(AuthenticationToken admin, String username, int caid) throws AuthorizationDeniedException, EjbcaException {
        if (!authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.REGULAR_VIEWCERTIFICATE,
                    null);
            throw new AuthorizationDeniedException(msg);
        }
        EndEntityInformation userdata = endEntityAccessSession.findUser(admin, username);
        if (userdata == null) {
            log.info(intres.getLocalizedMessage("ra.errorentitynotexist", username));
            String msg = intres.getLocalizedMessage("ra.wrongusernameorpassword");
            throw new EjbcaException(ErrorCode.USER_NOT_FOUND, msg);
        }
        if (!authorizationSession.isAuthorizedNoLogging(admin,
                AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.VIEW_END_ENTITY)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource",
                    AccessRulesConstants.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AccessRulesConstants.VIEW_END_ENTITY, null);
            throw new AuthorizationDeniedException(msg);
        }
        if (!authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", StandardRules.CAACCESS.resource() + caid, null);
            throw new AuthorizationDeniedException(msg);
        }
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityInformation convertUserDataVOWSInternal(final UserDataVOWS userData, final int caId, final int endEntityProfileId,
                                                            final int certificateProfileId, final int tokenId, final boolean useRawSubjectDN) throws EjbcaException {
        final ExtendedInformation ei = new ExtendedInformation();
        boolean useEI = false;

        if (userData.getStartTime() != null) {
            String customStartTime = userData.getStartTime();
            try {
                if (customStartTime.length() > 0 && !customStartTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
                    customStartTime = customStartTime.replace("Z", "+00:00");
                    if (!customStartTime.matches("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}.\\d{2}:\\d{2}$")) {
                        // We use the old absolute time format, so we need to upgrade and log deprecation info
                        final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
                        final String newCustomStartTime = ValidityDate.formatAsISO8601(oldDateFormat.parse(customStartTime),
                                ValidityDate.TIMEZONE_UTC);
                        log.info(
                                "WS client sent userdata with startTime using US Locale date format. yyyy-MM-dd HH:mm:ssZZ should be used for absolute time and any fetched UserDataVOWS will use this format.");
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
                log.info("WS client supplied invalid startTime in userData. startTime for this request was ignored. Supplied SubjectDN was \""
                        + userData.getSubjectDN() + "\" and customStartTime was '" + customStartTime + "'.");
                throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, "Invalid date format in StartTime");
            }
        }
        if (userData.getEndTime() != null) {
            String customEndTime = userData.getEndTime();
            try {
                if (customEndTime.length() > 0 && !customEndTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
                    if (!customEndTime.matches("^\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2}.\\d{2}:\\d{2}$")) {
                        // We use the old absolute time format, so we need to upgrade and log deprecation info
                        final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
                        final String newCustomStartTime = ValidityDate.formatAsISO8601(oldDateFormat.parse(customEndTime), ValidityDate.TIMEZONE_UTC);
                        log.info(
                                "WS client sent userdata with endTime using US Locale date format. yyyy-MM-dd HH:mm:ssZZ should be used for absolute time and any fetched UserDataVOWS will use this format.");
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
                log.info("WS client supplied invalid endTime in userData. endTime for this request was ignored. Supplied SubjectDN was \""
                        + userData.getSubjectDN() + "\"");
                throw new EjbcaException(ErrorCode.FIELD_VALUE_NOT_VALID, "Invalid date format in EndTime.");
            }
        }
        if (userData.getCertificateSerialNumber() != null) {
            ei.setCertificateSerialNumber(userData.getCertificateSerialNumber());
            useEI = true;
        }

        if (useRawSubjectDN) {
            // It could/should B64 encoded to avoid XML baddies, ExtendedInformation.getRawSubjectDn does encoding, if the string is encoded
            final String value = StringTools.putBase64String(userData.getSubjectDN());
            ei.setMapData(ExtendedInformation.RAWSUBJECTDN, value);
            useEI = true;
        }
        useEI = setExtendedInformationFromUserDataVOWS(userData, ei) || useEI;

        final EndEntityInformation endEntityInformation = new EndEntityInformation(userData.getUsername(), userData.getSubjectDN(), caId,
                userData.getSubjectAltName(), userData.getEmail(), userData.getStatus(), userData.getType(), endEntityProfileId, certificateProfileId,
                null, null, tokenId, useEI ? ei : null);

        endEntityInformation.setPassword(userData.getPassword());
        endEntityInformation.setCardNumber(userData.getCardNumber());
        endEntityInformation.setSendNotification(userData.isSendNotification());
        return endEntityInformation;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public EndEntityInformation convertUserDataVOWS(final AuthenticationToken authenticationToken, final UserDataVOWS userData)
            throws CADoesntExistsException, EjbcaException {
        // No need to check CA authorization here, we are only converting the user input. The actual authorization check in CA is done when
        // trying to add/edit the user
        final CAInfo cainfo = caSession.getCAInfoInternal(-1, userData.getCaName(), true);
        if (cainfo == null) {
            throw new CADoesntExistsException("No CA found by name of " + userData.getCaName());
        }
        final int caid = cainfo.getCAId();
        if (caid == 0) {
            throw new CADoesntExistsException("Error CA " + userData.getCaName() + " have caid 0, which is impossible.");
        }

        int endentityprofileid;
        try {
            endentityprofileid = endEntityProfileSession.getEndEntityProfileId(userData.getEndEntityProfileName());
        } catch (EndEntityProfileNotFoundException e) {
            throw new EjbcaException(ErrorCode.EE_PROFILE_NOT_EXISTS,
                    "Error End Entity profile " + userData.getEndEntityProfileName() + " does not exist.", e);
        }

        final int certificateprofileid = certificateProfileSession.getCertificateProfileId(userData.getCertificateProfileName());
        if (certificateprofileid == 0) {
            throw new EjbcaException(ErrorCode.CERT_PROFILE_NOT_EXISTS,
                    "Error Certificate profile " + userData.getCertificateProfileName() + " does not exist.");
        }
        final CertificateProfile cp = certificateProfileSession.getCertificateProfile(certificateprofileid);
        final boolean useRawSubjectDN = cp.getAllowDNOverrideByEndEntityInformation();


        final int tokenid = getTokenId(authenticationToken, userData.getTokenType());
        if (tokenid == 0) {
            throw new EjbcaException(ErrorCode.UNKOWN_TOKEN_TYPE, "Error Token Type  " + userData.getTokenType() + " does not exist.");
        }

        return convertUserDataVOWSInternal(userData, caid, endentityprofileid, certificateprofileid, tokenid, useRawSubjectDN);
    }

    /** Sets generic Custom ExtendedInformation from potential data in UserDataVOWS.
     * This is data from the field "Custom certificate extension data" in the EE profile.
     * @param userdata UserDataVOWS that we want to see if any ExtendedInformationWS is set
     * @param ei ExtendedInformation to populate with information.
     * @return true if some value was added, false if nothing was added
     */
    private static boolean setExtendedInformationFromUserDataVOWS(UserDataVOWS userdata, ExtendedInformation ei) {
        // Set generic Custom ExtendedInformation from potential data in UserDataVOWS
        final List<ExtendedInformationWS> userei = userdata.getExtendedInformation();
        if (userei == null) {
            return false;
        }
        boolean useEI = false;
        for (ExtendedInformationWS item : userei) {
            final String key = item.getName();
            final String value = item.getValue();
            if (value == null || key == null) {
                if (log.isDebugEnabled()) {
                    log.debug("Key or value is null when trying to set generic extended information.");
                }
                continue;
            }
            if (OID.isStartingWithValidOID(key)) {
                ei.setExtensionData(key, value);
                if (log.isDebugEnabled()) {
                    log.debug("Set certificate extension: " + key + ", " + value);
                }
            } else {
                ei.setMapData(key, value);
                if (log.isDebugEnabled()) {
                    log.debug("Set generic extended information: " + key + ", " + value);
                }
            }
            useEI = true;
        }
        return useEI;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation, final String caName,
                                                    final String endEntityProfileName, final String certificateProfileName, final String tokenName) {
        final UserDataVOWS dataWS = new UserDataVOWS();
        dataWS.setUsername(endEntityInformation.getUsername());
        dataWS.setCaName(caName);
        dataWS.setEndEntityProfileName(endEntityProfileName);
        dataWS.setCertificateProfileName(certificateProfileName);
        dataWS.setTokenType(tokenName);

        dataWS.setPassword(null);
        dataWS.setClearPwd(false);
        dataWS.setSubjectDN(endEntityInformation.getDN());
        dataWS.setSubjectAltName(endEntityInformation.getSubjectAltName());
        dataWS.setEmail(endEntityInformation.getEmail());
        dataWS.setStatus(endEntityInformation.getStatus());
        dataWS.setCardNumber(endEntityInformation.getCardNumber());
        dataWS.setSendNotification(endEntityInformation.getSendNotification());

        final ExtendedInformation ei = endEntityInformation.getExtendedInformation();
        if (ei != null) {
            String startTime = ei.getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
            if (startTime != null && startTime.length() > 0 && !startTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
                try {
                    // Always respond with the time formatted in a neutral time zone
                    startTime = ValidityDate.getISO8601FromImpliedUTC(startTime, ValidityDate.TIMEZONE_UTC);
                } catch (ParseException e) {
                    log.info("Failed to convert " + ExtendedInformation.CUSTOM_STARTTIME + " to ISO8601 format.");
                }
            }
            dataWS.setStartTime(startTime);
            String endTime = ei.getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
            if (endTime != null && endTime.length() > 0 && !endTime.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
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
            final HashMap<String, ?> data = (HashMap<String, ?>) ei.getData();
            if (data != null) {
                final List<ExtendedInformationWS> extendedInfo = new ArrayList<>();
                final Set<String> set = data.keySet();
                for (Iterator<String> iterator = set.iterator(); iterator.hasNext();) {
                    final String key = iterator.next();
                    final String value = ei.getMapData(key);
                    if (value != null) {
                        extendedInfo.add(new ExtendedInformationWS(key, value));
                    }
                }
                dataWS.setExtendedInformation(extendedInfo);
            }
        }

        return dataWS;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public UserDataVOWS convertEndEntityInformation(final EndEntityInformation endEntityInformation) throws EjbcaException, CADoesntExistsException {
        final String username = endEntityInformation.getUsername();
        // No need to check CA authorization here, we are only converting the user input. The actual authorization check in CA is done when
        // trying to add/edit the user
        final String caname = caSession.getCAInfoInternal(endEntityInformation.getCAId(), null, true).getName();

        final String endentityprofilename = endEntityProfileSession.getEndEntityProfileName(endEntityInformation.getEndEntityProfileId());
        if (endentityprofilename == null) {
            final String message = "Error End Entity profile id " + endEntityInformation.getEndEntityProfileId() + " does not exist. User: "
                    + username;
            log.error(message);
            throw new EjbcaException(ErrorCode.EE_PROFILE_NOT_EXISTS, message);
        }

        final String certificateprofilename = certificateProfileSession.getCertificateProfileName(endEntityInformation.getCertificateProfileId());
        if (certificateprofilename == null) {
            final String message = "Error Certificate profile id " + endEntityInformation.getCertificateProfileId() + " does not exist. User: "
                    + username;
            log.error(message);
            throw new EjbcaException(ErrorCode.CERT_PROFILE_NOT_EXISTS, message);
        }

        final String tokenname = getTokenName(endEntityInformation.getTokenType());
        if (tokenname == null) {
            final String message = "Error Token Type id " + endEntityInformation.getTokenType() + " does not exist. User: " + username;
            log.error(message);
            throw new EjbcaException(ErrorCode.UNKOWN_TOKEN_TYPE, message);
        }
        return convertEndEntityInformation(endEntityInformation, caname, endentityprofilename, certificateprofilename, tokenname);
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Query convertUserMatch(AuthenticationToken admin, UserMatch usermatch)
            throws CADoesntExistsException, AuthorizationDeniedException, EndEntityProfileNotFoundException {
        Query retval = new Query(Query.TYPE_USERQUERY);
        switch (usermatch.getMatchwith()) {
        case UserMatch.MATCH_WITH_ENDENTITYPROFILE:
            String endentityprofilename = Integer.toString(endEntityProfileSession.getEndEntityProfileId(usermatch.getMatchvalue()));
            retval.add(usermatch.getMatchwith(), usermatch.getMatchtype(), endentityprofilename);
            break;
        case UserMatch.MATCH_WITH_CERTIFICATEPROFILE:
            String certificateprofilename = Integer.toString(certificateProfileSession.getCertificateProfileId(usermatch.getMatchvalue()));
            retval.add(usermatch.getMatchwith(), usermatch.getMatchtype(), certificateprofilename);
            break;
        case UserMatch.MATCH_WITH_CA:
        CAInfo caInfo = caSession.getCAInfo(admin, usermatch.getMatchvalue());
        if (caInfo==null) {
            final String message = "Error CA " + usermatch.getMatchvalue() + " does not exist";
            log.error(message);
            throw new CADoesntExistsException(message);
        }else {
            String caname = Integer.toString(caInfo.getCAId());
            retval.add(usermatch.getMatchwith(), usermatch.getMatchtype(), caname);
        }
        break;
        case UserMatch.MATCH_WITH_TOKEN:
            String tokenname = Integer.toString(getTokenId(admin, usermatch.getMatchvalue()));
            retval.add(usermatch.getMatchwith(), usermatch.getMatchtype(), tokenname);
            break;
        default:
            retval.add(usermatch.getMatchwith(), usermatch.getMatchtype(), usermatch.getMatchvalue());
            break;
        }
        return retval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public Collection<java.security.cert.Certificate> returnOnlyValidCertificates(final AuthenticationToken admin,
            final Collection<java.security.cert.Certificate> certs) {
        final ArrayList<java.security.cert.Certificate> retval = new ArrayList<>();
        for (java.security.cert.Certificate cert : certs) {
            boolean isrevoked = certificateStoreSession.isRevoked(CertTools.getIssuerDN(cert), CertTools.getSerialNumber(cert));
            if (!isrevoked) {
                try {
                    CertTools.checkValidity(cert, new Date());
                    retval.add(cert);
                } catch (CertificateExpiredException e) {
                } catch (CertificateNotYetValidException e) {
                }
            }
        }
        return retval;
    }

    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @Override
    public List<Certificate> returnAuthorizedCertificates(final AuthenticationToken admin, final Collection<java.security.cert.Certificate> certs,
            final boolean validate, final long nowMillis) {
        final List<Certificate> retval = new ArrayList<>();
        final Map<Integer, Boolean> authorizationCache = new HashMap<>();
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
                    authorized = authorizationSession.isAuthorizedNoLogging(admin, StandardRules.CAACCESS.resource() + caid);
                    authorizationCache.put(caid, authorized);
                }
                if (authorized.booleanValue()) {
                    retval.add(new Certificate(next));
                }
            } catch (CertificateExpiredException | CertificateNotYetValidException e) {
                // Drop invalid cert
            } catch (CertificateEncodingException e) {
                // Drop invalid cert
                log.error("A defect certificate was detected.");
            }
        }
        return retval;
    }

    private int getTokenId(AuthenticationToken admin, String tokenname) {
        int returnval = 0;

        for (int i = 0; i < softtokennames.length; i++) {
            if (softtokennames[i].equals(tokenname)) {
                returnval = softtokenids[i];
                break;
            }
        }

        return returnval;
    }

    private String getTokenName(int tokenid) {
        String returnval = null;

        for (int i = 0; i < softtokenids.length; i++) {
            if (softtokenids[i] == tokenid) {
                returnval = softtokennames[i];
                break;
            }
        }

        return returnval;
    }

    @Override
    public void resetUserPasswordAndStatus(AuthenticationToken admin, String username, int status) {
        try {
            endEntityManagementSession.setPassword(admin, username, null);
            endEntityManagementSession.setUserStatus(admin, username, status);
            log.debug("Reset user password to null and status to " + status);
        } catch (Exception e) {
            // Catch all because this reset method will be called from within other catch clauses
            log.error(e);
        }
    }

    @Override
    public void checkValidityAndSetUserPassword(AuthenticationToken admin, java.security.cert.Certificate cert, String username, String password)
            throws CertificateNotYetValidException, CertificateExpiredException, EndEntityProfileValidationException, AuthorizationDeniedException,
            NoSuchEndEntityException, ApprovalException, WaitingForApprovalException {
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
        } catch (CertificateNotYetValidException e) {
            // If verification of outer signature fails because the old certificate is not valid, we don't really care, continue as if it was an initial request
            if (log.isDebugEnabled()) {
                log.debug("Certificate we try to verify outer signature with is not yet valid. SubjectDN: " + CertTools.getSubjectDN(cert));
            }
            throw e;
        } catch (CertificateExpiredException e) {
            if (log.isDebugEnabled()) {
                log.debug("Certificate we try to verify outer signature with has expired. SubjectDN: " + CertTools.getSubjectDN(cert));
            }
            throw e;
        }
    }

    @Override
    public void caCertResponse(AuthenticationToken admin, String caname, byte[] cert, List<byte[]> cachain, String keystorepwd,
            boolean futureRollover) throws AuthorizationDeniedException, EjbcaException, ApprovalException, WaitingForApprovalException,
            CertPathValidatorException, CesecoreException, CertificateParsingException {
        CAInfo cainfo = caSession.getCAInfo(admin, caname);
        if (cainfo == null) {
            final String errmsg = intres.getLocalizedMessage("caadmin.canotexistsname", caname);
            throw new CADoesntExistsException(errmsg);
        }
        // create response messages, for CVC certificates we use a regular X509ResponseMessage
        X509ResponseMessage msg = new X509ResponseMessage();
        msg.setCertificate(CertTools.getCertfromByteArray(cert, java.security.cert.Certificate.class));
        // Activate the CA's token using the provided keystorepwd if any
        if (keystorepwd != null) {
            cryptoTokenManagementSession.activate(admin, cainfo.getCAToken().getCryptoTokenId(), keystorepwd.toCharArray());
        }
        caAdminSession.receiveResponse(admin, cainfo.getCAId(), msg, cachain, null, futureRollover);
    }

    @Override
    public byte[] caRenewCertRequest(AuthenticationToken admin, String caname, List<byte[]> cachain, boolean regenerateKeys, boolean usenextkey,
            boolean activatekey, String keystorepwd) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException,
            CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException {
        CAInfo cainfo = caSession.getCAInfo(admin, caname);
        if (cainfo == null) {
            final String msg = intres.getLocalizedMessage("caadmin.canotexistsname", caname);
            throw new CADoesntExistsException(msg);
        }
        String nextSignKeyAlias = null; // null means generate new keypair
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

    @Override
    public void importCaCert(AuthenticationToken admin, String caname, byte[] certbytes) throws AuthorizationDeniedException, CAExistsException,
            IllegalCryptoTokenException, CertificateImportException, EjbcaException, CertificateParsingException {
        final Collection<CertificateWrapper> cachain = CertTools.bytesToListOfCertificateWrapperOrThrow(certbytes);
        caAdminSession.importCACertificate(admin, caname, cachain);
    }

    @Override
    public void updateCaCert(AuthenticationToken admin, String caname, byte[] certbytes)
            throws AuthorizationDeniedException, CADoesntExistsException, CertificateImportException, EjbcaException, CertificateParsingException, CmsCertificatePathMissingException {
        final Collection<CertificateWrapper> cachain = CertTools.bytesToListOfCertificateWrapperOrThrow(certbytes);
        CAInfo cainfo = caSession.getCAInfo(admin, caname);
        if (cainfo == null) {
            final String msg = intres.getLocalizedMessage("caadmin.canotexistsname", caname);
            throw new CADoesntExistsException(msg);
        }
        caAdminSession.updateCACertificate(admin, cainfo.getCAId(), cachain);
    }

    @Override
    public void rolloverCACert(AuthenticationToken admin, String caname)
            throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException {
        CAInfo cainfo = caSession.getCAInfo(admin, caname);
        if (cainfo == null) {
            final String msg = intres.getLocalizedMessage("caadmin.canotexistsname", caname);
            throw new CADoesntExistsException(msg);
        }
        caAdminSession.rolloverCA(admin, cainfo.getCAId());
    }

    @Override
    public SshRequestMessage convertSshRequestMessage(SshRequestMessageWs sshRequestMessageWs) {
            String keyId = sshRequestMessageWs.getKeyId();
            String comment = sshRequestMessageWs.getComment();
            byte[] publicKey = sshRequestMessageWs.getPublicKey();
            List<String> principals = sshRequestMessageWs.getPrincipals();
            Map<String, String> criticalOptions = sshRequestMessageWs.getCriticalOptions();
            Map<String, byte[]> additionalExtensions = sshRequestMessageWs.getAdditionalExtensions();

        return new SshRequestMessage(publicKey, keyId, principals, additionalExtensions, criticalOptions, comment);
    }

}
