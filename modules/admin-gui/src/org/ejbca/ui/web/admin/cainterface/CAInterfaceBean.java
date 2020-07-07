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

package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.AbstractMap;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.Set;

import javax.ejb.EJBException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.FileUploadException;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CvcCABase;
import org.cesecore.certificates.ca.CvcPlugin;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.ssh.SshCaInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStatus;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.standard.NameConstraint;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.AsStringComparator;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.EntryValueComparator;
import org.cesecore.util.FileTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.ParameterException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.RevokedInfoView;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;

/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 * <p>
 * Semi-deprecated, we should try to move the methods here into session beans or managed beans.
 *
 * @version $Id$
 */
public class CAInterfaceBean implements Serializable {

	private static final long serialVersionUID = 3L;
	private static final Logger log = Logger.getLogger(CAInterfaceBean.class);
	private static final String LIST_SEPARATOR = ";";

	private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private AuthorizationSessionLocal authorizationSession;
    private CAAdminSessionLocal caadminsession;
    private CaSessionLocal casession;
    private CertificateProfileSession certificateProfileSession;
    private CertificateStoreSessionLocal certificatesession;
    private CertReqHistorySessionLocal certreqhistorysession;
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    private PublisherSessionLocal publishersession;

    private SignSession signsession;

    private CADataHandler cadatahandler;

    private boolean initialized;
    private AuthenticationToken authenticationToken;
    private CAInfo cainfo;
    private EjbcaWebBean ejbcawebbean;
    /** The certification request in binary format */
    private transient byte[] request;
    private Certificate processedcert;

	/** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() { }

    // Public methods
    public void initialize(final EjbcaWebBean ejbcawebbean) {
        if (!initialized) {
          certificatesession = ejbLocalHelper.getCertificateStoreSession();
          certreqhistorysession = ejbLocalHelper.getCertReqHistorySession();
          cryptoTokenManagementSession = ejbLocalHelper.getCryptoTokenManagementSession();
          caadminsession = ejbLocalHelper.getCaAdminSession();
          casession = ejbLocalHelper.getCaSession();
          authorizationSession = ejbLocalHelper.getAuthorizationSession();
          signsession = ejbLocalHelper.getSignSession();
          publishersession = ejbLocalHelper.getPublisherSession();
          certificateProfileSession = ejbLocalHelper.getCertificateProfileSession();
          authenticationToken = ejbcawebbean.getAdminObject();
          this.ejbcawebbean = ejbcawebbean;

          cadatahandler = new CADataHandler(authenticationToken, ejbLocalHelper, ejbcawebbean);
          initialized =true;
        }
    }

    public CertificateView[] getCACertificates(int caid) {
        final List<CertificateView> ret = new ArrayList<>();
        for (final Certificate certificate : signsession.getCertificateChain(caid)) {
            RevokedInfoView revokedinfo = null;
            CertificateStatus revinfo = certificatesession.getStatus(CertTools.getIssuerDN(certificate), CertTools.getSerialNumber(certificate));
            if (revinfo != null && revinfo.revocationReason != RevokedCertInfo.NOT_REVOKED) {
                revokedinfo = new RevokedInfoView(revinfo, CertTools.getSerialNumber(certificate));
            }
            ret.add(new CertificateView(certificate, revokedinfo));
        }
        return ret.toArray(new CertificateView[0]);
    }

    /**
     * Method that returns a HashMap connecting available CAIds (Integer) to CA Names (String).
     * @deprecated Since 7.0.0. Use CaSession.getCAIdToNameMap directly instead
     */
    @Deprecated
    public Map<Integer, String>  getCAIdToNameMap(){
    	return casession.getCAIdToNameMap();
    }

    /**
     * Return the name of the CA based on its ID
     * @param caId the CA ID
     * @return the name of the CA or null if it does not exists.
     */
    public String getName(Integer caId) {
        return casession.getCAIdToNameMap().get(caId);
    }

    public CADataHandler getCADataHandler(){
      return cadatahandler;
    }

    /** Slow method to get CAInfo. The returned object has id-to-name maps of publishers and validators. */
    public CAInfoView getCAInfo(int caid) throws AuthorizationDeniedException {
      return cadatahandler.getCAInfo(caid);
    }

    public int getCAStatusNoAuth(int caid) {
        final CAInfo caInfo = casession.getCAInfoInternal(caid);
        return (caInfo != null ? caInfo.getStatus() : 0);
    }

    @Deprecated
    public void saveRequestInfo(CAInfo cainfo){
    	this.cainfo = cainfo;
    }

    @Deprecated
    public CAInfo getRequestInfo(){
    	return this.cainfo;
    }

	public void saveRequestData(byte[] request){
		this.request = request;
	}

	public byte[] getRequestData(){
		return this.request;
	}

	public String getRequestDataAsString() throws Exception{
		String returnval = null;
		if(request != null ){
			returnval = RequestHelper.BEGIN_CERTIFICATE_REQUEST_WITH_NL
			+ new String(Base64.encode(request, true))
			+ RequestHelper.END_CERTIFICATE_REQUEST_WITH_NL;
		}
		return returnval;
	}

	public void saveProcessedCertificate(Certificate cert){
		this.processedcert =cert;
	}

    Certificate getProcessedCertificate(){
		return this.processedcert;
	}

	public String getProcessedCertificateAsString() throws Exception{
		String returnval = null;
		if(request != null ){
			byte[] b64cert = Base64.encode(this.processedcert.getEncoded(), true);
			returnval = CertTools.BEGIN_CERTIFICATE_WITH_NL;
			returnval += new String(b64cert);
			returnval += CertTools.END_CERTIFICATE_WITH_NL;
		}
		return returnval;
	}

	public AuthenticationToken getAuthenticationToken() {
	    return authenticationToken;
	}

	public String republish(CertificateView certificateView) throws AuthorizationDeniedException {
		String returnval = "CERTREPUBLISHFAILED";
		int certificateProfileId = CertificateProfileConstants.CERTPROFILE_NO_PROFILE;
		String password = null;
		ExtendedInformation ei = null;
		// Unescaped subjectDN is used to avoid causing issues in custom publishers (see ECA-6761)
		String dn = certificateView.getSubjectDNUnescaped();
		final CertReqHistory certreqhist = certreqhistorysession.retrieveCertReqHistory(certificateView.getSerialNumberBigInt(), certificateView.getIssuerDN());
		if (certreqhist != null) {
			// First try to look up all info using the Certificate Request History from when the certificate was issued
			// We need this since the certificate subjectDN might be a subset of the subjectDN in the template
			certificateProfileId = certreqhist.getEndEntityInformation().getCertificateProfileId();
			password = certreqhist.getEndEntityInformation().getPassword();
			ei = certreqhist.getEndEntityInformation().getExtendedInformation();
			dn = certreqhist.getEndEntityInformation().getCertificateDN();
		}
		final String fingerprint = certificateView.getSHA1Fingerprint().toLowerCase();
		final CertificateDataWrapper cdw = certificatesession.getCertificateData(fingerprint);
		if (cdw != null) {
			// If we are missing Certificate Request History for this certificate, we can at least recover some of this info
			if (certificateProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
				certificateProfileId = cdw.getCertificateData().getCertificateProfileId();
			}
		}
		if (certificateProfileId == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
			// If there is no cert req history and the cert profile was not defined in the CertificateData row, so we can't do anything about it..
			returnval = "CERTREQREPUBLISHFAILED";
		} else {
			final CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(certificateProfileId);
			if (certprofile != null) {
				if (!certprofile.getPublisherList().isEmpty()) {
                    if (publishersession.storeCertificate(authenticationToken, certprofile.getPublisherList(), cdw, password, dn, ei)) {
                        returnval = "CERTREPUBLISHEDSUCCESS";
                    }
				} else {
					returnval = "NOPUBLISHERSDEFINED";
				}
			} else {
				returnval = "CERTPROFILENOTFOUND";
			}
		}
		return returnval;
	}

	/** Class used to sort CertReq History by users modified time, with latest first*/
	private static class CertReqUserCreateComparator implements Comparator<CertReqHistory> {
		@Override
		public int compare(CertReqHistory o1, CertReqHistory o2) {
			return -(o1.getEndEntityInformation().getTimeModified().compareTo(o2.getEndEntityInformation().getTimeModified()));
		}
	}

	/**
	 * Returns a List of CertReqHistUserData from the certreqhist database in an collection sorted by timestamp.
	 */
	public List<CertReqHistory> getCertReqUserDatas(String username){
		List<CertReqHistory> history = this.certreqhistorysession.retrieveCertReqHistory(username);
		// Sort it by timestamp, newest first;
		history.sort(new CertReqUserCreateComparator());
		return history;
	}

	//
	// Methods from editcas.jsp refactoring
	//
    public boolean actionCreateCaMakeRequest(CaInfoDto caInfoDto, Map<ApprovalRequestType, Integer> approvals,
            String availablePublisherValues, String availableKeyValidatorValues,
            boolean buttonCreateCa, boolean buttonMakeRequest,
            byte[] fileBuffer) throws Exception {
        // This will occur if administrator has insufficient access to crypto tokens, which won't provide any
        // selectable items for Crypto Token when creating a CA.
        if (caInfoDto.getCryptoTokenIdParam().isEmpty()) {
            log.info("No selected crypto token. Check crypto token access rules for administrator " + authenticationToken);
            throw new CryptoTokenAuthenticationFailedException("Crypto token authentication failed for administrator " + authenticationToken);
        }
        capitalizeCountryCodeInSubjectDN(caInfoDto);
        int cryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());
        try {
            if (cryptoTokenId==0) {
                // The admin has requested a quick setup and wants to generate a soft keystore with some usable keys
                caInfoDto.setCryptoTokenDefaultKey("defaultKey");
                caInfoDto.setCryptoTokenCertSignKey("signKey");
                caInfoDto.setSelectedKeyEncryptKey("");
                caInfoDto.setTestKey("testKey");
                // First create a new soft auto-activated CryptoToken with the same name as the CA
                final Properties cryptoTokenProperties = new Properties();
                cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, CesecoreConfiguration.getCaKeyStorePass());
                try {
                    cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, caInfoDto.getCaName(), SoftCryptoToken.class.getName(),
                            cryptoTokenProperties, null, null);
                } catch (CryptoTokenNameInUseException e) {
                    // If the name was already in use we simply add a timestamp to the name to manke it unique
                    final String postfix = "_" + new SimpleDateFormat("yyyyMMddHHmmss").format(new Date());
                    cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(authenticationToken, caInfoDto.getCaName() + postfix, SoftCryptoToken.class.getName(),
                            cryptoTokenProperties, null, null);
                }
                // Next generate recommended RSA key pairs for decryption and test
                cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, caInfoDto.getCryptoTokenDefaultKey(), AlgorithmConstants.KEYALGORITHM_RSA + "2048");
                cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, caInfoDto.getTestKey(), AlgorithmConstants.KEYALGORITHM_RSA + "1024");
                // Next, create a CA signing key
                final String caSignKeyAlgo = AlgorithmTools.getKeyAlgorithmFromSigAlg(caInfoDto.getSignatureAlgorithmParam());
                String caSignKeySpec = AlgorithmConstants.KEYALGORITHM_RSA + "2048";
                caInfoDto.setSignKeySpec("2048");
                if (AlgorithmConstants.KEYALGORITHM_DSA.equals(caSignKeyAlgo)) {
                    caSignKeySpec = AlgorithmConstants.KEYALGORITHM_DSA + "1024";
                    caInfoDto.setSignKeySpec(caSignKeySpec);
                } else if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(caSignKeyAlgo)) {
                    caSignKeySpec = "prime256v1";
                    caInfoDto.setSignKeySpec(caSignKeySpec);
                } else if (AlgorithmTools.isGost3410Enabled() && AlgorithmConstants.KEYALGORITHM_ECGOST3410.equals(caSignKeyAlgo)) {
                    caSignKeySpec = CesecoreConfiguration.getExtraAlgSubAlgName("gost3410", "B");
                    caInfoDto.setSignKeySpec(caSignKeySpec);
                } else if (AlgorithmTools.isDstu4145Enabled() && AlgorithmConstants.KEYALGORITHM_DSTU4145.equals(caSignKeyAlgo)) {
                    caSignKeySpec = CesecoreConfiguration.getExtraAlgSubAlgName("dstu4145", "233");
                    caInfoDto.setSignKeySpec(caSignKeySpec);
                }
                cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, caInfoDto.getCryptoTokenCertSignKey(), caSignKeySpec);
            }
            return actionCreateCaMakeRequestInternal(caInfoDto, approvals, availablePublisherValues, availableKeyValidatorValues,
                    buttonCreateCa, buttonMakeRequest, cryptoTokenId, fileBuffer);
        } catch (Exception e) {
            // If we failed during the creation we manually roll back any created soft CryptoToken
            // The more proper way of doing it would be to implement a CaAdminSession call for one-shot
            // CryptoToken and CA creation, but this would currently push a lot of GUI specific code
            // to the business logic. Until we have a new GUI this is probably the best way of doing it.
            if (cryptoTokenId != 0 && "0".equals(caInfoDto.getCryptoTokenIdParam())) {
                cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, cryptoTokenId);
            }
            throw e;
        }
    }

    private void capitalizeCountryCodeInSubjectDN(final CaInfoDto caInfoDto) {
        String subjectDN = caInfoDto.getCaSubjectDN();
        String delimiter = "C=";
        int delimeterStartIndex = subjectDN.indexOf(delimiter);
        int countryStartIndex = delimeterStartIndex + delimiter.length();
        if (delimeterStartIndex != -1) {
            // Assume country code is 2 characters long. In special cases when it's longer and it's lowercase not all of it will be capitalized.
            // In that case CA creation fails just like it always used to anyway.
            int countryEndIndex = countryStartIndex + 2;
            String replacement = subjectDN.substring(countryStartIndex, countryEndIndex).toUpperCase(Locale.ENGLISH);
            String manipulatedSubjectDN = subjectDN.substring(0, countryStartIndex)
                       + replacement
                       + subjectDN.substring(countryEndIndex);
            caInfoDto.setCaSubjectDN(manipulatedSubjectDN);
        }
    }

	private boolean actionCreateCaMakeRequestInternal(CaInfoDto caInfoDto, Map<ApprovalRequestType, Integer> approvals,
            String availablePublisherValues, String availableKeyValidatorValues,
            boolean buttonCreateCa, boolean buttonMakeRequest,
            int cryptoTokenId,
            byte[] fileBuffer) throws Exception {

	    boolean illegaldnoraltname = false;

	    final List<String> keyPairAliases = cryptoTokenManagementSession.getKeyPairAliases(authenticationToken, cryptoTokenId);
	    if (!keyPairAliases.contains(caInfoDto.getCryptoTokenDefaultKey())) {
            log.info(authenticationToken.toString() + " attempted to createa a CA with a non-existing defaultKey alias: " + caInfoDto.getCryptoTokenDefaultKey());
            throw new Exception("Invalid default key alias!");
	    }
        final String[] suppliedAliases = {caInfoDto.getCryptoTokenCertSignKey(), caInfoDto.getCryptoTokenCertSignKey(), caInfoDto.getSelectedKeyEncryptKey(), caInfoDto.getTestKey()};
        for (final String currentSuppliedAlias : suppliedAliases) {
            if (currentSuppliedAlias.length()>0 && !keyPairAliases.contains(currentSuppliedAlias)) {
                log.info(authenticationToken.toString() + " attempted to create a CA with a non-existing key alias: "+currentSuppliedAlias);
                throw new Exception("Invalid key alias!");
            }
        }
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, caInfoDto.getCryptoTokenDefaultKey());
        if (caInfoDto.getCryptoTokenCertSignKey().length() > 0) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
        }
        if (caInfoDto.getCryptoTokenCertSignKey().length() > 0) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
        }
        if (caInfoDto.getSelectedKeyEncryptKey().length() > 0) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, caInfoDto.getSelectedKeyEncryptKey());
        }
        if (caInfoDto.getTestKey().length() > 0) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, caInfoDto.getTestKey());
        }
        final CAToken caToken = new CAToken(cryptoTokenId, caTokenProperties);
        if (caInfoDto.getSignatureAlgorithmParam() == null) {
            throw new Exception("No signature algorithm supplied!");
        }
        caToken.setSignatureAlgorithm(caInfoDto.getSignatureAlgorithmParam());
        caToken.setEncryptionAlgorithm(AlgorithmTools.getEncSigAlgFromSigAlg(caInfoDto.getSignatureAlgorithmParam()));

        if (caInfoDto.getSignKeySpec() == null || caInfoDto.getSignKeySpec().length() == 0) {
            throw new Exception("No key specification supplied.");
        }
        if (caInfoDto.getKeySequenceFormatAsString() == null) {
            caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        } else {
            caToken.setKeySequenceFormat(Integer.parseInt(caInfoDto.getKeySequenceFormatAsString()));
        }
        if (caInfoDto.getKeySequence() == null) {
            caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        } else {
            caToken.setKeySequence(caInfoDto.getKeySequence());
        }
	    try {
	        CertTools.stringToBcX500Name(caInfoDto.getCaSubjectDN());
	    } catch (IllegalArgumentException e) {
	        illegaldnoraltname = true;
	    }
        int certprofileid = (caInfoDto.getCurrentCertProfile()==null ? 0 : Integer.parseInt(caInfoDto.getCurrentCertProfile()));
        int defaultCertProfileId = (caInfoDto.getDefaultCertificateProfile() == null ? 0 : Integer.parseInt(caInfoDto.getDefaultCertificateProfile()));
        int signedBy = caInfoDto.getSignedBy();

	    if (caInfoDto.getDescription() == null) {
            caInfoDto.setDescription("");
	    }

	    // If 'buttonMakeRequest' set encodedValidity to zero days, otherwise perform validation if it's an absolute date or a relative time.
	    if (buttonMakeRequest) {
	        caInfoDto.setCaEncodedValidity("0d"); // not applicable
        } else {
            String errorMessage = isValidityTimeValid(caInfoDto.getCaEncodedValidity());
            if(!StringUtils.isEmpty(errorMessage)) {
                throw new ParameterException(errorMessage);
            }
        }

	    if (caInfoDto.getCaType() != 0 && caInfoDto.getCaSubjectDN() != null && caInfoDto.getCaName() != null && signedBy != 0) {
	        // Approvals is generic for all types of CAs
//	        final List<Integer> approvalsettings = StringTools.idStringToListOfInteger(approvalSettingValues, LIST_SEPARATOR);
//            final int approvalProfileID = (approvalProfileParam==null ? -1 : Integer.parseInt(approvalProfileParam));

	        if (caInfoDto.getCaType() == CAInfo.CATYPE_X509) {
	            // Create a X509 CA
	            if (caInfoDto.getCaSubjectAltName() == null) {
                    caInfoDto.setCaSubjectAltName("");
	            }

	            // Check for invalid or malformed SAN
	            String errorMessage = checkSubjectAltName(caInfoDto.getCaSubjectAltName());
	            if (!StringUtils.isEmpty(errorMessage)) {
	               throw new ParameterException(errorMessage);
	            }

	            /* Process certificate policies. */
	            final List<CertificatePolicy> policies = parsePolicies(caInfoDto.getPolicyId());
	            // Certificate policies from the CA and the CertificateProfile will be merged for cert creation in the CAAdminSession.createCA call
	            final List<Integer> crlPublishers = StringTools.idStringToListOfInteger(availablePublisherValues, LIST_SEPARATOR);
	            final List<Integer> keyValidators = StringTools.idStringToListOfInteger(availableKeyValidatorValues, LIST_SEPARATOR);

	            List<String> authorityInformationAccess = new ArrayList<>();
	            if (StringUtils.isNotBlank(caInfoDto.getAuthorityInformationAccess())) {
	            	authorityInformationAccess = new ArrayList<>( Arrays.asList(caInfoDto.getAuthorityInformationAccess().split(LIST_SEPARATOR)));
	            }
	            List<String> certificateAiaDefaultCaIssuerUri = new ArrayList<>();
	            if (StringUtils.isNotBlank(caInfoDto.getCertificateAiaDefaultCaIssuerUri())) {
	                certificateAiaDefaultCaIssuerUri = new ArrayList<>( Arrays.asList(caInfoDto.getCertificateAiaDefaultCaIssuerUri().split(LIST_SEPARATOR)));
	            }
	            String caDefinedFreshestCrl = "";
	            if (caInfoDto.getCaDefinedFreshestCRL() != null) {
	                caDefinedFreshestCrl = caInfoDto.getCaDefinedFreshestCRL();
	            }
	            if (caInfoDto.isUsePartitionedCrl() && (caInfoDto.getSuspendedCrlPartitions() >= caInfoDto.getCrlPartitions())) {
                    throw new ParameterException(ejbcawebbean.getText("CRLPARTITIONNUMBERINVALID"));
                }

	            final List<String> nameConstraintsPermitted = parseNameConstraintsInput(caInfoDto.getNameConstraintsPermitted());
	            final List<String> nameConstraintsExcluded = parseNameConstraintsInput(caInfoDto.getNameConstraintsExcluded());
	            final boolean hasNameConstraints = !nameConstraintsPermitted.isEmpty() || !nameConstraintsExcluded.isEmpty();
	            if (hasNameConstraints && !isNameConstraintAllowedInProfile(certprofileid)) {
	               throw new ParameterException(ejbcawebbean.getText("NAMECONSTRAINTSNOTENABLED"));
	            }

	            final int caSerialNumberOctetSize = (caInfoDto.getCaSerialNumberOctetSize() != null) ?
                        Integer.parseInt(caInfoDto.getCaSerialNumberOctetSize()) : CesecoreConfiguration.getSerialNumberOctetSizeForNewCa();
                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos(caInfoDto.getSignKeySpec(), caInfoDto.getCaSubjectDN(), caInfoDto.isServiceCmsActive());
	            if (caInfoDto.getCrlPeriod() != 0 && !illegaldnoraltname) {
                    X509CAInfo.X509CAInfoBuilder x509CAInfoBuilder = new X509CAInfo.X509CAInfoBuilder()
                            .setSubjectDn(caInfoDto.getCaSubjectDN())
                            .setName(caInfoDto.getCaName())
                            .setStatus(CAConstants.CA_ACTIVE)
                            .setSubjectAltName(caInfoDto.getCaSubjectAltName())
                            .setCertificateProfileId(certprofileid)
                            .setDefaultCertProfileId(defaultCertProfileId)
                            .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                            .setEncodedValidity(caInfoDto.getCaEncodedValidity())
                            .setCaType(caInfoDto.getCaType())
                            .setCertificateChain(null)
                            .setCaToken(caToken)
                            .setDescription(caInfoDto.getDescription())
                            .setCaSerialNumberOctetSize(caSerialNumberOctetSize)
                            .setPolicies(policies)
                            .setCrlPeriod(caInfoDto.getCrlPeriod())
                            .setCrlIssueInterval(caInfoDto.getCrlIssueInterval())
                            .setCrlOverlapTime(caInfoDto.getcrlOverlapTime())
                            .setDeltaCrlPeriod(caInfoDto.getDeltaCrlPeriod())
                            .setCrlPublishers(crlPublishers)
                            .setValidators(keyValidators)
                            .setUseAuthorityKeyIdentifier(caInfoDto.isUseAuthorityKeyIdentifier())
                            .setAuthorityKeyIdentifierCritical(caInfoDto.isAuthorityKeyIdentifierCritical())
                            .setUseCrlNumber(caInfoDto.isUseCrlNumber())
                            .setCrlNumberCritical(caInfoDto.isCrlNumberCritical())
                            .setDefaultCrlDistPoint(caInfoDto.getDefaultCRLDistPoint())
                            .setDefaultCrlIssuer(caInfoDto.getDefaultCRLIssuer())
                            .setDefaultOcspCerviceLocator(caInfoDto.getDefaultOCSPServiceLocator())
                            .setAuthorityInformationAccess(authorityInformationAccess)
                            .setCertificateAiaDefaultCaIssuerUri(certificateAiaDefaultCaIssuerUri)
                            .setNameConstraintsPermitted(nameConstraintsPermitted)
                            .setNameConstraintsExcluded(nameConstraintsExcluded)
                            .setCaDefinedFreshestCrl(caDefinedFreshestCrl)
                            .setFinishUser(caInfoDto.isFinishUser())
                            .setExtendedCaServiceInfos(extendedCaServiceInfos)
                            .setUseUtf8PolicyText(caInfoDto.isUseUtf8Policy())
                            .setApprovals(approvals)
                            .setUsePrintableStringSubjectDN(caInfoDto.isUsePrintableStringSubjectDN())
                            .setUseLdapDnOrder(caInfoDto.isUseLdapDNOrder())
                            .setUseCrlDistributionPointOnCrl(caInfoDto.isUseCrlDistributiOnPointOnCrl())
                            .setCrlDistributionPointOnCrlCritical(caInfoDto.isCrlDistributionPointOnCrlCritical())
                            .setDoEnforceUniquePublicKeys(caInfoDto.isDoEnforceUniquePublickeys())
                            .setDoEnforceKeyRenewal(caInfoDto.isDoEnforceKeyRenewal())
                            .setDoEnforceUniqueDistinguishedName(caInfoDto.isDoEnforceUniqueDN())
                            .setDoEnforceUniqueSubjectDNSerialnumber(caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber())
                            .setUseCertReqHistory(caInfoDto.isUseCertReqHistory())
                            .setUseUserStorage(caInfoDto.isUseUserStorage())
                            .setUseCertificateStorage(caInfoDto.isUseCertificateStorage())
                            .setDoPreProduceOcspResponses(caInfoDto.isDoPreProduceOcspResponses())
                            .setDoStoreOcspResponsesOnDemand(caInfoDto.isDoStoreOcspResponsesOnDemand())
                            .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                            .setKeepExpiredCertsOnCRL(caInfoDto.isKeepExpiredOnCrl())
                            .setUsePartitionedCrl(caInfoDto.isUsePartitionedCrl())
                            .setCrlPartitions(caInfoDto.getCrlPartitions())
                            .setSuspendedCrlPartitions(caInfoDto.getSuspendedCrlPartitions())
                            .setRequestPreProcessor(caInfoDto.getRequestPreProcessor());
                    if (buttonCreateCa) {
                        X509CAInfo x509cainfo =  x509CAInfoBuilder
                                .setIncludeInHealthCheck(caInfoDto.isIncludeInHealthCheck())
                                .setSignedBy(signedBy)
                                .setCmpRaAuthSecret(caInfoDto.getSharedCmpRaSecret())
                                .build();
                        try {
                            caadminsession.createCA(authenticationToken, x509cainfo);
                        } catch (EJBException e) {
                            if (e.getCausedByException() instanceof IllegalArgumentException) {
                                //Couldn't create CA from the given parameters
                                illegaldnoraltname = true;
                            } else {
                                throw e;
                            }
                        }
	                }

	                if (buttonMakeRequest) {
                        X509CAInfo x509cainfo =  x509CAInfoBuilder
                                .setSignedBy(CAInfo.SIGNEDBYEXTERNALCA)
                                .setIncludeInHealthCheck(false) // Do not automatically include new CAs in health-check because it's not active
                                .build();
	                    saveRequestInfo(x509cainfo);
	                }
	            }
	        } else if (caInfoDto.getCaType() == CAInfo.CATYPE_CVC) {
	            // Only default values for these that are not used
	            long crlPeriod = 2400;
	            long crlIssueInterval = 0;
	            long crlOverlapTime = 0;
	            long deltaCrlPeriod = 0;
	            final List<Integer> crlPublishers = new ArrayList<>();
	            final List<Integer> keyValidators = new ArrayList<>();
                if (!illegaldnoraltname) {
                    // A CVC CA does not have any of the external services OCSP, CMS
	                List<ExtendedCAServiceInfo> extendedCaServices = new ArrayList<>();
	                if (buttonMakeRequest) {
	                    signedBy = CAInfo.SIGNEDBYEXTERNALCA;
	                }
	                // Create the CAInfo to be used for either generating the whole CA or making a request
	                CVCCAInfo cvccainfo = new CVCCAInfo(caInfoDto.getCaSubjectDN(), caInfoDto.getCaName(), CAConstants.CA_ACTIVE, new Date(),
	                        certprofileid, defaultCertProfileId, caInfoDto.getCaEncodedValidity(),
	                        null, caInfoDto.getCaType(), signedBy,
	                        null, caToken, caInfoDto.getDescription(), -1, null,
	                        crlPeriod, crlIssueInterval, crlOverlapTime, deltaCrlPeriod, crlPublishers, keyValidators,
	                        caInfoDto.isFinishUser(), extendedCaServices,
	                        approvals,
	                        false, // Do not automatically include new CAs in health-check
	                        caInfoDto.isDoEnforceUniquePublickeys(),
                            caInfoDto.isDoEnforceKeyRenewal(),
	                        caInfoDto.isDoEnforceUniqueDN(),
	                        caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber(),
                            caInfoDto.isUseCertReqHistory(),
                            caInfoDto.isUseUserStorage(),
                            caInfoDto.isUseCertificateStorage(),
                            caInfoDto.isAcceptRevocationsNonExistingEntry());
	                if (buttonCreateCa) {
	                    caadminsession.createCA(authenticationToken, cvccainfo);
	                } else if (buttonMakeRequest) {
	                    saveRequestInfo(cvccainfo);
	                }
	            }
	        } else if (caInfoDto.getCaType() == CAInfo.CATYPE_SSH) {
                // Create a X509 CA
                if (caInfoDto.getCaSubjectAltName() == null) {
                    caInfoDto.setCaSubjectAltName("");
                }

                // Check for invalid or malformed SAN
                String errorMessage = checkSubjectAltName(caInfoDto.getCaSubjectAltName());
                if (!StringUtils.isEmpty(errorMessage)) {
                   throw new ParameterException(errorMessage);
                }
                // TODO: Implement KRL publishing after initial release

                // TODO: Implement validators after initial release
                //final List<Integer> keyValidators = StringTools.idStringToListOfInteger(availableKeyValidatorValues, LIST_SEPARATOR);


                final List<String> nameConstraintsPermitted = parseNameConstraintsInput(caInfoDto.getNameConstraintsPermitted());
                final List<String> nameConstraintsExcluded = parseNameConstraintsInput(caInfoDto.getNameConstraintsExcluded());
                final boolean hasNameConstraints = !nameConstraintsPermitted.isEmpty() || !nameConstraintsExcluded.isEmpty();
                if (hasNameConstraints && !isNameConstraintAllowedInProfile(certprofileid)) {
                   throw new ParameterException(ejbcawebbean.getText("NAMECONSTRAINTSNOTENABLED"));
                }

                final int caSerialNumberOctetSize = (caInfoDto.getCaSerialNumberOctetSize() != null) ?
                        Integer.parseInt(caInfoDto.getCaSerialNumberOctetSize()) : CesecoreConfiguration.getSerialNumberOctetSizeForNewCa();
                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos(caInfoDto.getSignKeySpec(), caInfoDto.getCaSubjectDN(), caInfoDto.isServiceCmsActive());
                if (caInfoDto.getCrlPeriod() != 0 && !illegaldnoraltname) {
                    SshCaInfo.SshCAInfoBuilder sshCAInfoBuilder = new SshCaInfo.SshCAInfoBuilder()
                            .setSubjectDn(caInfoDto.getCaSubjectDN())
                            .setName(caInfoDto.getCaName())
                            .setStatus(CAConstants.CA_ACTIVE)
                            .setCertificateProfileId(certprofileid)
                            .setDefaultCertProfileId(defaultCertProfileId)
                            .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                            .setEncodedValidity(caInfoDto.getCaEncodedValidity())
                            .setCaType(caInfoDto.getCaType())
                            .setCertificateChain(null)
                            .setCaToken(caToken)
                            .setDescription(caInfoDto.getDescription())
                            .setCaSerialNumberOctetSize(caSerialNumberOctetSize)
                            .setFinishUser(caInfoDto.isFinishUser())
                            .setExtendedCaServiceInfos(extendedCaServiceInfos)
                            .setUseUtf8PolicyText(caInfoDto.isUseUtf8Policy())
                            .setUsePrintableStringSubjectDN(caInfoDto.isUsePrintableStringSubjectDN())
                            .setUseLdapDnOrder(caInfoDto.isUseLdapDNOrder())
                            .setDoEnforceUniquePublicKeys(caInfoDto.isDoEnforceUniquePublickeys())
                            .setDoEnforceKeyRenewal(caInfoDto.isDoEnforceKeyRenewal())
                            .setDoEnforceUniqueDistinguishedName(caInfoDto.isDoEnforceUniqueDN())
                            .setDoEnforceUniqueSubjectDNSerialnumber(caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber())
                            .setUseCertReqHistory(caInfoDto.isUseCertReqHistory())
                            .setUseUserStorage(caInfoDto.isUseUserStorage())
                            .setUseCertificateStorage(caInfoDto.isUseCertificateStorage())
                            .setSubjectAltName(caInfoDto.getCaSubjectAltName())
                            .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                            // TODO ECA-9293: SSH, add approvals here
                            .setApprovals(new HashMap<>());

                    if (buttonCreateCa) {
                        SshCaInfo sshCaInfo = sshCAInfoBuilder
                                .setIncludeInHealthCheck(caInfoDto.isIncludeInHealthCheck())
                                .setSignedBy(signedBy)
                                .build();
                        try {
                            caadminsession.createCA(authenticationToken, sshCaInfo);
                        } catch (EJBException e) {
                            if (e.getCausedByException() instanceof IllegalArgumentException) {
                                // Couldn't create CA from the given parameters
                                illegaldnoraltname = true;
                            } else {
                                throw e;
                            }
                        }
                    }

                    if (buttonMakeRequest) {
                        SshCaInfo sshCaInfo =  sshCAInfoBuilder
                                .setSignedBy(CAInfo.SIGNEDBYEXTERNALCA)
                                .setIncludeInHealthCheck(false) // Do not automatically include new CAs in health-check because it's not active
                                .build();
                        saveRequestInfo(sshCaInfo);
                    }
                }
            } else {
                throw new IllegalStateException("Unknown CA type with identifier " + caInfoDto.getCaType() + " was encountered.");
            }
	    }
        if (buttonMakeRequest && !illegaldnoraltname) {
            CAInfo cainfo = getRequestInfo();
            caadminsession.createCA(authenticationToken, cainfo);
            int caid = cainfo.getCAId();
            try {
                byte[] certreq = cadatahandler.makeRequest(caid, fileBuffer, caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
                saveRequestData(certreq);
            } catch (CryptoTokenOfflineException e) {
                casession.removeCA(authenticationToken, caid);
            }
        }
	    return illegaldnoraltname;
	}

	private List<String> parseNameConstraintsInput(String input) throws ParameterException {
        try {
            return NameConstraint.parseNameConstraintsList(input);
        } catch (CertificateExtensionException e) {
            throw new ParameterException(ejbcawebbean.getText("INVALIDNAMECONSTRAINT", false, e.getMessage()));
        }

    }

    public String isValidityTimeValid(String validityString) {
        // Fixed end dates are not limited
        if (ValidityDate.isValidIso8601Date(validityString)) {
            //We have a valid date, let's just check that it's in the future as well.
            Date validityDate;
            try {
                validityDate = ValidityDate.parseAsIso8601(validityString);
            } catch (ParseException e) {
               throw new IllegalStateException(validityString + " was an invalid date, but this should already have been checked.");
            }
            if (validityDate.before(new Date())) {
                return ejbcawebbean.getText("INVALIDVALIDITY_PAST");
            }
        } else {
            //Only positive relative times allowed.
            try {
                if (SimpleTime.parseMillies(validityString) <= 0) {
                    return ejbcawebbean.getText("INVALIDVALIDITYORCERTEND");
                }
            } catch (NumberFormatException e) {
                return ejbcawebbean.getText("INVALIDVALIDITYORCERTEND") + ": " + e.getMessage();
            }
        }
        return "";
    }


    private boolean isNameConstraintAllowedInProfile(int certProfileId) {
        final CertificateProfile certProfile = certificateProfileSession.getCertificateProfile(certProfileId);

        final boolean isCA = (certProfile.getType() == CertificateConstants.CERTTYPE_SUBCA ||
                certProfile.getType() == CertificateConstants.CERTTYPE_ROOTCA);

        return isCA && certProfile.getUseNameConstraints();
    }

    public List<ExtendedCAServiceInfo> makeExtendedServicesInfos(String keySpec, String subjectdn, boolean serviceCmsActive) {
	    String keyType = AlgorithmConstants.KEYALGORITHM_RSA;
        try {
            Integer.parseInt(keySpec);
        } catch (NumberFormatException e) {
            if (keySpec.startsWith("DSA")) {
                keyType = AlgorithmConstants.KEYALGORITHM_DSA;
            } else if (keySpec.startsWith(AlgorithmConstants.KEYSPECPREFIX_ECGOST3410)) {
                keyType = AlgorithmConstants.KEYALGORITHM_ECGOST3410;
            } else if (AlgorithmTools.isDstu4145Enabled() && keySpec.startsWith(CesecoreConfiguration.getOidDstu4145())) {
                keyType = AlgorithmConstants.KEYALGORITHM_DSTU4145;
            } else {
                keyType = AlgorithmConstants.KEYALGORITHM_ECDSA;
            }
        }

        final int cmsactive = serviceCmsActive ? ExtendedCAServiceInfo.STATUS_ACTIVE : ExtendedCAServiceInfo.STATUS_INACTIVE;

        List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>();
        // Create and active External CA Services.
        extendedcaservices.add(
                new CmsCAServiceInfo(cmsactive,
                        "CN=CMSCertificate, " + subjectdn, "",
                        keySpec, keyType));
        extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
        return extendedcaservices;
    }

    public String checkSubjectAltName(String subjectaltname) {
        if (subjectaltname != null && !subjectaltname.trim().equals("")) {
            final DNFieldExtractor subtest = new DNFieldExtractor(subjectaltname, DNFieldExtractor.TYPE_SUBJECTALTNAME);
            if (subtest.isIllegal() || subtest.existsOther()) {
                return ejbcawebbean.getText("INVALIDSUBJECTALT");
            }
        }
        return StringUtils.EMPTY;
    }

    public List<CertificatePolicy> parsePolicies(String policyid) {
        final ArrayList<CertificatePolicy> policies = new ArrayList<>();
        if (!(policyid == null || policyid.trim().equals(""))) {
            final String[] str = policyid.split("\\s+");
            if (str.length > 1) {
                policies.add(new CertificatePolicy(str[0], CertificatePolicy.id_qt_cps, str[1]));
            } else {
                policies.add(new CertificatePolicy((policyid.trim()),null,null));
            }
        }
        return policies;
    }

    public CAInfo createCaInfo(CaInfoDto caInfoDto, int caid, String subjectDn, Map<ApprovalRequestType, Integer> approvals,
	        String availablePublisherValues, String availableKeyValidatorValues) throws Exception {
        // We need to pick up the old CAToken, so we don't overwrite with default values when we save the CA further down
        CAInfo caInfo = casession.getCAInfo(authenticationToken, caid);
        CAToken catoken = caInfo.getCAToken();
        if (catoken == null) {
            catoken = new CAToken(caid, new Properties());
        }
        if (caInfoDto.getKeySequenceFormatAsString() == null) {
            catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        } else {
            catoken.setKeySequenceFormat(Integer.parseInt(caInfoDto.getKeySequenceFormatAsString()));
        }
        if (caInfoDto.getKeySequence() == null) {
            catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        } else {
            catoken.setKeySequence(caInfoDto.getKeySequence());
        }
        if (caInfoDto.getDescription() == null) {
            caInfoDto.setDescription("");
        }
        if (StringUtils.isBlank(caInfoDto.getCaEncodedValidity()) && caInfoDto.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
            // A validityString of null is allowed, when using a validity is not applicable
            caInfoDto.setCaEncodedValidity("0d");
        } else {
            try {
                // Fixed dates are not limited.
                ValidityDate.parseAsIso8601(caInfoDto.getCaEncodedValidity());
            } catch(ParseException e) {
                // Only positive relative times allowed.
                long millis;
                try {
                    millis = SimpleTime.getSecondsFormat().parseMillis(caInfoDto.getCaEncodedValidity());
                } catch(NumberFormatException nfe) {
                    throw new ParameterException(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
                }
                if (millis <= 0) {
                    throw new ParameterException(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
                }
                // format validityString before saving
                caInfoDto.setCaEncodedValidity(SimpleTime.toString(millis, SimpleTime.TYPE_DAYS));
            }
        }
        if (caid != 0 && caInfoDto.getCaType() != 0) {
            // First common info for both X509 CAs and CVC CAs
           CAInfo cainfo = null;
//           final List<Integer> approvalsettings = StringTools.idStringToListOfInteger(approvalSettingValues, LIST_SEPARATOR);
//           final int approvalProfileID = (approvalProfileParam==null ? -1 : Integer.parseInt(approvalProfileParam));
           final List<Integer> crlpublishers = StringTools.idStringToListOfInteger(availablePublisherValues, LIST_SEPARATOR);
           final List<Integer> keyValidators = StringTools.idStringToListOfInteger(availableKeyValidatorValues, LIST_SEPARATOR);

           // Info specific for X509 CA
           if (caInfoDto.isCaTypeX509()) {
               List<String> authorityInformationAccess = new ArrayList<>();
               if (StringUtils.isNotEmpty(caInfoDto.getAuthorityInformationAccess())) {
                   authorityInformationAccess = new ArrayList<>( Arrays.asList(caInfoDto.getAuthorityInformationAccess().split(LIST_SEPARATOR)));
               }
               List<String> certificateAiaDefaultCaIssuerUri = new ArrayList<>();
               if (StringUtils.isNotEmpty(caInfoDto.getCertificateAiaDefaultCaIssuerUri())) {
                   certificateAiaDefaultCaIssuerUri = new ArrayList<>( Arrays.asList(caInfoDto.getCertificateAiaDefaultCaIssuerUri().split(LIST_SEPARATOR)));
               }
               final String cadefinedfreshestcrl = (caInfoDto.getCaDefinedFreshestCRL() == null ? "" : caInfoDto.getCaDefinedFreshestCRL());
               if (caInfoDto.isUsePartitionedCrl() && (caInfoDto.getSuspendedCrlPartitions() >= caInfoDto.getCrlPartitions())) {
                   throw new ParameterException(ejbcawebbean.getText("CRLPARTITIONNUMBERINVALID"));
               }
               // Create extended CA Service updatedata.
               final int cmsactive = caInfoDto.isServiceCmsActive() ? ExtendedCAServiceInfo.STATUS_ACTIVE : ExtendedCAServiceInfo.STATUS_INACTIVE;
               final ArrayList<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>();
               extendedcaservices.add(new CmsCAServiceInfo(cmsactive, false));

               final int caSerialNumberOctetSize = (caInfoDto.getCaSerialNumberOctetSize() != null)
                       ? Integer.parseInt(caInfoDto.getCaSerialNumberOctetSize()) : CesecoreConfiguration.getSerialNumberOctetSizeForNewCa();

               // No need to add the Keyrecovery extended service here, because it is only "updated" in EditCA, and there
               // is not need to update it.
               X509CAInfo.X509CAInfoBuilder x509CAInfoBuilder = new X509CAInfo.X509CAInfoBuilder()
                       .setCaId(caid)
                       .setEncodedValidity(caInfoDto.getCaEncodedValidity())
                       .setCaToken(catoken)
                       .setDescription(caInfoDto.getDescription())
                       .setCaSerialNumberOctetSize(caSerialNumberOctetSize)
                       .setCrlPeriod(caInfoDto.getCrlPeriod())
                       .setCrlIssueInterval(caInfoDto.getCrlIssueInterval())
                       .setCrlOverlapTime(caInfoDto.getcrlOverlapTime())
                       .setDeltaCrlPeriod(caInfoDto.getDeltaCrlPeriod())
                       .setCrlPublishers(crlpublishers)
                       .setValidators(keyValidators)
                       .setUseAuthorityKeyIdentifier(caInfoDto.isUseAuthorityKeyIdentifier())
                       .setAuthorityKeyIdentifierCritical(caInfoDto.isAuthorityKeyIdentifierCritical())
                       .setUseCrlNumber(caInfoDto.isUseCrlNumber())
                       .setCrlNumberCritical(caInfoDto.isCrlNumberCritical())
                       .setDefaultCrlDistPoint(caInfoDto.getDefaultCRLDistPoint())
                       .setDefaultCrlIssuer(caInfoDto.getDefaultCRLIssuer())
                       .setDefaultOcspCerviceLocator(caInfoDto.getDefaultOCSPServiceLocator())
                       .setAuthorityInformationAccess(authorityInformationAccess)
                       .setCertificateAiaDefaultCaIssuerUri(certificateAiaDefaultCaIssuerUri)
                       .setNameConstraintsPermitted(parseNameConstraintsInput(caInfoDto.getNameConstraintsPermitted()))
                       .setNameConstraintsExcluded(parseNameConstraintsInput(caInfoDto.getNameConstraintsExcluded()))
                       .setCaDefinedFreshestCrl(cadefinedfreshestcrl)
                       .setFinishUser(caInfoDto.isFinishUser())
                       .setExtendedCaServiceInfos(extendedcaservices)
                       .setUseUtf8PolicyText(caInfoDto.isUseUtf8Policy())
                       .setApprovals(approvals)
                       .setUsePrintableStringSubjectDN(caInfoDto.isUsePrintableStringSubjectDN())
                       .setUseLdapDnOrder(caInfoDto.isUseLdapDNOrder())
                       .setUseCrlDistributionPointOnCrl(caInfoDto.isUseCrlDistributiOnPointOnCrl())
                       .setCrlDistributionPointOnCrlCritical(caInfoDto.isCrlDistributionPointOnCrlCritical())
                       .setIncludeInHealthCheck(caInfoDto.isIncludeInHealthCheck())
                       .setDoEnforceUniquePublicKeys(caInfoDto.isDoEnforceUniquePublickeys())
                       .setDoEnforceKeyRenewal(caInfoDto.isDoEnforceKeyRenewal())
                       .setDoEnforceUniqueDistinguishedName(caInfoDto.isDoEnforceUniqueDN())
                       .setDoEnforceUniqueSubjectDNSerialnumber(caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber())
                       .setUseCertReqHistory(caInfoDto.isUseCertReqHistory())
                       .setUseUserStorage(caInfoDto.isUseUserStorage())
                       .setUseCertificateStorage(caInfoDto.isUseCertificateStorage())
                       .setDoPreProduceOcspResponses(caInfoDto.isDoPreProduceOcspResponses())
                       .setDoStoreOcspResponsesOnDemand(caInfoDto.isDoStoreOcspResponsesOnDemand())
                       .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                       .setCmpRaAuthSecret(caInfoDto.getSharedCmpRaSecret())
                       .setKeepExpiredCertsOnCRL(caInfoDto.isKeepExpiredOnCrl())
                       .setDefaultCertProfileId(caInfoDto.getDefaultCertProfileId())
                       .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                       .setUsePartitionedCrl(caInfoDto.isUsePartitionedCrl())
                       .setCrlPartitions(caInfoDto.getCrlPartitions())
                       .setSuspendedCrlPartitions(caInfoDto.getSuspendedCrlPartitions())
                       .setRequestPreProcessor(caInfoDto.getRequestPreProcessor());
               cainfo = x509CAInfoBuilder.buildForUpdate();
            } else if (caInfoDto.getCaType() == CAInfo.CATYPE_CVC) {
               // Info specific for CVC CA


               // Edit CVC CA data
               // A CVC CA does not have any of the external services OCSP, CMS
               final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>();
               // Create the CAInfo to be used for either generating the whole CA or making a request
               cainfo = new CVCCAInfo(caid, caInfoDto.getCaEncodedValidity(),
                       catoken, caInfoDto.getDescription(),
                       caInfoDto.getCrlPeriod(), caInfoDto.getCrlIssueInterval(), caInfoDto.getcrlOverlapTime(), caInfoDto.getDeltaCrlPeriod(), crlpublishers, keyValidators,
                       caInfoDto.isFinishUser(), extendedcaservices,
                       approvals,
                       caInfoDto.isIncludeInHealthCheck(),
                       caInfoDto.isDoEnforceUniquePublickeys(),
                       caInfoDto.isDoEnforceKeyRenewal(),
                       caInfoDto.isDoEnforceUniqueDN(),
                       caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber(),
                       caInfoDto.isUseCertReqHistory(),
                       caInfoDto.isUseUserStorage(),
                       caInfoDto.isUseCertificateStorage(),
                       caInfoDto.isAcceptRevocationsNonExistingEntry(), caInfoDto.getDefaultCertProfileId());
            } else if (caInfoDto.getCaType() == CAInfo.CATYPE_SSH) {
                final int caSerialNumberOctetSize = (caInfoDto.getCaSerialNumberOctetSize() != null)
                        ? Integer.parseInt(caInfoDto.getCaSerialNumberOctetSize())
                        : CesecoreConfiguration.getSerialNumberOctetSizeForNewCa();
                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos(caInfoDto.getSignKeySpec(), caInfoDto.getCaSubjectDN(),
                        caInfoDto.isServiceCmsActive());

                SshCaInfo.SshCAInfoBuilder sshCAInfoBuilder = new SshCaInfo.SshCAInfoBuilder().setSubjectDn(caInfoDto.getCaSubjectDN())
                        .setName(caInfoDto.getCaName()).setStatus(CAConstants.CA_ACTIVE)
                        .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                        .setEncodedValidity(caInfoDto.getCaEncodedValidity()).setCaType(caInfoDto.getCaType()).setCertificateChain(null)
                        .setCaToken(catoken).setDescription(caInfoDto.getDescription()).setCaSerialNumberOctetSize(caSerialNumberOctetSize)
                        .setFinishUser(caInfoDto.isFinishUser()).setExtendedCaServiceInfos(extendedCaServiceInfos)
                        .setUseUtf8PolicyText(caInfoDto.isUseUtf8Policy()).setUsePrintableStringSubjectDN(caInfoDto.isUsePrintableStringSubjectDN())
                        .setUseLdapDnOrder(caInfoDto.isUseLdapDNOrder()).setDoEnforceUniquePublicKeys(caInfoDto.isDoEnforceUniquePublickeys())
                        .setDoEnforceKeyRenewal(caInfoDto.isDoEnforceKeyRenewal())
                        .setDoEnforceUniqueDistinguishedName(caInfoDto.isDoEnforceUniqueDN())
                        .setDoEnforceUniqueSubjectDNSerialnumber(caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber())
                        .setUseCertReqHistory(caInfoDto.isUseCertReqHistory()).setUseUserStorage(caInfoDto.isUseUserStorage())
                        .setUseCertificateStorage(caInfoDto.isUseCertificateStorage()).setSubjectAltName(caInfoDto.getCaSubjectAltName())
                        .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                        .setCaId(caid)
                        // TODO ECA-9293: SSH, add approvals here
                        .setApprovals(new HashMap<>());
                cainfo = sshCAInfoBuilder.buildForUpdate();
            }
            cainfo.setSubjectDN(subjectDn);
            cainfo.setStatus(caInfo.getStatus());
            cainfo.setName(caInfo.getName());
            return cainfo;
        }
        return null;
	}

    public List<Entry<String, String>> getAvailableCryptoTokens(final String caSigingAlgorithm, boolean isEditingCA)
            throws AuthorizationDeniedException {
	    final List<Entry<String, String>> availableCryptoTokens = new ArrayList<>();
	    if (caSigingAlgorithm != null && caSigingAlgorithm.length()>0) {
	        final List<CryptoTokenInfo> cryptoTokenInfos = cryptoTokenManagementSession.getCryptoTokenInfos(authenticationToken);
            for (final CryptoTokenInfo cryptoTokenInfo : cryptoTokenInfos) {
                // Make sure we may use it
                if (authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.USE.resource() + '/' + cryptoTokenInfo.getCryptoTokenId())
                        && cryptoTokenInfo.isActive()) {
	                final int cryptoTokenId = cryptoTokenInfo.getCryptoTokenId();
	                try {
    	                // Fetch a list of all keys and their specs
    	                final List<KeyPairInfo> cryptoTokenKeyPairInfos = cryptoTokenManagementSession.getKeyPairInfos(authenticationToken, cryptoTokenId);
    	                // Only allow tokens with at least one keypair
    	                if (!cryptoTokenKeyPairInfos.isEmpty()) {
    	                    for (final KeyPairInfo cryptoTokenKeyPairInfo : cryptoTokenKeyPairInfos) {
    	                        String requiredKeyAlgorithm = AlgorithmTools.getKeyAlgorithmFromSigAlg(caSigingAlgorithm);
    	                        if (requiredKeyAlgorithm.equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())) {
    	                            // We have at least on key in this token with the right key algorithm mathing the CA's singing algorithm, so add the token!
    	                            availableCryptoTokens.add(new AbstractMap.SimpleEntry<>(Integer.toString(cryptoTokenId), cryptoTokenInfo.getName()));
    	                            break; // This token is fine, proceed with next token
    	                        }
    	                    }
    	                }
	                } catch (CryptoTokenOfflineException ctoe) {
	                   // The CryptoToken might have timed out
	                }
	            }
	        }
	    }
        availableCryptoTokens.sort(new EntryValueComparator<>(new AsStringComparator()));
        if (!isEditingCA && authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.MODIFY_CRYPTOTOKEN.resource())) {
            // Add a quick setup option for key generation (not visible when editing an uninitialized CA)
            availableCryptoTokens.add(0, new AbstractMap.SimpleEntry<>(Integer.toString(0), ejbcawebbean.getText("CRYPTOTOKEN_NEWFROMCA")));
        }
	    return availableCryptoTokens;
	}

	public List<Entry<String, String>> getFailedCryptoTokens(final String caSigingAlgorithm) throws AuthorizationDeniedException {
        final List<Entry<String, String>> failedCryptoTokens = new ArrayList<>();
        if (caSigingAlgorithm != null && caSigingAlgorithm.length()>0) {
            final List<CryptoTokenInfo> cryptoTokenInfos = cryptoTokenManagementSession.getCryptoTokenInfos(authenticationToken);
            for (final CryptoTokenInfo cryptoTokenInfo : cryptoTokenInfos) {
                // Make sure we may use it
                if (authorizationSession.isAuthorizedNoLogging(authenticationToken, CryptoTokenRules.USE.resource() + '/' + cryptoTokenInfo.getCryptoTokenId())
                        && cryptoTokenInfo.isActive()) {
                    final int cryptoTokenId = cryptoTokenInfo.getCryptoTokenId();
                    try {
                        // Try to access to keys
                        cryptoTokenManagementSession.getKeyPairInfos(authenticationToken, cryptoTokenId);
                    } catch (CryptoTokenOfflineException ctoe) {
                       failedCryptoTokens.add(new AbstractMap.SimpleEntry<>(Integer.toString(cryptoTokenId), cryptoTokenInfo.getName()));
                    }
                }
            }
        }
        return failedCryptoTokens;
    }

	public List<KeyPairInfo> getKeyPairInfos(int cryptoTokenId) throws CryptoTokenOfflineException, AuthorizationDeniedException {
	    if (cryptoTokenManagementSession.getCryptoTokenInfo(cryptoTokenId) == null) {
           log.debug("CryptoToken didn't exist when trying to get aliases");
           return Collections.emptyList();
        }
        return cryptoTokenManagementSession.getKeyPairInfos(authenticationToken, cryptoTokenId);
	}

    /** @return a list of key pair aliases that can be used for either signing or encryption under the supplied CA signing algorithm */
    public List<String> getAvailableCryptoTokenMixedAliases(final List<KeyPairInfo> keyPairInfos, final String caSigingAlgorithm) {
        final List<String> aliases = new ArrayList<>(getAvailableCryptoTokenAliases(keyPairInfos, caSigingAlgorithm));
        final List<String> encAliases = getAvailableCryptoTokenEncryptionAliases(keyPairInfos, caSigingAlgorithm);
        aliases.removeAll(encAliases);  // Avoid duplicates
        aliases.addAll(encAliases);
        return aliases;
    }

    /** @return a list of key pair aliases that can be used for signing using the supplied CA signing algorithm */
	public List<String> getAvailableCryptoTokenAliases(final List<KeyPairInfo> keyPairInfos, final String caSigingAlgorithm) {
	    final List<String> aliases = new ArrayList<>();
        for (final KeyPairInfo cryptoTokenKeyPairInfo : keyPairInfos) {
            if (AlgorithmTools.getKeyAlgorithmFromSigAlg(caSigingAlgorithm).equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())) {
                aliases.add(cryptoTokenKeyPairInfo.getAlias());
            }
        }
        return aliases;
	}

    /** @return a list of key pair aliases that can be used for encryption using the supplied CA signing algorithm to derive encryption algo. */
    public List<String> getAvailableCryptoTokenEncryptionAliases(final List<KeyPairInfo> keyPairInfos, final String caSigingAlgorithm) {
        final List<String> aliases = new ArrayList<>();
        for (final KeyPairInfo cryptoTokenKeyPairInfo : keyPairInfos) {
            if (AlgorithmTools.getKeyAlgorithmFromSigAlg(AlgorithmTools.getEncSigAlgFromSigAlg(caSigingAlgorithm)).equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())) {
                aliases.add(cryptoTokenKeyPairInfo.getAlias());
            }
        }
        return aliases;
    }

	/**
	 *
	 * @return true if admin has general read rights to CAs, but no edit rights.
	 */
    public boolean hasEditRight() {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAEDIT.resource());
    }

    public boolean hasCreateRight() {
        return authorizationSession.isAuthorizedNoLogging(authenticationToken, StandardRules.CAADD.resource());
    }

	public boolean isCaExportable(CAInfo caInfo) {
	    boolean ret = false;
	    final int caInfoStatus = caInfo.getStatus();
	    if (caInfoStatus != CAConstants.CA_EXTERNAL && caInfoStatus != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE) {
	        final int cryptoTokenId = caInfo.getCAToken().getCryptoTokenId();
	        final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(cryptoTokenId);
	        if (cryptoTokenInfo!=null) {
	            ret = (SoftCryptoToken.class.getSimpleName().equals(cryptoTokenInfo.getType())) && cryptoTokenInfo.isAllowExportPrivateKey();
	        }
	    }
	    return ret;
	}

	public List<Entry<String,String>> getAvailableCaCertificateProfiles() {
	    final int[] types = { CertificateConstants.CERTTYPE_ROOTCA, CertificateConstants.CERTTYPE_SUBCA };
        final Map<Integer, String> idToNameMap = certificateProfileSession.getCertificateProfileIdToNameMap();
        final List<Entry<String,String>> ret = new ArrayList<>();
	    for (int type : types) {
	        final Collection<Integer> ids = certificateProfileSession.getAuthorizedCertificateProfileIds(authenticationToken, type);
	        for (final Integer id : ids) {
	            ret.add(new SimpleEntry<>(id.toString(), (type==CertificateConstants.CERTTYPE_ROOTCA ? "(RootCAs) " : "(SubCAs) ") + idToNameMap.get(id)));
	        }
	    }
        return ret;
	}

    public List<Entry<String,String>> getAvailableKeySpecs() {
        final List<Entry<String,String>> ret = new ArrayList<>();
        // Legacy idea: Never use larger keys than 2048 bit RSA for CMS signing
        // Reference: RFC 6485 - The Profile for Algorithms and Key Sizes for Use in the Resource PKI. [§ 3, and 5]
        final int[] SIZES_RSA = {1024, 1536, 2048, 3072, 4096/*, 6144, 8192*/};
        final int[] SIZES_DSA = {1024};
        for (int size : SIZES_RSA) {
            ret.add(new SimpleEntry<>(String.valueOf(size), "RSA "+size));
        }
        for (int size : SIZES_DSA) {
            ret.add(new SimpleEntry<>("DSA"+size, "DSA "+size));
        }
        @SuppressWarnings("unchecked")
        final Enumeration<String> ecNamedCurves = ECNamedCurveTable.getNames();
        while (ecNamedCurves.hasMoreElements()) {
            final String ecNamedCurve = ecNamedCurves.nextElement();
            ret.add(new SimpleEntry<>(ecNamedCurve, "ECDSA "+ecNamedCurve));
        }

        for (String alg : CesecoreConfiguration.getExtraAlgs()) {
            for (String subalg : CesecoreConfiguration.getExtraAlgSubAlgs(alg)) {
                final String title = CesecoreConfiguration.getExtraAlgSubAlgTitle(alg, subalg);
                final String name = CesecoreConfiguration.getExtraAlgSubAlgName(alg, subalg);
                ret.add(new SimpleEntry<>(name, title));
            }
        }

        return ret;
    }

    public boolean createAuthCertSignRequest(int caid, byte[] request) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        if (request != null) {
            byte[] signedreq = caadminsession.createAuthCertSignRequest(authenticationToken, caid, request);
            saveRequestData(signedreq);
            return true;
        }
        return false;
    }

    public byte[] parseRequestParameters(HttpServletRequest request, Map<String, String> requestMap) throws IOException {
        byte[] fileBuffer = null;
        try {
            if (ServletFileUpload.isMultipartContent(request)) {
                final DiskFileItemFactory diskFileItemFactory = new DiskFileItemFactory();
                diskFileItemFactory.setSizeThreshold(59999);
                ServletFileUpload upload = new ServletFileUpload(diskFileItemFactory);
                upload.setSizeMax(60000);
                final List<FileItem> items = upload.parseRequest(request);
                for (final FileItem item : items) {
                    if (item.isFormField()) {
                        final String fieldName = item.getFieldName();
                        final String currentValue = requestMap.get(fieldName);
                        if (currentValue != null) {
                            requestMap.put(fieldName, currentValue + ";" + item.getString("UTF8"));
                        } else {
                            requestMap.put(fieldName, item.getString("UTF8"));
                        }
                    } else {
                        //final String itemName = item.getName();
                        final InputStream file = item.getInputStream();
                        byte[] fileBufferTmp = FileTools.readInputStreamtoBuffer(file);
                        if (fileBuffer == null && fileBufferTmp.length > 0) {
                            fileBuffer = fileBufferTmp;
                        }
                    }
                }
            } else {
                final Set<String> keySet = request.getParameterMap().keySet();
                for (final String key : keySet) {
                    requestMap.put(key, request.getParameter(key));
                }
            }
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (FileUploadException e) {
            throw new IOException(e);
        }
        return fileBuffer;
    }

    /** Returns true if any CVC CA implementation is available, false otherwise.
     * Used to hide/give warning when no CVC CA implementation is available.
     */
    public boolean isCvcAvailable() {
        boolean ret = false;
        ServiceLoader<? extends CvcPlugin> loader = CvcCABase.getImplementationClasses();
        if (loader.iterator().hasNext()) {
            ret = true;
        }
        return ret;
    }
    /** Returns true if a unique (issuerDN,serialNumber) is present in the database.
     * If this is available, you can not use CVC CAs. Returns false if a unique index is
     * Used to hide/give warning when no CVC CA implementation is available.
     */
    public boolean isUniqueIssuerDNSerialNoIndexPresent() {
        return certificatesession.isUniqueCertificateSerialNumberIndex();
    }

    /** Returns the "not before" date of the next certificate during a rollover period, or null if no next certificate exists.
     * @throws CADoesntExistsException If the CA doesn't exist.
     */
    public Date getRolloverNotBefore(int caid) throws CADoesntExistsException {
        final Certificate nextCert = casession.getFutureRolloverCertificate(caid);
        if (nextCert != null) {
            return CertTools.getNotBefore(nextCert);
        }
        return null;
    }
    /** Returns the "not after" date of the next certificate during a rollover period, or null if no next certificate exists.
     * @throws CADoesntExistsException If the CA doesn't exist.
     */
    public Date getRolloverNotAfter(int caid) throws CADoesntExistsException {
        final Certificate nextCert = casession.getFutureRolloverCertificate(caid);
        if (nextCert != null) {
            return CertTools.getNotAfter(nextCert);
        }
        return null;
    }

    /**
     * Returns the current CA validity "not after" date.
     * @return Not after date, or null if the CA does not have a certificate yet.
     * @throws AuthorizationDeniedException authorization denied exception.
     */
    public Date getCANotAfter(int caid) throws AuthorizationDeniedException {
        final Collection<Certificate> chain = casession.getCAInfo(authenticationToken, caid).getCertificateChain();
        return CollectionUtils.isNotEmpty(chain) ? CertTools.getNotAfter(chain.iterator().next()) : null;
    }

    /**
     * Checks if keys in current crypto token are already in use by another CA or not
     * This method used while creating a new CA to warn users about keys which are already in use
     * by other CAs.
     *
     * @param CAIds CA ids.
     * @param alias alias.
     * @param currentCryptoTokenId crypto token id.
     * @return boolean true if crypto key is used by another CA or false otherwise.
     * @throws IllegalStateException illegal state exception.
     */
    public boolean isKeyInUse(final Collection<Integer> CAIds, final String alias, final int currentCryptoTokenId) {
        for (final int caId : CAIds) {
            final CAInfo caInfo = casession.getCAInfoInternal(caId);
            if (cainfo != null && currentCryptoTokenId == caInfo.getCAToken().getCryptoTokenId() && caInfo.getCAToken().getProperties().contains(alias))
                return true;
        }
        return false;
    }
}
