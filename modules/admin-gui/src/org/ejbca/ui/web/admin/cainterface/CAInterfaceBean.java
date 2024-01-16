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

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.text.ParseException;
import java.util.AbstractMap;
import java.util.AbstractMap.SimpleEntry;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.stream.Collectors;

import javax.ejb.EJBException;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.MutablePair;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.CryptoTokenRules;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CVCCAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CitsCaInfo;
import org.cesecore.certificates.ca.CvcCABase;
import org.cesecore.certificates.ca.CvcPlugin;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.kfenroll.ProxyCaInfo;
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
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.util.AsStringComparator;
import org.cesecore.util.EntryValueComparator;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.ParameterException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.RevokedInfoView;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.util.cert.OID;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 * <p>
 * Semi-deprecated, we should try to move the methods here into session beans or managed beans.
 */
public class CAInterfaceBean implements Serializable {

	private static final long serialVersionUID = 3L;
	private static final Logger log = Logger.getLogger(CAInterfaceBean.class);
	private static final String LIST_SEPARATOR = ";";

	public static final int PLACEHOLDER_CRYPTO_TOKEN_ID = 0;

	private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private AuthorizationSessionLocal authorizationSession;
    private CAAdminSessionLocal caadminsession;
    private CaSessionLocal casession;
    private CertificateProfileSession certificateProfileSession;
    private CertificateStoreSessionLocal certificatesession;
    private CertReqHistorySessionLocal certreqhistorysession;
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    private PublisherSessionLocal publishersession;
    private KeyValidatorSessionLocal keyValidatorSession;

    private SignSession signsession;

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
          keyValidatorSession = ejbLocalHelper.getKeyValidatorSession();
          authenticationToken = ejbcawebbean.getAdminObject();
          this.ejbcawebbean = ejbcawebbean;
          initialized =true;
        } else {
            log.debug("=initialize(): already initialized");
        }
        log.trace("<initialize()");
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

    /** Slow method to get CAInfo. The returned object has id-to-name maps of publishers and validators. */
    public CAInfoView getCAInfo(int caid) throws AuthorizationDeniedException {
      final CAInfo cainfo = casession.getCAInfo(authenticationToken, caid);
      return new CAInfoView(cainfo, ejbcawebbean, publishersession.getPublisherIdToNameMap(), keyValidatorSession.getKeyValidatorIdToNameMap());
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

	public String getRequestDataAsString(final int caType) {
		String returnval = null;
		if(request != null ){
		    returnval = RequestHelper.BEGIN_CERTIFICATE_REQUEST_WITH_NL;
		    if(caType == CAInfo.CATYPE_CITS) {
		        returnval += Hex.toHexString(request);
		    } else {
		        returnval += new String(Base64.encode(request, true));
		    }
			returnval += RequestHelper.END_CERTIFICATE_REQUEST_WITH_NL;
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
	 * Returns a List of CertReqHistUserData from the certreqhist database in a collection sorted by timestamp.
	 */
	public List<CertReqHistory> getCertReqUserDatas(String username){
		List<CertReqHistory> history = this.certreqhistorysession.retrieveCertReqHistory(username);
		// Sort it by timestamp, newest first;
		history.sort(new CertReqUserCreateComparator());
		return history;
	}


    public boolean actionCreateCaMakeRequest(CaInfoDto caInfoDto, Map<ApprovalRequestType, Integer> approvals,
            String availablePublisherValues, String availableKeyValidatorValues,
            boolean buttonCreateCa, boolean buttonMakeRequest,
            byte[] fileBuffer) throws Exception {
        // Proxy Ca is exceptional in behavior, so, just saving it straight
        if (caInfoDto.isCaTypeProxy()) {
            return actionCreateCaMakeRequestInternal(caInfoDto, null, null, null, buttonCreateCa, buttonMakeRequest, 0, fileBuffer);
        }
        // This will occur if administrator has insufficient access to crypto tokens, which won't provide any
        // selectable items for Crypto Token when creating a CA.
        if (StringUtils.isEmpty(caInfoDto.getCryptoTokenIdParam())) {
            log.info("No crypto token selected. Check crypto token access rules for administrator " + authenticationToken);
            throw new CryptoTokenAuthenticationFailedException("Crypto token authentication failed for administrator " + authenticationToken);
        }
        caInfoDto.setCaSubjectDN(StringTools.capitalizeCountryCodeInSubjectDN(caInfoDto.getCaSubjectDN()));
        int cryptoTokenId = Integer.parseInt(caInfoDto.getCryptoTokenIdParam());
        return actionCreateCaMakeRequestInternal(caInfoDto, approvals, availablePublisherValues, availableKeyValidatorValues,
                buttonCreateCa, buttonMakeRequest, cryptoTokenId, fileBuffer);
    }

    /**
     * 
     * @throws ParameterException if any of the input from the web was invalid
     * @throws AuthorizationDeniedException if the current admin did not have access to the selected resources
     * @throws CryptoTokenOfflineException if the crypto token was unavailable
     * @throws InvalidAlgorithmException no signing algorithm was defined for this CA
     * @throws CAExistsException if a CA of this name/subjectDN already exists
     * @throws CADoesntExistsException if the CA was not created
     */
	private boolean actionCreateCaMakeRequestInternal(CaInfoDto caInfoDto, Map<ApprovalRequestType, Integer> approvals,
            String availablePublisherValues, String availableKeyValidatorValues,
            boolean buttonCreateCa, boolean buttonMakeRequest,
            int cryptoTokenId,
            byte[] fileBuffer) throws ParameterException, CryptoTokenOfflineException, AuthorizationDeniedException, InvalidAlgorithmException, CAExistsException, CADoesntExistsException {

        if (caInfoDto.isCaTypeProxy()) {
            ProxyCaInfo.ProxyCaInfoBuilder proxyCaInfoBuilder = createProxyCaInfoBuilder(caInfoDto);
            if (buttonCreateCa) {
                ProxyCaInfo proxyCaInfo =  proxyCaInfoBuilder
                    .build();
                proxyCaInfo.setSubjectDN(caInfoDto.getCaSubjectDN());
                proxyCaInfo.setEncodedValidity("99y");
                final int caid = DnComponents.stringToBCDNString(proxyCaInfo.getSubjectDN()).hashCode();
                proxyCaInfo.setCAId(caid);

                try {
                    caadminsession.createCA(authenticationToken, proxyCaInfo);
                } catch (CAExistsException | CryptoTokenOfflineException | InvalidAlgorithmException | AuthorizationDeniedException e) {
                    throw e;
                }

            }
            return false;
        }

	    boolean illegaldnoraltname = false;

	    final List<String> keyPairAliases = cryptoTokenManagementSession.getKeyPairAliases(authenticationToken, cryptoTokenId);
	    if (!keyPairAliases.contains(caInfoDto.getCryptoTokenDefaultKey())) {
            log.info(authenticationToken.toString() + " attempted to createa a CA with a non-existing defaultKey alias: " + caInfoDto.getCryptoTokenDefaultKey());
            throw new CryptoTokenOfflineException("Invalid default key alias!");
	    }
        final String[] suppliedAliases = {caInfoDto.getCryptoTokenCertSignKey(), caInfoDto.getCryptoTokenAlternativeCertSignKey(), caInfoDto.getCryptoTokenCertSignKey(), caInfoDto.getSelectedKeyEncryptKey(), caInfoDto.getTestKey()};
        for (final String currentSuppliedAlias : suppliedAliases) {
            if (currentSuppliedAlias.length()>0 && !keyPairAliases.contains(currentSuppliedAlias)) {
                log.info(authenticationToken.toString() + " attempted to create a CA with a non-existing key alias: "+currentSuppliedAlias);
                throw new IllegalStateException("Invalid key alias!");
            }
        }
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, caInfoDto.getCryptoTokenDefaultKey());
        if (caInfoDto.getCryptoTokenCertSignKey().length() > 0) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
        }
        if (caInfoDto.getCryptoTokenCertSignKey().length() > 0 && caInfoDto.getCaType() != CAInfo.CATYPE_CITS) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, caInfoDto.getCryptoTokenCertSignKey());
        }
        if (caInfoDto.getSelectedKeyEncryptKey().length() > 0 && caInfoDto.getCaType() != CAInfo.CATYPE_CITS) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING, caInfoDto.getSelectedKeyEncryptKey());
        }
        if (caInfoDto.getTestKey().length() > 0) {
            caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING, caInfoDto.getTestKey());
        }
        //Hybrid certs only implemented for X509
        if (caInfoDto.isCaTypeX509()) {
            if (!StringUtils.isEmpty(caInfoDto.getCryptoTokenAlternativeCertSignKey())) {
                caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_ALTERNATIVE_CERTSIGN_STRING,
                        caInfoDto.getCryptoTokenAlternativeCertSignKey());
            } 
            
        }
        final CAToken caToken = new CAToken(cryptoTokenId, caTokenProperties);
        //Hybrid certs only implemented for X509
        if (caInfoDto.isCaTypeX509()) {
            if (!StringUtils.isEmpty(caInfoDto.getAlternativeSignatureAlgorithmParam())) {
                caToken.setAlternativeSignatureAlgorithm(caInfoDto.getAlternativeSignatureAlgorithmParam());
                //Future proofing to allow the alternative key to potentially be on a different crypto token
            }      
        }
       
        if (caInfoDto.getSignatureAlgorithmParam() == null) {
            throw new InvalidAlgorithmException("No signature algorithm supplied!");
        }
        caToken.setSignatureAlgorithm(caInfoDto.getSignatureAlgorithmParam());
        PublicKey encryptionKey = cryptoTokenManagementSession.getCryptoToken(cryptoTokenId).getPublicKey(caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_KEYENCRYPT));
        caToken.setEncryptionAlgorithm(AlgorithmTools.getEncSigAlgFromSigAlg(caInfoDto.getSignatureAlgorithmParam(), encryptionKey));
                
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
        if(!caInfoDto.isCaTypeX509() && !caInfoDto.isCaTypeCits()) {
    	    try {
    	        DnComponents.stringToBcX500Name(caInfoDto.getCaSubjectDN());
    	    } catch (IllegalArgumentException e) {
    	        illegaldnoraltname = true;
    	    }
	    }
        int certprofileid = (caInfoDto.getCurrentCertProfile()==null ? 0 : Integer.parseInt(caInfoDto.getCurrentCertProfile()));
        int defaultCertProfileId = (caInfoDto.getDefaultCertificateProfile() == null ? 0 : Integer.parseInt(caInfoDto.getDefaultCertificateProfile()));
        int signedBy = caInfoDto.getSignedBy();

	    if (caInfoDto.getDescription() == null) {
            caInfoDto.setDescription("");
	    }

	    // If 'buttonMakeRequest' set encodedValidity to zero days, otherwise perform validation if it's an absolute date or a relative time.
	    if (buttonMakeRequest && caInfoDto.getCaType() != CAInfo.CATYPE_CITS) {
	        caInfoDto.setCaEncodedValidity("0d"); // not applicable
        } else {
            String errorMessage = isValidityTimeValid(caInfoDto.getCaEncodedValidity(), 
                                        caInfoDto.getCaType()==CAInfo.CATYPE_CITS);
            if(!StringUtils.isEmpty(errorMessage)) {
                throw new ParameterException(errorMessage);
            }
        }

	    if (caInfoDto.getCaType() != 0 && caInfoDto.getCaSubjectDN() != null && caInfoDto.getCaName() != null && signedBy != 0) {

	        // Approvals is generic for all types of CAs

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
	            for (CertificatePolicy certificatePolicy : policies) {
	                if (!OID.isValidOid(certificatePolicy.getPolicyID())) {
	                    throw new ParameterException(ejbcawebbean.getText("INVALIDPOLICYOID"));                                              
	                }
	            }
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
                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos();
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
                            .setGenerateCrlUponRevocation(caInfoDto.isGenerateCrlUponRevocation())
                            .setAllowChangingRevocationReason(caInfoDto.isAllowChangingRevocationReason())
                            .setAllowInvalidityDate(caInfoDto.isAllowInvalidityDate())
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
							.setDoPreProduceIndividualOcspResponses(caInfoDto.isDoPreProduceOcspResponseUponIssuanceAndRevocation())
                            .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                            .setKeepExpiredCertsOnCRL(caInfoDto.isKeepExpiredOnCrl())
                            .setUsePartitionedCrl(caInfoDto.isUsePartitionedCrl())
                            .setCrlPartitions(caInfoDto.getCrlPartitions())
                            .setSuspendedCrlPartitions(caInfoDto.getSuspendedCrlPartitions())
                            .setMsCaCompatible(caInfoDto.isMsCaCompatible())
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

                final List<String> nameConstraintsPermitted = parseNameConstraintsInput(caInfoDto.getNameConstraintsPermitted());
                final List<String> nameConstraintsExcluded = parseNameConstraintsInput(caInfoDto.getNameConstraintsExcluded());
                final boolean hasNameConstraints = !nameConstraintsPermitted.isEmpty() || !nameConstraintsExcluded.isEmpty();
                if (hasNameConstraints && !isNameConstraintAllowedInProfile(certprofileid)) {
                   throw new ParameterException(ejbcawebbean.getText("NAMECONSTRAINTSNOTENABLED"));
                }

                final int caSerialNumberOctetSize = (caInfoDto.getCaSerialNumberOctetSize() != null) ?
                        Integer.parseInt(caInfoDto.getCaSerialNumberOctetSize()) : CesecoreConfiguration.getSerialNumberOctetSizeForNewCa();
                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos();
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
            } else if (caInfoDto.getCaType() == CAInfo.CATYPE_CITS) {
                // TODO: Validations on CaInfoDTO

                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos();
                final List<Integer> keyValidators = StringTools.idStringToListOfInteger(availableKeyValidatorValues, LIST_SEPARATOR);
                CitsCaInfo.CitsCaInfoBuilder citsCaInfoBuilder = new CitsCaInfo.CitsCaInfoBuilder()
                                           .setName(caInfoDto.getCaName())
                                           .setDescription(caInfoDto.getDescription())
                                           .setCertificateProfileId(certprofileid)
                                           .setEncodedValidity(caInfoDto.getCaEncodedValidity())
                                           .setCaType(caInfoDto.getCaType())
                                           .setStatus(CAConstants.CA_ACTIVE)
                                           .setSignedBy(signedBy)
                                           .setUpdateTime(new Date())
                                           .setExpireTime(null)
                                           .setCertificateChain(null)
                                           .setCaToken(caToken)
                                           .setApprovals(new HashMap<>()) // Approvals not implement yet for citsca
                                           .setExtendedCAServiceInfos(extendedCaServiceInfos)
                                           .setValidators(keyValidators)
                                           .setFinishUser(caInfoDto.isFinishUser())
                                           .setIncludeInHealthCheck(caInfoDto.isIncludeInHealthCheck())
                                           .setDoEnforceUniquePublicKeys(caInfoDto.isDoEnforceUniquePublickeys())
                                           .setDoEnforceKeyRenewal(caInfoDto.isDoEnforceKeyRenewal())
                                           .setDoEnforceUniqueDistinguishedName(caInfoDto.isDoEnforceUniqueDN())
                                           .setDoEnforceUniqueSubjectDNSerialnumber(caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber())
                                           .setUseCertReqHistory(caInfoDto.isUseCertReqHistory())
                                           .setUseUserStorage(caInfoDto.isUseUserStorage())
                                           .setUseCertificateStorage(caInfoDto.isUseCertificateStorage())
                                           .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                                           .setDefaultCertProfileId(defaultCertProfileId)
                                           .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                                           .setCertificateId(caInfoDto.getCertificateId())
                                           .setRegion(caInfoDto.getRegion());

                CitsCaInfo citsCaInfo =  citsCaInfoBuilder.build();

                saveRequestInfo(citsCaInfo);
            } else {
                throw new IllegalStateException("Unknown CA type with identifier " + caInfoDto.getCaType() + " was encountered.");
            }
	    } 
        if (buttonMakeRequest && !illegaldnoraltname) {
            CAInfo cainfo = getRequestInfo();
            caadminsession.createCA(authenticationToken, cainfo);
            int caid = cainfo.getCAId();
            try {
                byte[] certreq = null;
                if (caInfoDto.getCaType() == CAInfo.CATYPE_CITS) {
                    certreq = caadminsession.makeCitsRequest(authenticationToken, caid, 
                            fileBuffer, caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
                            caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN),
                            caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_DEFAULT));
                } else {
                    certreq = caadminsession.makeRequest(authenticationToken, caid, 
                                       fileBuffer, caToken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
                }
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

    public String isValidityTimeValid(String validityString, boolean isCitsCa) {
        
        if(isCitsCa) {
            if(StringUtils.isEmpty(validityString)) {
                return ""; // during edit CA
            }
            try {
                if (SimpleTime.parseItsValidity(validityString) <= 0) {
                    return ejbcawebbean.getText("INVALIDVALIDITYORCERTEND");
                }
            } catch (NumberFormatException e) {
                return ejbcawebbean.getText("INVALIDVALIDITYORCERTEND") + ": " + e.getMessage();
            }
        }
        // Fixed end dates are not limited
        else if (ValidityDate.isValidIso8601Date(validityString)) {
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
                if (SimpleTime.parseMillis(validityString) <= 0) {
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

    public List<ExtendedCAServiceInfo> makeExtendedServicesInfos() {
        List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>();
        // Create and active External CA Services.
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
        if (!(policyid == null || policyid.trim().isEmpty() || policyid.trim().equals(ejbcawebbean.getText("NONE")))) {
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
        
        if(caInfoDto.isCaTypeCits()) {
            if(StringUtils.isEmpty(caInfoDto.getCaEncodedValidity())){
                // only needed if remote bean is used i.e. non CA GUI
                throw new ParameterException(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
            }
            try {
                if (SimpleTime.parseItsValidity(caInfoDto.getCaEncodedValidity()) <= 0) {
                    throw new ParameterException(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND"));
                }
            } catch (NumberFormatException e) {
                throw new ParameterException(ejbcawebbean.getText("INVALIDVALIDITYORCERTEND") + ": " + e.getMessage());
            }
            // no need to convert to hours(not days like other cases) here
        } else if (StringUtils.isBlank(caInfoDto.getCaEncodedValidity()) 
                && caInfoDto.getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
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
               // Update extended CA Service data.
               List<ExtendedCAServiceInfo> extendedcaservices = makeExtendedServicesInfos();

               final int caSerialNumberOctetSize = (caInfoDto.getCaSerialNumberOctetSize() != null)
                       ? Integer.parseInt(caInfoDto.getCaSerialNumberOctetSize()) : CesecoreConfiguration.getSerialNumberOctetSizeForNewCa();

               final List<CertificatePolicy> policies = parsePolicies(caInfoDto.getPolicyId());
               for (CertificatePolicy certificatePolicy : policies) {
                   if (!OID.isValidOid(certificatePolicy.getPolicyID())) {
                       throw new ParameterException(ejbcawebbean.getText("INVALIDPOLICYOID"));                                              
                   }
               }
               // No need to add the Keyrecovery extended service here, because it is only "updated" in EditCA, and there
               // is not need to update it.
               X509CAInfo.X509CAInfoBuilder x509CAInfoBuilder = new X509CAInfo.X509CAInfoBuilder()
                       .setCaId(caid)
                       .setEncodedValidity(caInfoDto.getCaEncodedValidity())
                       .setCaToken(catoken)
                       .setDescription(caInfoDto.getDescription())
                       .setCaSerialNumberOctetSize(caSerialNumberOctetSize)
                       .setSubjectAltName(caInfoDto.getCaSubjectAltName())
                       .setPolicies(policies)
                       .setCrlPeriod(caInfoDto.getCrlPeriod())
                       .setCrlIssueInterval(caInfoDto.getCrlIssueInterval())
                       .setCrlOverlapTime(caInfoDto.getcrlOverlapTime())
                       .setDeltaCrlPeriod(caInfoDto.getDeltaCrlPeriod())
                       .setGenerateCrlUponRevocation(caInfoDto.isGenerateCrlUponRevocation())
                       .setAllowChangingRevocationReason(caInfoDto.isAllowChangingRevocationReason())
                       .setAllowInvalidityDate(caInfoDto.isAllowInvalidityDate())
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
					   .setDoPreProduceIndividualOcspResponses(caInfoDto.isDoPreProduceOcspResponseUponIssuanceAndRevocation())
                       .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                       .setCmpRaAuthSecret(caInfoDto.getSharedCmpRaSecret())
                       .setKeepExpiredCertsOnCRL(caInfoDto.isKeepExpiredOnCrl())
                       .setDefaultCertProfileId(caInfoDto.getDefaultCertProfileId())
                       .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                       .setUsePartitionedCrl(caInfoDto.isUsePartitionedCrl())
                       .setCrlPartitions(caInfoDto.getCrlPartitions())
                       .setMsCaCompatible(caInfoDto.isMsCaCompatible())
                       .setSuspendedCrlPartitions(caInfoDto.getSuspendedCrlPartitions())
                       .setRequestPreProcessor(caInfoDto.getRequestPreProcessor())
                       .setAlternateCertificateChains(caInfoDto.getAlternateCertificateChains());
               cainfo = x509CAInfoBuilder.buildForUpdate();
            } else if (caInfoDto.getCaType() == CAInfo.CATYPE_CVC) {
               // Info specific for CVC CA


               // Edit CVC CA data
               // A CVC CA does not have any of the external services OCSP, CMS
               final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<>();
               // Create the CAInfo to be used for either generating the whole CA or making a request
               cainfo = new CVCCAInfo(caid, caInfoDto.getCaEncodedValidity(),
                       catoken, caInfoDto.getDescription(),
                       caInfoDto.getCrlPeriod(), caInfoDto.getCrlIssueInterval(), caInfoDto.getcrlOverlapTime(), caInfoDto.getDeltaCrlPeriod(), 
                       caInfoDto.isGenerateCrlUponRevocation(), crlpublishers, keyValidators,
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
                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos();

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
            } else if (caInfoDto.getCaType() == CAInfo.CATYPE_CITS) {
                List<ExtendedCAServiceInfo> extendedCaServiceInfos = makeExtendedServicesInfos();
                CitsCaInfo.CitsCaInfoBuilder citsCaInfoBuilder = new CitsCaInfo.CitsCaInfoBuilder().setCaId(caid)
                                                                                                   .setName(caInfoDto.getCaName())
                                                                                                   .setDescription(caInfoDto.getDescription())
                                                                                                   .setEncodedValidity(caInfoDto.getCaEncodedValidity())
                                                                                                   .setCaType(caInfoDto.getCaType())
                                                                                                   .setSignedBy(caInfoDto.getSignedBy())
                                                                                                   .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                                                                                                   .setUpdateTime(new Date())
                                                                                                   .setExpireTime(null)
                                                                                                   .setCertificateChain(null)
                                                                                                   .setCaToken(catoken)
                                                                                                   .setApprovals(new HashMap<>()) // Approvals not implement yet for citsca
                                                                                                   .setExtendedCAServiceInfos(extendedCaServiceInfos)
                                                                                                   .setValidators(keyValidators)
                                                                                                   .setFinishUser(caInfoDto.isFinishUser())
                                                                                                   .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                                                                                                   .setIncludeInHealthCheck(caInfoDto.isIncludeInHealthCheck())
                                                                                                   .setDoEnforceUniquePublicKeys(caInfoDto.isDoEnforceUniquePublickeys())
                                                                                                   .setDoEnforceKeyRenewal(caInfoDto.isDoEnforceKeyRenewal())
                                                                                                   .setDoEnforceUniqueDistinguishedName(caInfoDto.isDoEnforceUniqueDN())
                                                                                                   .setDoEnforceUniqueSubjectDNSerialnumber(caInfoDto.isDoEnforceUniqueSubjectDNSerialnumber())
                                                                                                   .setUseCertReqHistory(caInfoDto.isUseCertReqHistory())
                                                                                                   .setUseUserStorage(caInfoDto.isUseUserStorage())
                                                                                                   .setUseCertificateStorage(caInfoDto.isUseCertificateStorage())
                                                                                                   .setAcceptRevocationNonExistingEntry(caInfoDto.isAcceptRevocationsNonExistingEntry())
                                                                                                   .setDefaultCertProfileId(caInfoDto.getDefaultCertProfileId())
                                                                                                   .setUseNoConflictCertificateData(caInfoDto.isUseNoConflictCertificateData())
                                                                                                   .setCertificateId(caInfoDto.getCertificateId())
                                                                                                   .setRegion(caInfoDto.getRegion());


                cainfo = citsCaInfoBuilder.buildForUpdate();
            }
           
            cainfo.setSubjectDN(subjectDn);
            cainfo.setStatus(caInfo.getStatus());
            cainfo.setName(caInfo.getName());
            return cainfo;
        }
        return null;
	}
    
    public List<Entry<String, String>> getAvailableCryptoTokens(boolean isEditingCA)
            throws AuthorizationDeniedException {
        return getAvailableCryptoTokens(isEditingCA, false);
    }

	public List<Entry<String, String>> getAvailableCryptoTokens(boolean isEditingCA, boolean citsEligibleTokensOnly)
            throws AuthorizationDeniedException {
        final List<Entry<String, String>> availableCryptoTokens = new ArrayList<>();
        final List<CryptoTokenInfo> cryptoTokenInfos = cryptoTokenManagementSession.getCryptoTokenInfos(authenticationToken);
        
        Set<String> eccKeysForCurvePresent = new HashSet<>();
        boolean citsEligible = false;
        String keySpec;
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
                        if(citsEligibleTokensOnly) {
                            eccKeysForCurvePresent.clear();
                            citsEligible = false;
                            for(KeyPairInfo keyPairInfo: cryptoTokenKeyPairInfos) {
                                keySpec = keyPairInfo.getKeySpecification();
                                if(!keyPairInfo.getKeyAlgorithm().contains("EC")) {
                                    continue;
                                }
                                if(!eccKeysForCurvePresent.contains(keySpec)) {
                                    eccKeysForCurvePresent.add(keySpec);
                                } else {
                                    // at least one EC key of same key spec is already present
                                    citsEligible = true;
                                    break;
                                }
                            }
                        }
                        // we expect two key pairs of same curve family in EC family to be useful i.e. sign and encryption key
                        // there can be two keys with same size but different curve family
                        if(!citsEligibleTokensOnly || citsEligible) {
                            availableCryptoTokens.add(new AbstractMap.SimpleEntry<>(Integer.toString(cryptoTokenId), cryptoTokenInfo.getName()));
                        }
                    }
                } catch (CryptoTokenOfflineException ctoe) {
                    // The CryptoToken might have timed out
                }
            }
        }

        availableCryptoTokens.sort(new EntryValueComparator<>(new AsStringComparator()));
        if (!isEditingCA && !availableCryptoTokens.isEmpty()) {
            // Add a dummy placeholder option
            availableCryptoTokens.add(0, new AbstractMap.SimpleEntry<>(Integer.toString(PLACEHOLDER_CRYPTO_TOKEN_ID), ejbcawebbean.getText("PLEASE_SELECT_CRYPTO_TOKEN")));
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
	public List<String> getAvailableCryptoTokenAliases(final List<KeyPairInfo> keyPairInfos, final String caSigningAlgorithm) {
	    final List<String> aliases = new ArrayList<>();
        for (final KeyPairInfo cryptoTokenKeyPairInfo : keyPairInfos) {
            if (AlgorithmTools.getKeyAlgorithmFromSigAlg(caSigningAlgorithm).equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())) {
                aliases.add(cryptoTokenKeyPairInfo.getAlias());
            }
        }
        return aliases;
	}

    /** @return a list of key pair aliases that can be used for encryption using the supplied CA signing algorithm to derive encryption algo. */
    public List<String> getAvailableCryptoTokenEncryptionAliases(final List<KeyPairInfo> keyPairInfos, final String caSigingAlgorithm) {
        final List<String> aliases = new ArrayList<>();
        for (final KeyPairInfo cryptoTokenKeyPairInfo : keyPairInfos) {
            if (AlgorithmConstants.KEYALGORITHM_ECDSA.equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())
                    || AlgorithmConstants.KEYALGORITHM_EC.equals(cryptoTokenKeyPairInfo.getKeyAlgorithm())) {
                //Only a limited subset of EC curves are available for ECCDH
                if (AlgorithmConstants.ECCDH_PERMITTED_CURVES.contains(cryptoTokenKeyPairInfo.getKeySpecification())) {
                    aliases.add(cryptoTokenKeyPairInfo.getAlias());
                }
            } else if (cryptoTokenKeyPairInfo.getKeyAlgorithm().equals(AlgorithmConstants.KEYALGORITHM_RSA)) {
                //Or in case of RSA
                aliases.add(cryptoTokenKeyPairInfo.getAlias());
            }
            // Dilithium and Falcon can only sign, so skip the PQ algorithms
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
	    if ((caInfoStatus != CAConstants.CA_EXTERNAL
            && caInfo.getCAType()!=CAInfo.CATYPE_CITS)
            && caInfoStatus != CAConstants.CA_WAITING_CERTIFICATE_RESPONSE
            && caInfo.getCAType() != CAInfo.CATYPE_PROXY) {
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

    public boolean createAuthCertSignRequest(int caid, byte[] request) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        if (request != null) {
            byte[] signedreq = caadminsession.createAuthCertSignRequest(authenticationToken, caid, request);
            saveRequestData(signedreq);
            return true;
        }
        return false;
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

    public boolean isCaTypeCits() {
        return cainfo.getCAType()==CAInfo.CATYPE_CITS;
    }
    
    public String getExpiryTime(Date expireTime) {
        return ejbcawebbean.formatAsISO8601(expireTime);
    }

    private ProxyCaInfo.ProxyCaInfoBuilder createProxyCaInfoBuilder(CaInfoDto ca) {
        List<MutablePair<String, String>> headerPairs = ca.getHeaders().stream().map(triple -> new MutablePair<String, String>(triple.getMiddle(), triple.getRight())).collect(Collectors.toList());
        ProxyCaInfo.ProxyCaInfoBuilder proxyCaInfoBuilder = new ProxyCaInfo.ProxyCaInfoBuilder()
            .setName(ca.getCaName())
            .setStatus(CAConstants.CA_ACTIVE)
            .setDescription(ca.getDescription())
            .setSubjectDn(ca.getCaSubjectDN())
            .setEnrollWithCsrUrl(ca.getUpstreamUrl())
            .setHeaders(headerPairs)
            .setUsername(ca.getUsername())
            .setPassword(ca.getPassword())
            .setCa(ca.getUpstreamCa())
            .setTemplate(ca.getUpstreamTemplate())
            .setSans(ca.getSansJson());
        return proxyCaInfoBuilder;
    }

}
