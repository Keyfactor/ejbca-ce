
package org.ejbca.core.protocol.ws.client.gen;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the org.ejbca.core.protocol.ws.client.gen package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _ExistsHardTokenResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "existsHardTokenResponse");
    private final static QName _RevokeCertBackdated_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeCertBackdated");
    private final static QName _AuthorizationDeniedException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "AuthorizationDeniedException");
    private final static QName _GetHardTokenDatas_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getHardTokenDatas");
    private final static QName _GetAvailableCAsInProfile_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAvailableCAsInProfile");
    private final static QName _CryptoTokenOfflineException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "CryptoTokenOfflineException");
    private final static QName _RevokeUser_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeUser");
    private final static QName _RevokeCertResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeCertResponse");
    private final static QName _IsApprovedResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "isApprovedResponse");
    private final static QName _RevokeTokenResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeTokenResponse");
    private final static QName _GetAvailableCAsResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAvailableCAsResponse");
    private final static QName _UserDataSourceException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "UserDataSourceException");
    private final static QName _WaitingForApprovalException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "WaitingForApprovalException");
    private final static QName _Pkcs12Req_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs12Req");
    private final static QName _SpkacRequestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "spkacRequestResponse");
    private final static QName _RepublishCertificate_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "republishCertificate");
    private final static QName _DeleteUserDataFromSourceResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "deleteUserDataFromSourceResponse");
    private final static QName _GetAuthorizedEndEntityProfilesResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAuthorizedEndEntityProfilesResponse");
    private final static QName _CesecoreException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "CesecoreException");
    private final static QName _FetchUserDataResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "fetchUserDataResponse");
    private final static QName _FindUser_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findUser");
    private final static QName _GetEjbcaVersion_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getEjbcaVersion");
    private final static QName _GenTokenCertificatesResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "genTokenCertificatesResponse");
    private final static QName _FindCerts_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findCerts");
    private final static QName _FindCertsResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findCertsResponse");
    private final static QName _CreateCRLResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "createCRLResponse");
    private final static QName _PublisherException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "PublisherException");
    private final static QName _RepublishCertificateResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "republishCertificateResponse");
    private final static QName _HardTokenDoesntExistsException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "HardTokenDoesntExistsException");
    private final static QName _RevokeCertBackdatedResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeCertBackdatedResponse");
    private final static QName _FindUserResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findUserResponse");
    private final static QName _ApprovalException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "ApprovalException");
    private final static QName _GetLastCertChainResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getLastCertChainResponse");
    private final static QName _UserDoesntFullfillEndEntityProfile_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "UserDoesntFullfillEndEntityProfile");
    private final static QName _ApprovalRequestExpiredException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "ApprovalRequestExpiredException");
    private final static QName _GetPublisherQueueLength_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getPublisherQueueLength");
    private final static QName _SpkacRequest_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "spkacRequest");
    private final static QName _HardTokenExistsException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "HardTokenExistsException");
    private final static QName _GetLastCertChain_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getLastCertChain");
    private final static QName _CaCertResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "caCertResponse");
    private final static QName _CheckRevokationStatusResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "checkRevokationStatusResponse");
    private final static QName _RevokeUserResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeUserResponse");
    private final static QName _CrmfRequestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "crmfRequestResponse");
    private final static QName _SoftTokenRequestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "softTokenRequestResponse");
    private final static QName _GetAvailableCertificateProfilesResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAvailableCertificateProfilesResponse");
    private final static QName _EditUserResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "editUserResponse");
    private final static QName _GetAvailableCAsInProfileResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAvailableCAsInProfileResponse");
    private final static QName _NotFoundException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "NotFoundException");
    private final static QName _MultipleMatchException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "MultipleMatchException");
    private final static QName _GetAuthorizedEndEntityProfiles_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAuthorizedEndEntityProfiles");
    private final static QName _KeyRecoverNewestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "keyRecoverNewestResponse");
    private final static QName _CheckRevokationStatus_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "checkRevokationStatus");
    private final static QName _Pkcs10RequestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs10RequestResponse");
    private final static QName _IllegalQueryException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "IllegalQueryException");
    private final static QName _CustomLog_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "customLog");
    private final static QName _KeyRecoverNewest_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "keyRecoverNewest");
    private final static QName _GetHardTokenData_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getHardTokenData");
    private final static QName _CertificateRequest_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "certificateRequest");
    private final static QName _CvcRequestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "cvcRequestResponse");
    private final static QName _Pkcs12ReqResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs12ReqResponse");
    private final static QName _ExistsHardToken_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "existsHardToken");
    private final static QName _RevokeToken_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeToken");
    private final static QName _SoftTokenRequest_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "softTokenRequest");
    private final static QName _CrmfRequest_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "crmfRequest");
    private final static QName _GetHardTokenDatasResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getHardTokenDatasResponse");
    private final static QName _CertificateRequestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "certificateRequestResponse");
    private final static QName _SignRequestException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "SignRequestException");
    private final static QName _GetCertificateResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getCertificateResponse");
    private final static QName _GetAvailableCertificateProfiles_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAvailableCertificateProfiles");
    private final static QName _IsAuthorizedResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "isAuthorizedResponse");
    private final static QName _RevokeBackDateNotAllowedForProfileException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "RevokeBackDateNotAllowedForProfileException");
    private final static QName _AlreadyRevokedException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "AlreadyRevokedException");
    private final static QName _CvcRequest_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "cvcRequest");
    private final static QName _DateNotValidException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "DateNotValidException");
    private final static QName _CertificateExpiredException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "CertificateExpiredException");
    private final static QName _CaRenewCertRequest_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "caRenewCertRequest");
    private final static QName _IsAuthorized_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "isAuthorized");
    private final static QName _GetPublisherQueueLengthResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getPublisherQueueLengthResponse");
    private final static QName _GetHardTokenDataResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getHardTokenDataResponse");
    private final static QName _GenTokenCertificates_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "genTokenCertificates");
    private final static QName _Pkcs10Request_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs10Request");
    private final static QName _GetCertificate_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getCertificate");
    private final static QName _IsApproved_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "isApproved");
    private final static QName _GetAvailableCAs_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getAvailableCAs");
    private final static QName _EditUser_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "editUser");
    private final static QName _DeleteUserDataFromSource_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "deleteUserDataFromSource");
    private final static QName _CADoesntExistsException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "CADoesntExistsException");
    private final static QName _GetLastCAChainResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getLastCAChainResponse");
    private final static QName _CustomLogResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "customLogResponse");
    private final static QName _CaRenewCertRequestResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "caRenewCertRequestResponse");
    private final static QName _EjbcaException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaException");
    private final static QName _GetLastCAChain_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getLastCAChain");
    private final static QName _ApprovalRequestExecutionException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "ApprovalRequestExecutionException");
    private final static QName _RevokeCert_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeCert");
    private final static QName _FetchUserData_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "fetchUserData");
    private final static QName _GetEjbcaVersionResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "getEjbcaVersionResponse");
    private final static QName _CaCertResponseResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "caCertResponseResponse");
    private final static QName _CAOfflineException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "CAOfflineException");
    private final static QName _CreateCRL_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "createCRL");
    private final static QName _CaRenewCertRequestResponseReturn_QNAME = new QName("", "return");
    private final static QName _CaCertResponseArg1_QNAME = new QName("", "arg1");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.ejbca.core.protocol.ws.client.gen
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link GetAvailableCertificateProfiles }
     * 
     */
    public GetAvailableCertificateProfiles createGetAvailableCertificateProfiles() {
        return new GetAvailableCertificateProfiles();
    }
    
    /**
     * Create an instance of {@link GetCertificate }
     * 
     */
    public GetCertificate createGetCertificate() {
        return new GetCertificate();
    }

    /**
     * Create an instance of {@link CaCertResponse }
     * 
     */
    public CaCertResponse createCaCertResponse() {
        return new CaCertResponse();
    }

    /**
     * Create an instance of {@link RevokeUserResponse }
     * 
     */
    public RevokeUserResponse createRevokeUserResponse() {
        return new RevokeUserResponse();
    }

    /**
     * Create an instance of {@link GetPublisherQueueLength }
     * 
     */
    public GetPublisherQueueLength createGetPublisherQueueLength() {
        return new GetPublisherQueueLength();
    }

    /**
     * Create an instance of {@link RevokeTokenResponse }
     * 
     */
    public RevokeTokenResponse createRevokeTokenResponse() {
        return new RevokeTokenResponse();
    }

    /**
     * Create an instance of {@link WaitingForApprovalException }
     * 
     */
    public WaitingForApprovalException createWaitingForApprovalException() {
        return new WaitingForApprovalException();
    }

    /**
     * Create an instance of {@link CAOfflineException }
     * 
     */
    public CAOfflineException createCAOfflineException() {
        return new CAOfflineException();
    }

    /**
     * Create an instance of {@link CrmfRequestResponse }
     * 
     */
    public CrmfRequestResponse createCrmfRequestResponse() {
        return new CrmfRequestResponse();
    }

    /**
     * Create an instance of {@link GetHardTokenDatas }
     * 
     */
    public GetHardTokenDatas createGetHardTokenDatas() {
        return new GetHardTokenDatas();
    }

    /**
     * Create an instance of {@link UserDataSourceException }
     * 
     */
    public UserDataSourceException createUserDataSourceException() {
        return new UserDataSourceException();
    }

    /**
     * Create an instance of {@link UserDoesntFullfillEndEntityProfile }
     * 
     */
    public UserDoesntFullfillEndEntityProfile createUserDoesntFullfillEndEntityProfile() {
        return new UserDoesntFullfillEndEntityProfile();
    }

    /**
     * Create an instance of {@link GenTokenCertificates }
     * 
     */
    public GenTokenCertificates createGenTokenCertificates() {
        return new GenTokenCertificates();
    }

    /**
     * Create an instance of {@link HardTokenExistsException }
     * 
     */
    public HardTokenExistsException createHardTokenExistsException() {
        return new HardTokenExistsException();
    }

    /**
     * Create an instance of {@link FindUser }
     * 
     */
    public FindUser createFindUser() {
        return new FindUser();
    }

    /**
     * Create an instance of {@link ApprovalRequestExecutionException }
     * 
     */
    public ApprovalRequestExecutionException createApprovalRequestExecutionException() {
        return new ApprovalRequestExecutionException();
    }

    /**
     * Create an instance of {@link RevokeBackDateNotAllowedForProfileException }
     * 
     */
    public RevokeBackDateNotAllowedForProfileException createRevokeBackDateNotAllowedForProfileException() {
        return new RevokeBackDateNotAllowedForProfileException();
    }

    /**
     * Create an instance of {@link RevokeToken }
     * 
     */
    public RevokeToken createRevokeToken() {
        return new RevokeToken();
    }

    /**
     * Create an instance of {@link Pkcs10RequestResponse }
     * 
     */
    public Pkcs10RequestResponse createPkcs10RequestResponse() {
        return new Pkcs10RequestResponse();
    }

    /**
     * Create an instance of {@link RevokeCertResponse }
     * 
     */
    public RevokeCertResponse createRevokeCertResponse() {
        return new RevokeCertResponse();
    }

    /**
     * Create an instance of {@link CryptoTokenOfflineException }
     * 
     */
    public CryptoTokenOfflineException createCryptoTokenOfflineException() {
        return new CryptoTokenOfflineException();
    }

    /**
     * Create an instance of {@link GetLastCertChain }
     * 
     */
    public GetLastCertChain createGetLastCertChain() {
        return new GetLastCertChain();
    }

    /**
     * Create an instance of {@link GetEjbcaVersionResponse }
     * 
     */
    public GetEjbcaVersionResponse createGetEjbcaVersionResponse() {
        return new GetEjbcaVersionResponse();
    }

    /**
     * Create an instance of {@link AlreadyRevokedException }
     * 
     */
    public AlreadyRevokedException createAlreadyRevokedException() {
        return new AlreadyRevokedException();
    }

    /**
     * Create an instance of {@link Pkcs12Req }
     * 
     */
    public Pkcs12Req createPkcs12Req() {
        return new Pkcs12Req();
    }

    /**
     * Create an instance of {@link RepublishCertificateResponse }
     * 
     */
    public RepublishCertificateResponse createRepublishCertificateResponse() {
        return new RepublishCertificateResponse();
    }

    /**
     * Create an instance of {@link UserMatch }
     * 
     */
    public UserMatch createUserMatch() {
        return new UserMatch();
    }

    /**
     * Create an instance of {@link GetEjbcaVersion }
     * 
     */
    public GetEjbcaVersion createGetEjbcaVersion() {
        return new GetEjbcaVersion();
    }

    /**
     * Create an instance of {@link Certificate }
     * 
     */
    public Certificate createCertificate() {
        return new Certificate();
    }

    /**
     * Create an instance of {@link FetchUserData }
     * 
     */
    public FetchUserData createFetchUserData() {
        return new FetchUserData();
    }

    /**
     * Create an instance of {@link EjbcaException }
     * 
     */
    public EjbcaException createEjbcaException() {
        return new EjbcaException();
    }

    /**
     * Create an instance of {@link EditUser }
     * 
     */
    public EditUser createEditUser() {
        return new EditUser();
    }

    /**
     * Create an instance of {@link CustomLogResponse }
     * 
     */
    public CustomLogResponse createCustomLogResponse() {
        return new CustomLogResponse();
    }

    /**
     * Create an instance of {@link PinDataWS }
     * 
     */
    public PinDataWS createPinDataWS() {
        return new PinDataWS();
    }

    /**
     * Create an instance of {@link FetchUserDataResponse }
     * 
     */
    public FetchUserDataResponse createFetchUserDataResponse() {
        return new FetchUserDataResponse();
    }

    /**
     * Create an instance of {@link FindUserResponse }
     * 
     */
    public FindUserResponse createFindUserResponse() {
        return new FindUserResponse();
    }

    /**
     * Create an instance of {@link CaRenewCertRequest }
     * 
     */
    public CaRenewCertRequest createCaRenewCertRequest() {
        return new CaRenewCertRequest();
    }

    /**
     * Create an instance of {@link GetAvailableCAs }
     * 
     */
    public GetAvailableCAs createGetAvailableCAs() {
        return new GetAvailableCAs();
    }

    /**
     * Create an instance of {@link DateNotValidException }
     * 
     */
    public DateNotValidException createDateNotValidException() {
        return new DateNotValidException();
    }

    /**
     * Create an instance of {@link UserDataSourceVOWS }
     * 
     */
    public UserDataSourceVOWS createUserDataSourceVOWS() {
        return new UserDataSourceVOWS();
    }

    /**
     * Create an instance of {@link GetHardTokenDatasResponse }
     * 
     */
    public GetHardTokenDatasResponse createGetHardTokenDatasResponse() {
        return new GetHardTokenDatasResponse();
    }

    /**
     * Create an instance of {@link CertificateResponse }
     * 
     */
    public CertificateResponse createCertificateResponse() {
        return new CertificateResponse();
    }

    /**
     * Create an instance of {@link HardTokenDataWS }
     * 
     */
    public HardTokenDataWS createHardTokenDataWS() {
        return new HardTokenDataWS();
    }

    /**
     * Create an instance of {@link KeyRecoverNewestResponse }
     * 
     */
    public KeyRecoverNewestResponse createKeyRecoverNewestResponse() {
        return new KeyRecoverNewestResponse();
    }

    /**
     * Create an instance of {@link CesecoreException }
     * 
     */
    public CesecoreException createCesecoreException() {
        return new CesecoreException();
    }

    /**
     * Create an instance of {@link FindCertsResponse }
     * 
     */
    public FindCertsResponse createFindCertsResponse() {
        return new FindCertsResponse();
    }

    /**
     * Create an instance of {@link CustomLog }
     * 
     */
    public CustomLog createCustomLog() {
        return new CustomLog();
    }

    /**
     * Create an instance of {@link GetAvailableCertificateProfilesResponse }
     * 
     */
    public GetAvailableCertificateProfilesResponse createGetAvailableCertificateProfilesResponse() {
        return new GetAvailableCertificateProfilesResponse();
    }

    /**
     * Create an instance of {@link RevokeCertBackdatedResponse }
     * 
     */
    public RevokeCertBackdatedResponse createRevokeCertBackdatedResponse() {
        return new RevokeCertBackdatedResponse();
    }

    /**
     * Create an instance of {@link CADoesntExistsException }
     * 
     */
    public CADoesntExistsException createCADoesntExistsException() {
        return new CADoesntExistsException();
    }

    /**
     * Create an instance of {@link RepublishCertificate }
     * 
     */
    public RepublishCertificate createRepublishCertificate() {
        return new RepublishCertificate();
    }

    /**
     * Create an instance of {@link PublisherException }
     * 
     */
    public PublisherException createPublisherException() {
        return new PublisherException();
    }

    /**
     * Create an instance of {@link CreateCRLResponse }
     * 
     */
    public CreateCRLResponse createCreateCRLResponse() {
        return new CreateCRLResponse();
    }

    /**
     * Create an instance of {@link CvcRequestResponse }
     * 
     */
    public CvcRequestResponse createCvcRequestResponse() {
        return new CvcRequestResponse();
    }

    /**
     * Create an instance of {@link KeyRecoverNewest }
     * 
     */
    public KeyRecoverNewest createKeyRecoverNewest() {
        return new KeyRecoverNewest();
    }

    /**
     * Create an instance of {@link GenTokenCertificatesResponse }
     * 
     */
    public GenTokenCertificatesResponse createGenTokenCertificatesResponse() {
        return new GenTokenCertificatesResponse();
    }

    /**
     * Create an instance of {@link ExtendedInformationWS }
     * 
     */
    public ExtendedInformationWS createExtendedInformationWS() {
        return new ExtendedInformationWS();
    }

    /**
     * Create an instance of {@link CheckRevokationStatusResponse }
     * 
     */
    public CheckRevokationStatusResponse createCheckRevokationStatusResponse() {
        return new CheckRevokationStatusResponse();
    }

    /**
     * Create an instance of {@link MultipleMatchException }
     * 
     */
    public MultipleMatchException createMultipleMatchException() {
        return new MultipleMatchException();
    }

    /**
     * Create an instance of {@link EditUserResponse }
     * 
     */
    public EditUserResponse createEditUserResponse() {
        return new EditUserResponse();
    }

    /**
     * Create an instance of {@link IllegalQueryException }
     * 
     */
    public IllegalQueryException createIllegalQueryException() {
        return new IllegalQueryException();
    }

    /**
     * Create an instance of {@link Pkcs12ReqResponse }
     * 
     */
    public Pkcs12ReqResponse createPkcs12ReqResponse() {
        return new Pkcs12ReqResponse();
    }

    /**
     * Create an instance of {@link CvcRequest }
     * 
     */
    public CvcRequest createCvcRequest() {
        return new CvcRequest();
    }

    /**
     * Create an instance of {@link CaCertResponseResponse }
     * 
     */
    public CaCertResponseResponse createCaCertResponseResponse() {
        return new CaCertResponseResponse();
    }

    /**
     * Create an instance of {@link RevokeUser }
     * 
     */
    public RevokeUser createRevokeUser() {
        return new RevokeUser();
    }

    /**
     * Create an instance of {@link IsAuthorized }
     * 
     */
    public IsAuthorized createIsAuthorized() {
        return new IsAuthorized();
    }

    /**
     * Create an instance of {@link GetCertificateResponse }
     * 
     */
    public GetCertificateResponse createGetCertificateResponse() {
        return new GetCertificateResponse();
    }

    /**
     * Create an instance of {@link GetLastCertChainResponse }
     * 
     */
    public GetLastCertChainResponse createGetLastCertChainResponse() {
        return new GetLastCertChainResponse();
    }

    /**
     * Create an instance of {@link RevokeCert }
     * 
     */
    public RevokeCert createRevokeCert() {
        return new RevokeCert();
    }

    /**
     * Create an instance of {@link IsApprovedResponse }
     * 
     */
    public IsApprovedResponse createIsApprovedResponse() {
        return new IsApprovedResponse();
    }

    /**
     * Create an instance of {@link ApprovalException }
     * 
     */
    public ApprovalException createApprovalException() {
        return new ApprovalException();
    }

    /**
     * Create an instance of {@link DeleteUserDataFromSource }
     * 
     */
    public DeleteUserDataFromSource createDeleteUserDataFromSource() {
        return new DeleteUserDataFromSource();
    }

    /**
     * Create an instance of {@link RevokeStatus }
     * 
     */
    public RevokeStatus createRevokeStatus() {
        return new RevokeStatus();
    }

    /**
     * Create an instance of {@link KeyStore }
     * 
     */
    public KeyStore createKeyStore() {
        return new KeyStore();
    }

    /**
     * Create an instance of {@link CaRenewCertRequestResponse }
     * 
     */
    public CaRenewCertRequestResponse createCaRenewCertRequestResponse() {
        return new CaRenewCertRequestResponse();
    }

    /**
     * Create an instance of {@link UserDataVOWS }
     * 
     */
    public UserDataVOWS createUserDataVOWS() {
        return new UserDataVOWS();
    }

    /**
     * Create an instance of {@link DeleteUserDataFromSourceResponse }
     * 
     */
    public DeleteUserDataFromSourceResponse createDeleteUserDataFromSourceResponse() {
        return new DeleteUserDataFromSourceResponse();
    }

    /**
     * Create an instance of {@link IsAuthorizedResponse }
     * 
     */
    public IsAuthorizedResponse createIsAuthorizedResponse() {
        return new IsAuthorizedResponse();
    }

    /**
     * Create an instance of {@link GetHardTokenDataResponse }
     * 
     */
    public GetHardTokenDataResponse createGetHardTokenDataResponse() {
        return new GetHardTokenDataResponse();
    }

    /**
     * Create an instance of {@link ExistsHardTokenResponse }
     * 
     */
    public ExistsHardTokenResponse createExistsHardTokenResponse() {
        return new ExistsHardTokenResponse();
    }

    /**
     * Create an instance of {@link NotFoundException }
     * 
     */
    public NotFoundException createNotFoundException() {
        return new NotFoundException();
    }

    /**
     * Create an instance of {@link CertificateExpiredException }
     * 
     */
    public CertificateExpiredException createCertificateExpiredException() {
        return new CertificateExpiredException();
    }

    /**
     * Create an instance of {@link CertificateRequest }
     * 
     */
    public CertificateRequest createCertificateRequest() {
        return new CertificateRequest();
    }

    /**
     * Create an instance of {@link TokenCertificateRequestWS }
     * 
     */
    public TokenCertificateRequestWS createTokenCertificateRequestWS() {
        return new TokenCertificateRequestWS();
    }

    /**
     * Create an instance of {@link GetAvailableCAsInProfile }
     * 
     */
    public GetAvailableCAsInProfile createGetAvailableCAsInProfile() {
        return new GetAvailableCAsInProfile();
    }

    /**
     * Create an instance of {@link GetAvailableCAsResponse }
     * 
     */
    public GetAvailableCAsResponse createGetAvailableCAsResponse() {
        return new GetAvailableCAsResponse();
    }

    /**
     * Create an instance of {@link SoftTokenRequest }
     * 
     */
    public SoftTokenRequest createSoftTokenRequest() {
        return new SoftTokenRequest();
    }

    /**
     * Create an instance of {@link Pkcs10Request }
     * 
     */
    public Pkcs10Request createPkcs10Request() {
        return new Pkcs10Request();
    }

    /**
     * Create an instance of {@link SpkacRequestResponse }
     * 
     */
    public SpkacRequestResponse createSpkacRequestResponse() {
        return new SpkacRequestResponse();
    }

    /**
     * Create an instance of {@link ExistsHardToken }
     * 
     */
    public ExistsHardToken createExistsHardToken() {
        return new ExistsHardToken();
    }

    /**
     * Create an instance of {@link CheckRevokationStatus }
     * 
     */
    public CheckRevokationStatus createCheckRevokationStatus() {
        return new CheckRevokationStatus();
    }

    /**
     * Create an instance of {@link HardTokenDoesntExistsException }
     * 
     */
    public HardTokenDoesntExistsException createHardTokenDoesntExistsException() {
        return new HardTokenDoesntExistsException();
    }

    /**
     * Create an instance of {@link GetLastCAChain }
     * 
     */
    public GetLastCAChain createGetLastCAChain() {
        return new GetLastCAChain();
    }

    /**
     * Create an instance of {@link SpkacRequest }
     * 
     */
    public SpkacRequest createSpkacRequest() {
        return new SpkacRequest();
    }

    /**
     * Create an instance of {@link TokenCertificateResponseWS }
     * 
     */
    public TokenCertificateResponseWS createTokenCertificateResponseWS() {
        return new TokenCertificateResponseWS();
    }

    /**
     * Create an instance of {@link SoftTokenRequestResponse }
     * 
     */
    public SoftTokenRequestResponse createSoftTokenRequestResponse() {
        return new SoftTokenRequestResponse();
    }

    /**
     * Create an instance of {@link CertificateRequestResponse }
     * 
     */
    public CertificateRequestResponse createCertificateRequestResponse() {
        return new CertificateRequestResponse();
    }

    /**
     * Create an instance of {@link ApprovalRequestExpiredException }
     * 
     */
    public ApprovalRequestExpiredException createApprovalRequestExpiredException() {
        return new ApprovalRequestExpiredException();
    }

    /**
     * Create an instance of {@link NameAndId }
     * 
     */
    public NameAndId createNameAndId() {
        return new NameAndId();
    }

    /**
     * Create an instance of {@link GetAvailableCAsInProfileResponse }
     * 
     */
    public GetAvailableCAsInProfileResponse createGetAvailableCAsInProfileResponse() {
        return new GetAvailableCAsInProfileResponse();
    }

    /**
     * Create an instance of {@link ErrorCode }
     * 
     */
    public ErrorCode createErrorCode() {
        return new ErrorCode();
    }

    /**
     * Create an instance of {@link GetAuthorizedEndEntityProfiles }
     * 
     */
    public GetAuthorizedEndEntityProfiles createGetAuthorizedEndEntityProfiles() {
        return new GetAuthorizedEndEntityProfiles();
    }

    /**
     * Create an instance of {@link AuthorizationDeniedException }
     * 
     */
    public AuthorizationDeniedException createAuthorizationDeniedException() {
        return new AuthorizationDeniedException();
    }

    /**
     * Create an instance of {@link CrmfRequest }
     * 
     */
    public CrmfRequest createCrmfRequest() {
        return new CrmfRequest();
    }

    /**
     * Create an instance of {@link GetAuthorizedEndEntityProfilesResponse }
     * 
     */
    public GetAuthorizedEndEntityProfilesResponse createGetAuthorizedEndEntityProfilesResponse() {
        return new GetAuthorizedEndEntityProfilesResponse();
    }

    /**
     * Create an instance of {@link IsApproved }
     * 
     */
    public IsApproved createIsApproved() {
        return new IsApproved();
    }

    /**
     * Create an instance of {@link GetLastCAChainResponse }
     * 
     */
    public GetLastCAChainResponse createGetLastCAChainResponse() {
        return new GetLastCAChainResponse();
    }

    /**
     * Create an instance of {@link GetHardTokenData }
     * 
     */
    public GetHardTokenData createGetHardTokenData() {
        return new GetHardTokenData();
    }

    /**
     * Create an instance of {@link CreateCRL }
     * 
     */
    public CreateCRL createCreateCRL() {
        return new CreateCRL();
    }

    /**
     * Create an instance of {@link RevokeCertBackdated }
     * 
     */
    public RevokeCertBackdated createRevokeCertBackdated() {
        return new RevokeCertBackdated();
    }

    /**
     * Create an instance of {@link SignRequestException }
     * 
     */
    public SignRequestException createSignRequestException() {
        return new SignRequestException();
    }

    /**
     * Create an instance of {@link FindCerts }
     * 
     */
    public FindCerts createFindCerts() {
        return new FindCerts();
    }

    /**
     * Create an instance of {@link GetPublisherQueueLengthResponse }
     * 
     */
    public GetPublisherQueueLengthResponse createGetPublisherQueueLengthResponse() {
        return new GetPublisherQueueLengthResponse();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ExistsHardTokenResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "existsHardTokenResponse")
    public JAXBElement<ExistsHardTokenResponse> createExistsHardTokenResponse(ExistsHardTokenResponse value) {
        return new JAXBElement<ExistsHardTokenResponse>(_ExistsHardTokenResponse_QNAME, ExistsHardTokenResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeCertBackdated }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeCertBackdated")
    public JAXBElement<RevokeCertBackdated> createRevokeCertBackdated(RevokeCertBackdated value) {
        return new JAXBElement<RevokeCertBackdated>(_RevokeCertBackdated_QNAME, RevokeCertBackdated.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link AuthorizationDeniedException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "AuthorizationDeniedException")
    public JAXBElement<AuthorizationDeniedException> createAuthorizationDeniedException(AuthorizationDeniedException value) {
        return new JAXBElement<AuthorizationDeniedException>(_AuthorizationDeniedException_QNAME, AuthorizationDeniedException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetHardTokenDatas }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getHardTokenDatas")
    public JAXBElement<GetHardTokenDatas> createGetHardTokenDatas(GetHardTokenDatas value) {
        return new JAXBElement<GetHardTokenDatas>(_GetHardTokenDatas_QNAME, GetHardTokenDatas.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAvailableCAsInProfile }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAvailableCAsInProfile")
    public JAXBElement<GetAvailableCAsInProfile> createGetAvailableCAsInProfile(GetAvailableCAsInProfile value) {
        return new JAXBElement<GetAvailableCAsInProfile>(_GetAvailableCAsInProfile_QNAME, GetAvailableCAsInProfile.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CryptoTokenOfflineException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "CryptoTokenOfflineException")
    public JAXBElement<CryptoTokenOfflineException> createCryptoTokenOfflineException(CryptoTokenOfflineException value) {
        return new JAXBElement<CryptoTokenOfflineException>(_CryptoTokenOfflineException_QNAME, CryptoTokenOfflineException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeUser }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeUser")
    public JAXBElement<RevokeUser> createRevokeUser(RevokeUser value) {
        return new JAXBElement<RevokeUser>(_RevokeUser_QNAME, RevokeUser.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeCertResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeCertResponse")
    public JAXBElement<RevokeCertResponse> createRevokeCertResponse(RevokeCertResponse value) {
        return new JAXBElement<RevokeCertResponse>(_RevokeCertResponse_QNAME, RevokeCertResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link IsApprovedResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "isApprovedResponse")
    public JAXBElement<IsApprovedResponse> createIsApprovedResponse(IsApprovedResponse value) {
        return new JAXBElement<IsApprovedResponse>(_IsApprovedResponse_QNAME, IsApprovedResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeTokenResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeTokenResponse")
    public JAXBElement<RevokeTokenResponse> createRevokeTokenResponse(RevokeTokenResponse value) {
        return new JAXBElement<RevokeTokenResponse>(_RevokeTokenResponse_QNAME, RevokeTokenResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAvailableCAsResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAvailableCAsResponse")
    public JAXBElement<GetAvailableCAsResponse> createGetAvailableCAsResponse(GetAvailableCAsResponse value) {
        return new JAXBElement<GetAvailableCAsResponse>(_GetAvailableCAsResponse_QNAME, GetAvailableCAsResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link UserDataSourceException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "UserDataSourceException")
    public JAXBElement<UserDataSourceException> createUserDataSourceException(UserDataSourceException value) {
        return new JAXBElement<UserDataSourceException>(_UserDataSourceException_QNAME, UserDataSourceException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link WaitingForApprovalException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "WaitingForApprovalException")
    public JAXBElement<WaitingForApprovalException> createWaitingForApprovalException(WaitingForApprovalException value) {
        return new JAXBElement<WaitingForApprovalException>(_WaitingForApprovalException_QNAME, WaitingForApprovalException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs12Req }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs12Req")
    public JAXBElement<Pkcs12Req> createPkcs12Req(Pkcs12Req value) {
        return new JAXBElement<Pkcs12Req>(_Pkcs12Req_QNAME, Pkcs12Req.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link SpkacRequestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "spkacRequestResponse")
    public JAXBElement<SpkacRequestResponse> createSpkacRequestResponse(SpkacRequestResponse value) {
        return new JAXBElement<SpkacRequestResponse>(_SpkacRequestResponse_QNAME, SpkacRequestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RepublishCertificate }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "republishCertificate")
    public JAXBElement<RepublishCertificate> createRepublishCertificate(RepublishCertificate value) {
        return new JAXBElement<RepublishCertificate>(_RepublishCertificate_QNAME, RepublishCertificate.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DeleteUserDataFromSourceResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "deleteUserDataFromSourceResponse")
    public JAXBElement<DeleteUserDataFromSourceResponse> createDeleteUserDataFromSourceResponse(DeleteUserDataFromSourceResponse value) {
        return new JAXBElement<DeleteUserDataFromSourceResponse>(_DeleteUserDataFromSourceResponse_QNAME, DeleteUserDataFromSourceResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAuthorizedEndEntityProfilesResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAuthorizedEndEntityProfilesResponse")
    public JAXBElement<GetAuthorizedEndEntityProfilesResponse> createGetAuthorizedEndEntityProfilesResponse(GetAuthorizedEndEntityProfilesResponse value) {
        return new JAXBElement<GetAuthorizedEndEntityProfilesResponse>(_GetAuthorizedEndEntityProfilesResponse_QNAME, GetAuthorizedEndEntityProfilesResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CesecoreException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "CesecoreException")
    public JAXBElement<CesecoreException> createCesecoreException(CesecoreException value) {
        return new JAXBElement<CesecoreException>(_CesecoreException_QNAME, CesecoreException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link FetchUserDataResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "fetchUserDataResponse")
    public JAXBElement<FetchUserDataResponse> createFetchUserDataResponse(FetchUserDataResponse value) {
        return new JAXBElement<FetchUserDataResponse>(_FetchUserDataResponse_QNAME, FetchUserDataResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link FindUser }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "findUser")
    public JAXBElement<FindUser> createFindUser(FindUser value) {
        return new JAXBElement<FindUser>(_FindUser_QNAME, FindUser.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetEjbcaVersion }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getEjbcaVersion")
    public JAXBElement<GetEjbcaVersion> createGetEjbcaVersion(GetEjbcaVersion value) {
        return new JAXBElement<GetEjbcaVersion>(_GetEjbcaVersion_QNAME, GetEjbcaVersion.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GenTokenCertificatesResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "genTokenCertificatesResponse")
    public JAXBElement<GenTokenCertificatesResponse> createGenTokenCertificatesResponse(GenTokenCertificatesResponse value) {
        return new JAXBElement<GenTokenCertificatesResponse>(_GenTokenCertificatesResponse_QNAME, GenTokenCertificatesResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link FindCerts }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "findCerts")
    public JAXBElement<FindCerts> createFindCerts(FindCerts value) {
        return new JAXBElement<FindCerts>(_FindCerts_QNAME, FindCerts.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link FindCertsResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "findCertsResponse")
    public JAXBElement<FindCertsResponse> createFindCertsResponse(FindCertsResponse value) {
        return new JAXBElement<FindCertsResponse>(_FindCertsResponse_QNAME, FindCertsResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CreateCRLResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "createCRLResponse")
    public JAXBElement<CreateCRLResponse> createCreateCRLResponse(CreateCRLResponse value) {
        return new JAXBElement<CreateCRLResponse>(_CreateCRLResponse_QNAME, CreateCRLResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link PublisherException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "PublisherException")
    public JAXBElement<PublisherException> createPublisherException(PublisherException value) {
        return new JAXBElement<PublisherException>(_PublisherException_QNAME, PublisherException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RepublishCertificateResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "republishCertificateResponse")
    public JAXBElement<RepublishCertificateResponse> createRepublishCertificateResponse(RepublishCertificateResponse value) {
        return new JAXBElement<RepublishCertificateResponse>(_RepublishCertificateResponse_QNAME, RepublishCertificateResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link HardTokenDoesntExistsException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "HardTokenDoesntExistsException")
    public JAXBElement<HardTokenDoesntExistsException> createHardTokenDoesntExistsException(HardTokenDoesntExistsException value) {
        return new JAXBElement<HardTokenDoesntExistsException>(_HardTokenDoesntExistsException_QNAME, HardTokenDoesntExistsException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeCertBackdatedResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeCertBackdatedResponse")
    public JAXBElement<RevokeCertBackdatedResponse> createRevokeCertBackdatedResponse(RevokeCertBackdatedResponse value) {
        return new JAXBElement<RevokeCertBackdatedResponse>(_RevokeCertBackdatedResponse_QNAME, RevokeCertBackdatedResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link FindUserResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "findUserResponse")
    public JAXBElement<FindUserResponse> createFindUserResponse(FindUserResponse value) {
        return new JAXBElement<FindUserResponse>(_FindUserResponse_QNAME, FindUserResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ApprovalException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "ApprovalException")
    public JAXBElement<ApprovalException> createApprovalException(ApprovalException value) {
        return new JAXBElement<ApprovalException>(_ApprovalException_QNAME, ApprovalException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetLastCertChainResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getLastCertChainResponse")
    public JAXBElement<GetLastCertChainResponse> createGetLastCertChainResponse(GetLastCertChainResponse value) {
        return new JAXBElement<GetLastCertChainResponse>(_GetLastCertChainResponse_QNAME, GetLastCertChainResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link UserDoesntFullfillEndEntityProfile }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "UserDoesntFullfillEndEntityProfile")
    public JAXBElement<UserDoesntFullfillEndEntityProfile> createUserDoesntFullfillEndEntityProfile(UserDoesntFullfillEndEntityProfile value) {
        return new JAXBElement<UserDoesntFullfillEndEntityProfile>(_UserDoesntFullfillEndEntityProfile_QNAME, UserDoesntFullfillEndEntityProfile.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ApprovalRequestExpiredException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "ApprovalRequestExpiredException")
    public JAXBElement<ApprovalRequestExpiredException> createApprovalRequestExpiredException(ApprovalRequestExpiredException value) {
        return new JAXBElement<ApprovalRequestExpiredException>(_ApprovalRequestExpiredException_QNAME, ApprovalRequestExpiredException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetPublisherQueueLength }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getPublisherQueueLength")
    public JAXBElement<GetPublisherQueueLength> createGetPublisherQueueLength(GetPublisherQueueLength value) {
        return new JAXBElement<GetPublisherQueueLength>(_GetPublisherQueueLength_QNAME, GetPublisherQueueLength.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link SpkacRequest }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "spkacRequest")
    public JAXBElement<SpkacRequest> createSpkacRequest(SpkacRequest value) {
        return new JAXBElement<SpkacRequest>(_SpkacRequest_QNAME, SpkacRequest.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link HardTokenExistsException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "HardTokenExistsException")
    public JAXBElement<HardTokenExistsException> createHardTokenExistsException(HardTokenExistsException value) {
        return new JAXBElement<HardTokenExistsException>(_HardTokenExistsException_QNAME, HardTokenExistsException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetLastCertChain }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getLastCertChain")
    public JAXBElement<GetLastCertChain> createGetLastCertChain(GetLastCertChain value) {
        return new JAXBElement<GetLastCertChain>(_GetLastCertChain_QNAME, GetLastCertChain.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CaCertResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "caCertResponse")
    public JAXBElement<CaCertResponse> createCaCertResponse(CaCertResponse value) {
        return new JAXBElement<CaCertResponse>(_CaCertResponse_QNAME, CaCertResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CheckRevokationStatusResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "checkRevokationStatusResponse")
    public JAXBElement<CheckRevokationStatusResponse> createCheckRevokationStatusResponse(CheckRevokationStatusResponse value) {
        return new JAXBElement<CheckRevokationStatusResponse>(_CheckRevokationStatusResponse_QNAME, CheckRevokationStatusResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeUserResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeUserResponse")
    public JAXBElement<RevokeUserResponse> createRevokeUserResponse(RevokeUserResponse value) {
        return new JAXBElement<RevokeUserResponse>(_RevokeUserResponse_QNAME, RevokeUserResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CrmfRequestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "crmfRequestResponse")
    public JAXBElement<CrmfRequestResponse> createCrmfRequestResponse(CrmfRequestResponse value) {
        return new JAXBElement<CrmfRequestResponse>(_CrmfRequestResponse_QNAME, CrmfRequestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link SoftTokenRequestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "softTokenRequestResponse")
    public JAXBElement<SoftTokenRequestResponse> createSoftTokenRequestResponse(SoftTokenRequestResponse value) {
        return new JAXBElement<SoftTokenRequestResponse>(_SoftTokenRequestResponse_QNAME, SoftTokenRequestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAvailableCertificateProfilesResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAvailableCertificateProfilesResponse")
    public JAXBElement<GetAvailableCertificateProfilesResponse> createGetAvailableCertificateProfilesResponse(GetAvailableCertificateProfilesResponse value) {
        return new JAXBElement<GetAvailableCertificateProfilesResponse>(_GetAvailableCertificateProfilesResponse_QNAME, GetAvailableCertificateProfilesResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link EditUserResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "editUserResponse")
    public JAXBElement<EditUserResponse> createEditUserResponse(EditUserResponse value) {
        return new JAXBElement<EditUserResponse>(_EditUserResponse_QNAME, EditUserResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAvailableCAsInProfileResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAvailableCAsInProfileResponse")
    public JAXBElement<GetAvailableCAsInProfileResponse> createGetAvailableCAsInProfileResponse(GetAvailableCAsInProfileResponse value) {
        return new JAXBElement<GetAvailableCAsInProfileResponse>(_GetAvailableCAsInProfileResponse_QNAME, GetAvailableCAsInProfileResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link NotFoundException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "NotFoundException")
    public JAXBElement<NotFoundException> createNotFoundException(NotFoundException value) {
        return new JAXBElement<NotFoundException>(_NotFoundException_QNAME, NotFoundException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link MultipleMatchException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "MultipleMatchException")
    public JAXBElement<MultipleMatchException> createMultipleMatchException(MultipleMatchException value) {
        return new JAXBElement<MultipleMatchException>(_MultipleMatchException_QNAME, MultipleMatchException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAuthorizedEndEntityProfiles }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAuthorizedEndEntityProfiles")
    public JAXBElement<GetAuthorizedEndEntityProfiles> createGetAuthorizedEndEntityProfiles(GetAuthorizedEndEntityProfiles value) {
        return new JAXBElement<GetAuthorizedEndEntityProfiles>(_GetAuthorizedEndEntityProfiles_QNAME, GetAuthorizedEndEntityProfiles.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link KeyRecoverNewestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "keyRecoverNewestResponse")
    public JAXBElement<KeyRecoverNewestResponse> createKeyRecoverNewestResponse(KeyRecoverNewestResponse value) {
        return new JAXBElement<KeyRecoverNewestResponse>(_KeyRecoverNewestResponse_QNAME, KeyRecoverNewestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CheckRevokationStatus }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "checkRevokationStatus")
    public JAXBElement<CheckRevokationStatus> createCheckRevokationStatus(CheckRevokationStatus value) {
        return new JAXBElement<CheckRevokationStatus>(_CheckRevokationStatus_QNAME, CheckRevokationStatus.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs10RequestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs10RequestResponse")
    public JAXBElement<Pkcs10RequestResponse> createPkcs10RequestResponse(Pkcs10RequestResponse value) {
        return new JAXBElement<Pkcs10RequestResponse>(_Pkcs10RequestResponse_QNAME, Pkcs10RequestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link IllegalQueryException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "IllegalQueryException")
    public JAXBElement<IllegalQueryException> createIllegalQueryException(IllegalQueryException value) {
        return new JAXBElement<IllegalQueryException>(_IllegalQueryException_QNAME, IllegalQueryException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CustomLog }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "customLog")
    public JAXBElement<CustomLog> createCustomLog(CustomLog value) {
        return new JAXBElement<CustomLog>(_CustomLog_QNAME, CustomLog.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link KeyRecoverNewest }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "keyRecoverNewest")
    public JAXBElement<KeyRecoverNewest> createKeyRecoverNewest(KeyRecoverNewest value) {
        return new JAXBElement<KeyRecoverNewest>(_KeyRecoverNewest_QNAME, KeyRecoverNewest.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetHardTokenData }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getHardTokenData")
    public JAXBElement<GetHardTokenData> createGetHardTokenData(GetHardTokenData value) {
        return new JAXBElement<GetHardTokenData>(_GetHardTokenData_QNAME, GetHardTokenData.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CertificateRequest }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "certificateRequest")
    public JAXBElement<CertificateRequest> createCertificateRequest(CertificateRequest value) {
        return new JAXBElement<CertificateRequest>(_CertificateRequest_QNAME, CertificateRequest.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CvcRequestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "cvcRequestResponse")
    public JAXBElement<CvcRequestResponse> createCvcRequestResponse(CvcRequestResponse value) {
        return new JAXBElement<CvcRequestResponse>(_CvcRequestResponse_QNAME, CvcRequestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs12ReqResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs12ReqResponse")
    public JAXBElement<Pkcs12ReqResponse> createPkcs12ReqResponse(Pkcs12ReqResponse value) {
        return new JAXBElement<Pkcs12ReqResponse>(_Pkcs12ReqResponse_QNAME, Pkcs12ReqResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ExistsHardToken }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "existsHardToken")
    public JAXBElement<ExistsHardToken> createExistsHardToken(ExistsHardToken value) {
        return new JAXBElement<ExistsHardToken>(_ExistsHardToken_QNAME, ExistsHardToken.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeToken }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeToken")
    public JAXBElement<RevokeToken> createRevokeToken(RevokeToken value) {
        return new JAXBElement<RevokeToken>(_RevokeToken_QNAME, RevokeToken.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link SoftTokenRequest }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "softTokenRequest")
    public JAXBElement<SoftTokenRequest> createSoftTokenRequest(SoftTokenRequest value) {
        return new JAXBElement<SoftTokenRequest>(_SoftTokenRequest_QNAME, SoftTokenRequest.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CrmfRequest }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "crmfRequest")
    public JAXBElement<CrmfRequest> createCrmfRequest(CrmfRequest value) {
        return new JAXBElement<CrmfRequest>(_CrmfRequest_QNAME, CrmfRequest.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetHardTokenDatasResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getHardTokenDatasResponse")
    public JAXBElement<GetHardTokenDatasResponse> createGetHardTokenDatasResponse(GetHardTokenDatasResponse value) {
        return new JAXBElement<GetHardTokenDatasResponse>(_GetHardTokenDatasResponse_QNAME, GetHardTokenDatasResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CertificateRequestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "certificateRequestResponse")
    public JAXBElement<CertificateRequestResponse> createCertificateRequestResponse(CertificateRequestResponse value) {
        return new JAXBElement<CertificateRequestResponse>(_CertificateRequestResponse_QNAME, CertificateRequestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link SignRequestException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "SignRequestException")
    public JAXBElement<SignRequestException> createSignRequestException(SignRequestException value) {
        return new JAXBElement<SignRequestException>(_SignRequestException_QNAME, SignRequestException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetCertificateResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getCertificateResponse")
    public JAXBElement<GetCertificateResponse> createGetCertificateResponse(GetCertificateResponse value) {
        return new JAXBElement<GetCertificateResponse>(_GetCertificateResponse_QNAME, GetCertificateResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAvailableCertificateProfiles }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAvailableCertificateProfiles")
    public JAXBElement<GetAvailableCertificateProfiles> createGetAvailableCertificateProfiles(GetAvailableCertificateProfiles value) {
        return new JAXBElement<GetAvailableCertificateProfiles>(_GetAvailableCertificateProfiles_QNAME, GetAvailableCertificateProfiles.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link IsAuthorizedResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "isAuthorizedResponse")
    public JAXBElement<IsAuthorizedResponse> createIsAuthorizedResponse(IsAuthorizedResponse value) {
        return new JAXBElement<IsAuthorizedResponse>(_IsAuthorizedResponse_QNAME, IsAuthorizedResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeBackDateNotAllowedForProfileException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "RevokeBackDateNotAllowedForProfileException")
    public JAXBElement<RevokeBackDateNotAllowedForProfileException> createRevokeBackDateNotAllowedForProfileException(RevokeBackDateNotAllowedForProfileException value) {
        return new JAXBElement<RevokeBackDateNotAllowedForProfileException>(_RevokeBackDateNotAllowedForProfileException_QNAME, RevokeBackDateNotAllowedForProfileException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link AlreadyRevokedException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "AlreadyRevokedException")
    public JAXBElement<AlreadyRevokedException> createAlreadyRevokedException(AlreadyRevokedException value) {
        return new JAXBElement<AlreadyRevokedException>(_AlreadyRevokedException_QNAME, AlreadyRevokedException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CvcRequest }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "cvcRequest")
    public JAXBElement<CvcRequest> createCvcRequest(CvcRequest value) {
        return new JAXBElement<CvcRequest>(_CvcRequest_QNAME, CvcRequest.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DateNotValidException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "DateNotValidException")
    public JAXBElement<DateNotValidException> createDateNotValidException(DateNotValidException value) {
        return new JAXBElement<DateNotValidException>(_DateNotValidException_QNAME, DateNotValidException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CertificateExpiredException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "CertificateExpiredException")
    public JAXBElement<CertificateExpiredException> createCertificateExpiredException(CertificateExpiredException value) {
        return new JAXBElement<CertificateExpiredException>(_CertificateExpiredException_QNAME, CertificateExpiredException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CaRenewCertRequest }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "caRenewCertRequest")
    public JAXBElement<CaRenewCertRequest> createCaRenewCertRequest(CaRenewCertRequest value) {
        return new JAXBElement<CaRenewCertRequest>(_CaRenewCertRequest_QNAME, CaRenewCertRequest.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link IsAuthorized }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "isAuthorized")
    public JAXBElement<IsAuthorized> createIsAuthorized(IsAuthorized value) {
        return new JAXBElement<IsAuthorized>(_IsAuthorized_QNAME, IsAuthorized.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetPublisherQueueLengthResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getPublisherQueueLengthResponse")
    public JAXBElement<GetPublisherQueueLengthResponse> createGetPublisherQueueLengthResponse(GetPublisherQueueLengthResponse value) {
        return new JAXBElement<GetPublisherQueueLengthResponse>(_GetPublisherQueueLengthResponse_QNAME, GetPublisherQueueLengthResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetHardTokenDataResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getHardTokenDataResponse")
    public JAXBElement<GetHardTokenDataResponse> createGetHardTokenDataResponse(GetHardTokenDataResponse value) {
        return new JAXBElement<GetHardTokenDataResponse>(_GetHardTokenDataResponse_QNAME, GetHardTokenDataResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GenTokenCertificates }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "genTokenCertificates")
    public JAXBElement<GenTokenCertificates> createGenTokenCertificates(GenTokenCertificates value) {
        return new JAXBElement<GenTokenCertificates>(_GenTokenCertificates_QNAME, GenTokenCertificates.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs10Request }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs10Request")
    public JAXBElement<Pkcs10Request> createPkcs10Request(Pkcs10Request value) {
        return new JAXBElement<Pkcs10Request>(_Pkcs10Request_QNAME, Pkcs10Request.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetCertificate }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getCertificate")
    public JAXBElement<GetCertificate> createGetCertificate(GetCertificate value) {
        return new JAXBElement<GetCertificate>(_GetCertificate_QNAME, GetCertificate.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link IsApproved }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "isApproved")
    public JAXBElement<IsApproved> createIsApproved(IsApproved value) {
        return new JAXBElement<IsApproved>(_IsApproved_QNAME, IsApproved.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetAvailableCAs }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getAvailableCAs")
    public JAXBElement<GetAvailableCAs> createGetAvailableCAs(GetAvailableCAs value) {
        return new JAXBElement<GetAvailableCAs>(_GetAvailableCAs_QNAME, GetAvailableCAs.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link EditUser }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "editUser")
    public JAXBElement<EditUser> createEditUser(EditUser value) {
        return new JAXBElement<EditUser>(_EditUser_QNAME, EditUser.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DeleteUserDataFromSource }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "deleteUserDataFromSource")
    public JAXBElement<DeleteUserDataFromSource> createDeleteUserDataFromSource(DeleteUserDataFromSource value) {
        return new JAXBElement<DeleteUserDataFromSource>(_DeleteUserDataFromSource_QNAME, DeleteUserDataFromSource.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CADoesntExistsException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "CADoesntExistsException")
    public JAXBElement<CADoesntExistsException> createCADoesntExistsException(CADoesntExistsException value) {
        return new JAXBElement<CADoesntExistsException>(_CADoesntExistsException_QNAME, CADoesntExistsException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetLastCAChainResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getLastCAChainResponse")
    public JAXBElement<GetLastCAChainResponse> createGetLastCAChainResponse(GetLastCAChainResponse value) {
        return new JAXBElement<GetLastCAChainResponse>(_GetLastCAChainResponse_QNAME, GetLastCAChainResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CustomLogResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "customLogResponse")
    public JAXBElement<CustomLogResponse> createCustomLogResponse(CustomLogResponse value) {
        return new JAXBElement<CustomLogResponse>(_CustomLogResponse_QNAME, CustomLogResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CaRenewCertRequestResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "caRenewCertRequestResponse")
    public JAXBElement<CaRenewCertRequestResponse> createCaRenewCertRequestResponse(CaRenewCertRequestResponse value) {
        return new JAXBElement<CaRenewCertRequestResponse>(_CaRenewCertRequestResponse_QNAME, CaRenewCertRequestResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link EjbcaException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "EjbcaException")
    public JAXBElement<EjbcaException> createEjbcaException(EjbcaException value) {
        return new JAXBElement<EjbcaException>(_EjbcaException_QNAME, EjbcaException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetLastCAChain }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getLastCAChain")
    public JAXBElement<GetLastCAChain> createGetLastCAChain(GetLastCAChain value) {
        return new JAXBElement<GetLastCAChain>(_GetLastCAChain_QNAME, GetLastCAChain.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link ApprovalRequestExecutionException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "ApprovalRequestExecutionException")
    public JAXBElement<ApprovalRequestExecutionException> createApprovalRequestExecutionException(ApprovalRequestExecutionException value) {
        return new JAXBElement<ApprovalRequestExecutionException>(_ApprovalRequestExecutionException_QNAME, ApprovalRequestExecutionException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeCert }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeCert")
    public JAXBElement<RevokeCert> createRevokeCert(RevokeCert value) {
        return new JAXBElement<RevokeCert>(_RevokeCert_QNAME, RevokeCert.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link FetchUserData }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "fetchUserData")
    public JAXBElement<FetchUserData> createFetchUserData(FetchUserData value) {
        return new JAXBElement<FetchUserData>(_FetchUserData_QNAME, FetchUserData.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link GetEjbcaVersionResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "getEjbcaVersionResponse")
    public JAXBElement<GetEjbcaVersionResponse> createGetEjbcaVersionResponse(GetEjbcaVersionResponse value) {
        return new JAXBElement<GetEjbcaVersionResponse>(_GetEjbcaVersionResponse_QNAME, GetEjbcaVersionResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CaCertResponseResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "caCertResponseResponse")
    public JAXBElement<CaCertResponseResponse> createCaCertResponseResponse(CaCertResponseResponse value) {
        return new JAXBElement<CaCertResponseResponse>(_CaCertResponseResponse_QNAME, CaCertResponseResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CAOfflineException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "CAOfflineException")
    public JAXBElement<CAOfflineException> createCAOfflineException(CAOfflineException value) {
        return new JAXBElement<CAOfflineException>(_CAOfflineException_QNAME, CAOfflineException.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link CreateCRL }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "createCRL")
    public JAXBElement<CreateCRL> createCreateCRL(CreateCRL value) {
        return new JAXBElement<CreateCRL>(_CreateCRL_QNAME, CreateCRL.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "", name = "return", scope = CaRenewCertRequestResponse.class)
    public JAXBElement<byte[]> createCaRenewCertRequestResponseReturn(byte[] value) {
        return new JAXBElement<byte[]>(_CaRenewCertRequestResponseReturn_QNAME, byte[].class, CaRenewCertRequestResponse.class, ((byte[]) value));
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "", name = "arg1", scope = CaCertResponse.class)
    public JAXBElement<byte[]> createCaCertResponseArg1(byte[] value) {
        return new JAXBElement<byte[]>(_CaCertResponseArg1_QNAME, byte[].class, CaCertResponse.class, ((byte[]) value));
    }

}
