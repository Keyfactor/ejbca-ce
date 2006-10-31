
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

    private final static QName _RevokeCert_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeCert");
    private final static QName _Pkcs10Req_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs10Req");
    private final static QName _AuthorizationDeniedException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "AuthorizationDeniedException");
    private final static QName _RevokeUserResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeUserResponse");
    private final static QName _ApprovalException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "ApprovalException");
    private final static QName _NotFoundException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "NotFoundException");
    private final static QName _EditUser_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "editUser");
    private final static QName _Pkcs12ReqResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs12ReqResponse");
    private final static QName _EditUserResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "editUserResponse");
    private final static QName _RevokeCertResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeCertResponse");
    private final static QName _FindUserResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findUserResponse");
    private final static QName _WaitingForApprovalException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "WaitingForApprovalException");
    private final static QName _FindCerts_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findCerts");
    private final static QName _CheckRevokationStatusResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "checkRevokationStatusResponse");
    private final static QName _Pkcs10ReqResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs10ReqResponse");
    private final static QName _CheckRevokationStatus_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "checkRevokationStatus");
    private final static QName _IllegalQueryException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "IllegalQueryException");
    private final static QName _UserDoesntFullfillEndEntityProfile_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "UserDoesntFullfillEndEntityProfile");
    private final static QName _FindUser_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findUser");
    private final static QName _EjbcaException_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaException");
    private final static QName _RevokeUser_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeUser");
    private final static QName _RevokeTokenResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeTokenResponse");
    private final static QName _FindCertsResponse_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "findCertsResponse");
    private final static QName _RevokeToken_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "revokeToken");
    private final static QName _Pkcs12Req_QNAME = new QName("http://ws.protocol.core.ejbca.org/", "pkcs12Req");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.ejbca.core.protocol.ws.client.gen
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link FindUser }
     * 
     */
    public FindUser createFindUser() {
        return new FindUser();
    }

    /**
     * Create an instance of {@link WaitingForApprovalException }
     * 
     */
    public WaitingForApprovalException createWaitingForApprovalException() {
        return new WaitingForApprovalException();
    }

    /**
     * Create an instance of {@link EditUser }
     * 
     */
    public EditUser createEditUser() {
        return new EditUser();
    }

    /**
     * Create an instance of {@link RevokeUser }
     * 
     */
    public RevokeUser createRevokeUser() {
        return new RevokeUser();
    }

    /**
     * Create an instance of {@link RevokeUserResponse }
     * 
     */
    public RevokeUserResponse createRevokeUserResponse() {
        return new RevokeUserResponse();
    }

    /**
     * Create an instance of {@link UserDoesntFullfillEndEntityProfile }
     * 
     */
    public UserDoesntFullfillEndEntityProfile createUserDoesntFullfillEndEntityProfile() {
        return new UserDoesntFullfillEndEntityProfile();
    }

    /**
     * Create an instance of {@link NotFoundException }
     * 
     */
    public NotFoundException createNotFoundException() {
        return new NotFoundException();
    }

    /**
     * Create an instance of {@link Pkcs12ReqResponse }
     * 
     */
    public Pkcs12ReqResponse createPkcs12ReqResponse() {
        return new Pkcs12ReqResponse();
    }

    /**
     * Create an instance of {@link CheckRevokationStatus }
     * 
     */
    public CheckRevokationStatus createCheckRevokationStatus() {
        return new CheckRevokationStatus();
    }

    /**
     * Create an instance of {@link FindCertsResponse }
     * 
     */
    public FindCertsResponse createFindCertsResponse() {
        return new FindCertsResponse();
    }

    /**
     * Create an instance of {@link Certificate }
     * 
     */
    public Certificate createCertificate() {
        return new Certificate();
    }

    /**
     * Create an instance of {@link Pkcs10Req }
     * 
     */
    public Pkcs10Req createPkcs10Req() {
        return new Pkcs10Req();
    }

    /**
     * Create an instance of {@link Pkcs12Req }
     * 
     */
    public Pkcs12Req createPkcs12Req() {
        return new Pkcs12Req();
    }

    /**
     * Create an instance of {@link RevokeStatus }
     * 
     */
    public RevokeStatus createRevokeStatus() {
        return new RevokeStatus();
    }

    /**
     * Create an instance of {@link RevokeToken }
     * 
     */
    public RevokeToken createRevokeToken() {
        return new RevokeToken();
    }

    /**
     * Create an instance of {@link EjbcaException }
     * 
     */
    public EjbcaException createEjbcaException() {
        return new EjbcaException();
    }

    /**
     * Create an instance of {@link RevokeCert }
     * 
     */
    public RevokeCert createRevokeCert() {
        return new RevokeCert();
    }

    /**
     * Create an instance of {@link FindCerts }
     * 
     */
    public FindCerts createFindCerts() {
        return new FindCerts();
    }

    /**
     * Create an instance of {@link UserDataVOWS }
     * 
     */
    public UserDataVOWS createUserDataVOWS() {
        return new UserDataVOWS();
    }

    /**
     * Create an instance of {@link EditUserResponse }
     * 
     */
    public EditUserResponse createEditUserResponse() {
        return new EditUserResponse();
    }

    /**
     * Create an instance of {@link CheckRevokationStatusResponse }
     * 
     */
    public CheckRevokationStatusResponse createCheckRevokationStatusResponse() {
        return new CheckRevokationStatusResponse();
    }

    /**
     * Create an instance of {@link ApprovalException }
     * 
     */
    public ApprovalException createApprovalException() {
        return new ApprovalException();
    }

    /**
     * Create an instance of {@link AuthorizationDeniedException }
     * 
     */
    public AuthorizationDeniedException createAuthorizationDeniedException() {
        return new AuthorizationDeniedException();
    }

    /**
     * Create an instance of {@link IllegalQueryException }
     * 
     */
    public IllegalQueryException createIllegalQueryException() {
        return new IllegalQueryException();
    }

    /**
     * Create an instance of {@link RevokeCertResponse }
     * 
     */
    public RevokeCertResponse createRevokeCertResponse() {
        return new RevokeCertResponse();
    }

    /**
     * Create an instance of {@link UserMatch }
     * 
     */
    public UserMatch createUserMatch() {
        return new UserMatch();
    }

    /**
     * Create an instance of {@link KeyStore }
     * 
     */
    public KeyStore createKeyStore() {
        return new KeyStore();
    }

    /**
     * Create an instance of {@link Pkcs10ReqResponse }
     * 
     */
    public Pkcs10ReqResponse createPkcs10ReqResponse() {
        return new Pkcs10ReqResponse();
    }

    /**
     * Create an instance of {@link FindUserResponse }
     * 
     */
    public FindUserResponse createFindUserResponse() {
        return new FindUserResponse();
    }

    /**
     * Create an instance of {@link RevokeTokenResponse }
     * 
     */
    public RevokeTokenResponse createRevokeTokenResponse() {
        return new RevokeTokenResponse();
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
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs10Req }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs10Req")
    public JAXBElement<Pkcs10Req> createPkcs10Req(Pkcs10Req value) {
        return new JAXBElement<Pkcs10Req>(_Pkcs10Req_QNAME, Pkcs10Req.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeUserResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeUserResponse")
    public JAXBElement<RevokeUserResponse> createRevokeUserResponse(RevokeUserResponse value) {
        return new JAXBElement<RevokeUserResponse>(_RevokeUserResponse_QNAME, RevokeUserResponse.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link NotFoundException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "NotFoundException")
    public JAXBElement<NotFoundException> createNotFoundException(NotFoundException value) {
        return new JAXBElement<NotFoundException>(_NotFoundException_QNAME, NotFoundException.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs12ReqResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs12ReqResponse")
    public JAXBElement<Pkcs12ReqResponse> createPkcs12ReqResponse(Pkcs12ReqResponse value) {
        return new JAXBElement<Pkcs12ReqResponse>(_Pkcs12ReqResponse_QNAME, Pkcs12ReqResponse.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeCertResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeCertResponse")
    public JAXBElement<RevokeCertResponse> createRevokeCertResponse(RevokeCertResponse value) {
        return new JAXBElement<RevokeCertResponse>(_RevokeCertResponse_QNAME, RevokeCertResponse.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link WaitingForApprovalException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "WaitingForApprovalException")
    public JAXBElement<WaitingForApprovalException> createWaitingForApprovalException(WaitingForApprovalException value) {
        return new JAXBElement<WaitingForApprovalException>(_WaitingForApprovalException_QNAME, WaitingForApprovalException.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link CheckRevokationStatusResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "checkRevokationStatusResponse")
    public JAXBElement<CheckRevokationStatusResponse> createCheckRevokationStatusResponse(CheckRevokationStatusResponse value) {
        return new JAXBElement<CheckRevokationStatusResponse>(_CheckRevokationStatusResponse_QNAME, CheckRevokationStatusResponse.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs10ReqResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs10ReqResponse")
    public JAXBElement<Pkcs10ReqResponse> createPkcs10ReqResponse(Pkcs10ReqResponse value) {
        return new JAXBElement<Pkcs10ReqResponse>(_Pkcs10ReqResponse_QNAME, Pkcs10ReqResponse.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link IllegalQueryException }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "IllegalQueryException")
    public JAXBElement<IllegalQueryException> createIllegalQueryException(IllegalQueryException value) {
        return new JAXBElement<IllegalQueryException>(_IllegalQueryException_QNAME, IllegalQueryException.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link FindUser }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "findUser")
    public JAXBElement<FindUser> createFindUser(FindUser value) {
        return new JAXBElement<FindUser>(_FindUser_QNAME, FindUser.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link RevokeUser }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "revokeUser")
    public JAXBElement<RevokeUser> createRevokeUser(RevokeUser value) {
        return new JAXBElement<RevokeUser>(_RevokeUser_QNAME, RevokeUser.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link FindCertsResponse }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "findCertsResponse")
    public JAXBElement<FindCertsResponse> createFindCertsResponse(FindCertsResponse value) {
        return new JAXBElement<FindCertsResponse>(_FindCertsResponse_QNAME, FindCertsResponse.class, null, value);
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
     * Create an instance of {@link JAXBElement }{@code <}{@link Pkcs12Req }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "http://ws.protocol.core.ejbca.org/", name = "pkcs12Req")
    public JAXBElement<Pkcs12Req> createPkcs12Req(Pkcs12Req value) {
        return new JAXBElement<Pkcs12Req>(_Pkcs12Req_QNAME, Pkcs12Req.class, null, value);
    }

}
