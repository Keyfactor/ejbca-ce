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
package org.ejbca.core.protocol.cmp;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.ejb.CreateException;
import javax.ejb.EJBHome;
import javax.ejb.EJBObject;
import javax.ejb.FinderException;
import javax.ejb.Handle;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;

import junit.framework.TestCase;

import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceResponse;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Unit tests for CrmfMessageHandler. 
 * 
 * FIXME: This unit test massively stubs the session
 * beans in order to be able to be run offline. These stubs should be replaced
 * by mocks in future versions of EJBCA. Note that the stubs merely produce
 * deterministic data and perform no validation.
 * 
 * @author mikek
 * @version $Id$
 */
public class CrmfMessageHandlerTest extends TestCase {

    private static String USER_NAME = "foobar";

    private Admin admin;

    public CrmfMessageHandlerTest() {

    }

    public CrmfMessageHandlerTest(String name) {
        super(name);
    }

    public void setUp() throws Exception {
        super.setUp();
        admin = new Admin(Admin.TYPE_RA_USER);
    }

    public void tearDown() throws Exception {
        super.tearDown();
        admin = null;
    }

    public void testExtractUserNameComponent() throws RemoteException, CreateException, InstantiationException, IllegalAccessException,
            IllegalArgumentException, InvocationTargetException, SecurityException, NoSuchMethodException, NoSuchFieldException,
            ClassNotFoundException {

        
        
        
        CrmfMessageHandler crmfMessageHandler = new CrmfMessageHandler();

        /*
         * Some slight reflective manipulation of crmfMessageHandler here in
         * order to get around the fact that we're not running any of the logic
         * in its usual constructor, instead using the empty default one.
         */

        Field adminField = CrmfMessageHandler.class.getDeclaredField("admin");
        adminField.setAccessible(true);
        adminField.set(crmfMessageHandler, admin);

        Field userSessionField = CrmfMessageHandler.class.getDeclaredField("userAdminSession");
        userSessionField.setAccessible(true);
        userSessionField.set(crmfMessageHandler, new UserAdminSessionRemoteStub());

        Field signSessionField = CrmfMessageHandler.class.getDeclaredField("signSession");
        signSessionField.setAccessible(true);
        SignSessionStub signsession = new SignSessionStub();
        signSessionField.set(crmfMessageHandler, signsession);

        crmfMessageHandler.handleMessage(new CrmfRequestMessage() {
            private static final long serialVersionUID = 1L;

            public String getSubjectDN() {
                return "foo";
            }

        });

        assertEquals("testExtractUserNameComponent did not process user name correctly", USER_NAME, signsession.getUserName());

    }

    /*
     * Below here are stubs of the SessionBeans. These should be replaced by
     * mocks in EJBCA4. Code below this point is merely utility.
     */

    public static class SignSessionStub implements SignSessionRemote {

        /**
         * For the purpose of this test stub, this variable simply stores a test
         * result;
         */
        private String userName = "";

        public String getUserName() {
            return userName;
        }

        public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk) throws EjbcaException,
                ObjectNotFoundException {

            return null;
        }

        public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter)
                throws EjbcaException, ObjectNotFoundException {

            return null;
        }

        public Certificate createCertificate(Admin admin, String username, String password, Certificate incert) throws EjbcaException,
                ObjectNotFoundException {

            return null;
        }

        /**
		 * This method has been stubbed to respond to
		 * testExtractUserNameComponent
		 */
		public IResponseMessage createCertificate(Admin admin, IRequestMessage req, Class responseClass, UserDataVO suppliedUserData) throws EjbcaException {
            userName = req.getUsername();		
		    return null;
		}

        public Certificate createCertificate(Admin admin, String username, String password, PublicKey pk, int keyusage, Date notBefore, Date notAfter, int certificateprofileid, int caid) 
        throws EjbcaException, ObjectNotFoundException {
        	return null;
        }
        
		public byte[] createPKCS7(Admin admin, Certificate cert, boolean includeChain) throws CADoesntExistsException, SignRequestSignatureException {

            return null;
        }

        public byte[] createPKCS7(Admin admin, int caId, boolean includeChain) throws CADoesntExistsException {

            return null;
        }

        public IResponseMessage createRequestFailedResponse(Admin admin, IRequestMessage req, Class responseClass) throws AuthLoginException,
                AuthStatusException, IllegalKeyException, CADoesntExistsException, SignRequestSignatureException, SignRequestException {

            return null;
        }

        public IRequestMessage decryptAndVerifyRequest(Admin admin, IRequestMessage req) throws ObjectNotFoundException, AuthStatusException,
                AuthLoginException, IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException {

            return null;
        }

        public ExtendedCAServiceResponse extendedService(Admin admin, int caid, ExtendedCAServiceRequest request)
                throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException,
                CADoesntExistsException {

            return null;
        }

        public IResponseMessage getCRL(Admin admin, IRequestMessage req, Class responseClass) throws AuthStatusException, AuthLoginException,
                IllegalKeyException, CADoesntExistsException, SignRequestException, SignRequestSignatureException, UnsupportedEncodingException {

            return null;
        }

        public Collection getCertificateChain(Admin admin, int caid) {

            return null;
        }

        public boolean isUniqueCertificateSerialNumberIndex() {

            return false;
        }

        public EJBHome getEJBHome() throws RemoteException {

            return null;
        }

        public Handle getHandle() throws RemoteException {

            return null;
        }

        public Object getPrimaryKey() throws RemoteException {

            return null;
        }

        public boolean isIdentical(EJBObject arg0) throws RemoteException {

            return false;
        }

        public void remove() throws RemoteException, RemoveException {

        }

    }

    class UserAdminSessionRemoteStub implements UserAdminSessionRemote {

        public void addUser(Admin admin, String username, String password, String subjectdn, String subjectaltname, String email, boolean clearpwd,
                int endentityprofileid, int certificateprofileid, int type, int tokentype, int hardwaretokenissuerid, int caid)
                throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException,
                EjbcaException {

        }

        public void addUser(Admin admin, UserDataVO userdata, boolean clearpwd) throws AuthorizationDeniedException,
                UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException, EjbcaException {

        }

        public void addUserFromWS(Admin admin, UserDataVO userdata, boolean clearpwd) throws AuthorizationDeniedException,
                UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException, EjbcaException {

        }

        public void changeUser(Admin admin, String username, String password, String subjectdn, String subjectaltname, String email,
                boolean clearpwd, int endentityprofileid, int certificateprofileid, int type, int tokentype, int hardwaretokenissuerid, int status,
                int caid) throws AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, WaitingForApprovalException,
                CADoesntExistsException, EjbcaException {

        }

        public void changeUser(Admin admin, UserDataVO userdata, boolean clearpwd) throws AuthorizationDeniedException,
                UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException, EjbcaException {

        }

        public void changeUser(Admin admin, UserDataVO userdata, boolean clearpwd, boolean fromWebService) throws AuthorizationDeniedException,
                UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, CADoesntExistsException, EjbcaException {

        }

        public boolean checkForCAId(Admin admin, int caid)  {

            return false;
        }

        public boolean checkForCertificateProfileId(Admin admin, int certificateprofileid) {

            return false;
        }

        public boolean checkForEndEntityProfileId(Admin admin, int endentityprofileid) {

            return false;
        }

        public boolean checkForHardTokenProfileId(Admin admin, int profileid) {

            return false;
        }

        public void checkIfCertificateBelongToAdmin(Admin admin, BigInteger certificatesnr, String issuerdn) throws AuthorizationDeniedException {

        }

        public void checkIfCertificateBelongToUser(Admin admin, BigInteger certificatesnr, String issuerdn) throws AuthorizationDeniedException {

        }

        public void cleanUserCertDataSN(Admin admin, String username) throws AuthorizationDeniedException, FinderException, ApprovalException,
                WaitingForApprovalException {

        }

        public void decRemainingLoginAttempts(Admin admin, String username) throws AuthorizationDeniedException, FinderException {

        }

        public int decRequestCounter(Admin admin, String username) throws AuthorizationDeniedException, FinderException, ApprovalException,
                WaitingForApprovalException {

            return 0;
        }

        public void deleteUser(Admin admin, String username) throws AuthorizationDeniedException, NotFoundException, RemoveException {

        }

        public boolean existsUser(Admin admin, String username) {

            return false;
        }

        public Collection findAllUsersByCaId(Admin admin, int caid) {

            return null;
        }

        public Collection findAllUsersByStatus(Admin admin, int status) throws FinderException {

            return null;
        }

        public Collection findAllUsersByStatusWithLimit(Admin admin, int status, boolean onlybatchusers) throws FinderException {

            return null;
        }

        public Collection findAllUsersWithLimit(Admin admin) {

            return null;
        }

        public UserDataVO findUser(Admin admin, String username) throws AuthorizationDeniedException {

            return null;
        }

        public Collection findUserByEmail(Admin admin, String email) throws AuthorizationDeniedException {

            return null;
        }

        public UserDataVO findUserBySubjectAndIssuerDN(Admin admin, String subjectdn, String issuerdn) throws AuthorizationDeniedException {

            return null;
        }

        public UserDataVO findUserBySubjectDN(Admin admin, String subjectdn) throws AuthorizationDeniedException {

            return new UserDataVOStub();
        }

        public Admin getAdmin(Certificate certificate) {

            return null;
        }

        public boolean prepareForKeyRecovery(Admin admin, String username, int endEntityProfileId, Certificate certificate)
                throws AuthorizationDeniedException, ApprovalException, WaitingForApprovalException {

            return false;
        }

        public Collection query(Admin admin, Query query, String caauthorizationstring, String endentityprofilestring, int numberofrows)
                throws IllegalQueryException {

            return null;
        }

        public void resetRemainingLoginAttempts(Admin admin, String username) throws AuthorizationDeniedException, FinderException {

        }

        public void revokeAndDeleteUser(Admin admin, String username, int reason) throws AuthorizationDeniedException, ApprovalException,
                WaitingForApprovalException, RemoveException, NotFoundException {

        }

        public void revokeCert(Admin admin, BigInteger certserno, String issuerdn, String username, int reason) throws AuthorizationDeniedException,
                FinderException, ApprovalException, WaitingForApprovalException, AlreadyRevokedException {

        }

        public void revokeUser(Admin admin, String username, int reason) throws AuthorizationDeniedException, FinderException, ApprovalException,
                WaitingForApprovalException, AlreadyRevokedException {

        }

        public void setClearTextPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile,
                AuthorizationDeniedException, FinderException {

        }

        public void setPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile,
                AuthorizationDeniedException, FinderException {

        }

        public void setUserStatus(Admin admin, String username, int status) throws AuthorizationDeniedException, FinderException, ApprovalException,
                WaitingForApprovalException {

        }

        public boolean verifyPassword(Admin admin, String username, String password) throws UserDoesntFullfillEndEntityProfile,
                AuthorizationDeniedException, FinderException {

            return false;
        }

        public EJBHome getEJBHome() throws RemoteException {

            return null;
        }

        public Handle getHandle() throws RemoteException {

            return null;
        }

        public Object getPrimaryKey() throws RemoteException {

            return null;
        }

        public boolean isIdentical(EJBObject arg0) throws RemoteException {

            return false;
        }

        public void remove() throws RemoteException, RemoveException {

        }

        class UserDataVOStub extends UserDataVO {
            private static final long serialVersionUID = 1L;

            public String getUsername() {
                return USER_NAME;
            }
        }

        @Override
        public void cleanUserCertDataSN(UserDataVO data) throws ObjectNotFoundException {
            
        }

        @Override
        public List<UserData> findUsers(List<Integer> caIds, long timeModified, int status) {
            return null;
        }

    }

}
