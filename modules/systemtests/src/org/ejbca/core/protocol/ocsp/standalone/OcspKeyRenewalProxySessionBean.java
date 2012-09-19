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
package org.ejbca.core.protocol.ocsp.standalone;


import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.jndi.JndiConstants;
import org.ejbca.core.ejb.ocsp.standalone.StandaloneOcspKeyRenewalSessionLocal;
import org.ejbca.core.protocol.ws.client.gen.AlreadyRevokedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalRequestExecutionException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ApprovalRequestExpiredException_Exception;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CADoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CAOfflineException_Exception;
import org.ejbca.core.protocol.ws.client.gen.Certificate;
import org.ejbca.core.protocol.ws.client.gen.CertificateExpiredException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.CesecoreException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CryptoTokenOfflineException_Exception;
import org.ejbca.core.protocol.ws.client.gen.DateNotValidException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaException_Exception;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDataWS;
import org.ejbca.core.protocol.ws.client.gen.HardTokenDoesntExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.HardTokenExistsException_Exception;
import org.ejbca.core.protocol.ws.client.gen.IllegalQueryException_Exception;
import org.ejbca.core.protocol.ws.client.gen.KeyStore;
import org.ejbca.core.protocol.ws.client.gen.MultipleMatchException_Exception;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.NotFoundException_Exception;
import org.ejbca.core.protocol.ws.client.gen.PublisherException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeBackDateNotAllowedForProfileException_Exception;
import org.ejbca.core.protocol.ws.client.gen.RevokeStatus;
import org.ejbca.core.protocol.ws.client.gen.SignRequestException_Exception;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.client.gen.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataSourceException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataSourceVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.client.gen.WaitingForApprovalException_Exception;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspKeyRenewalProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspKeyRenewalProxySessionBean implements OcspKeyRenewalProxySessionRemote {

    @EJB
    private StandaloneOcspKeyRenewalSessionLocal ocspKeyRenewalSession;
    
     @PostConstruct
     public void setMockWebServiceObject() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
         EjbcaWSMock ejbcaWSMock = new EjbcaWSMock();
         ocspKeyRenewalSession.setEjbcaWs(ejbcaWSMock);
         
     }
     
     @Override
     public void renewKeyStores(String signerSubjectDN) {       
         ocspKeyRenewalSession.renewKeyStores(signerSubjectDN);
     }
     
     private static class EjbcaWSMock implements EjbcaWS, Serializable {
         private static final long serialVersionUID = 694285260730885817L;

         @Override
         public Certificate getCertificate(String arg0, String arg1) throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                 EjbcaException_Exception {
             return null;
         }

         @Override
         public void editUser(UserDataVOWS arg0) throws ApprovalException_Exception, AuthorizationDeniedException_Exception,
                 CADoesntExistsException_Exception, EjbcaException_Exception, UserDoesntFullfillEndEntityProfile_Exception,
                 WaitingForApprovalException_Exception {
             
         }

         @Override
         public List<UserDataVOWS> findUser(UserMatch arg0) throws AuthorizationDeniedException_Exception, EjbcaException_Exception,
                 IllegalQueryException_Exception {
             List<UserDataVOWS> result = new ArrayList<UserDataVOWS>();
             UserDataVOWS resultValue = new UserDataVOWS();
             resultValue.setUsername("ocspTestSigner");
             resultValue.setPassword("foo123");
             result.add(resultValue);
             return result;
         }

         @Override
         public List<Certificate> findCerts(String arg0, boolean arg1) throws AuthorizationDeniedException_Exception, EjbcaException_Exception {
             return null;
         }

         @Override
         public List<Certificate> getLastCertChain(String arg0) throws AuthorizationDeniedException_Exception, EjbcaException_Exception {
             return null;
         }

         @Override
         public CertificateResponse crmfRequest(String arg0, String arg1, String arg2, String arg3, String arg4)
                 throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, CesecoreException_Exception,
                 EjbcaException_Exception, NotFoundException_Exception {
             // TODO Auto-generated method stub
             return null;
         }

         @Override
         public CertificateResponse spkacRequest(String arg0, String arg1, String arg2, String arg3, String arg4)
                 throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, CesecoreException_Exception,
                 EjbcaException_Exception, NotFoundException_Exception {
             return null;
         }

         @Override
         public List<Certificate> cvcRequest(String arg0, String arg1, String arg2) throws ApprovalException_Exception,
                 AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, CertificateExpiredException_Exception,
                 CesecoreException_Exception, EjbcaException_Exception, NotFoundException_Exception, SignRequestException_Exception,
                 UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception {
             return null;
         }

         @Override
         public byte[] caRenewCertRequest(String arg0, List<byte[]> arg1, boolean arg2, boolean arg3, boolean arg4, String arg5)
                 throws ApprovalException_Exception, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                 EjbcaException_Exception, WaitingForApprovalException_Exception {
             return null;
         }

         @Override
         public void caCertResponse(String arg0, byte[] arg1, List<byte[]> arg2, String arg3) throws ApprovalException_Exception,
                 AuthorizationDeniedException_Exception, CesecoreException_Exception, EjbcaException_Exception, WaitingForApprovalException_Exception {
             
         }

         @Override
         public CertificateResponse pkcs10Request(String arg0, String arg1, String arg2, String arg3, String arg4)
                 throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, CesecoreException_Exception,
                 EjbcaException_Exception, NotFoundException_Exception {

             return null;
         }

         @Override
         public KeyStore pkcs12Req(String arg0, String arg1, String arg2, String arg3, String arg4) throws AuthorizationDeniedException_Exception,
                 CADoesntExistsException_Exception, EjbcaException_Exception, NotFoundException_Exception {

             return null;
         }

         @Override
         public void revokeCert(String arg0, String arg1, int arg2) throws AlreadyRevokedException_Exception, ApprovalException_Exception,
                 AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception, NotFoundException_Exception,
                 WaitingForApprovalException_Exception {
             
         }

         @Override
         public void revokeCertBackdated(String arg0, String arg1, int arg2, String arg3) throws AlreadyRevokedException_Exception,
                 ApprovalException_Exception, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                 DateNotValidException_Exception, EjbcaException_Exception, NotFoundException_Exception,
                 RevokeBackDateNotAllowedForProfileException_Exception, WaitingForApprovalException_Exception {
             
         }

         @Override
         public void revokeUser(String arg0, int arg1, boolean arg2) throws AlreadyRevokedException_Exception, ApprovalException_Exception,
                 AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception, NotFoundException_Exception,
                 WaitingForApprovalException_Exception {
             
         }

         @Override
         public void keyRecoverNewest(String arg0) throws ApprovalException_Exception, AuthorizationDeniedException_Exception,
                 CADoesntExistsException_Exception, EjbcaException_Exception, NotFoundException_Exception, WaitingForApprovalException_Exception {
             
         }

         @Override
         public void revokeToken(String arg0, int arg1) throws AlreadyRevokedException_Exception, ApprovalException_Exception,
                 AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception, NotFoundException_Exception,
                 WaitingForApprovalException_Exception {
             
         }

         @Override
         public RevokeStatus checkRevokationStatus(String arg0, String arg1) throws AuthorizationDeniedException_Exception,
                 CADoesntExistsException_Exception, EjbcaException_Exception {
             return null;
         }

         @Override
         public boolean isAuthorized(String arg0) throws EjbcaException_Exception {
             return false;
         }

         @Override
         public List<UserDataSourceVOWS> fetchUserData(List<String> arg0, String arg1) throws AuthorizationDeniedException_Exception,
                 EjbcaException_Exception, UserDataSourceException_Exception {
             return null;
         }

         @Override
         public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS arg0, List<TokenCertificateRequestWS> arg1, HardTokenDataWS arg2,
                 boolean arg3, boolean arg4) throws ApprovalException_Exception, ApprovalRequestExecutionException_Exception,
                 ApprovalRequestExpiredException_Exception, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                 EjbcaException_Exception, HardTokenExistsException_Exception, UserDoesntFullfillEndEntityProfile_Exception,
                 WaitingForApprovalException_Exception {
             return null;
         }

         @Override
         public boolean existsHardToken(String arg0) throws EjbcaException_Exception {
             return false;
         }

         @Override
         public HardTokenDataWS getHardTokenData(String arg0, boolean arg1, boolean arg2) throws ApprovalRequestExecutionException_Exception,
                 ApprovalRequestExpiredException_Exception, AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                 EjbcaException_Exception, HardTokenDoesntExistsException_Exception, NotFoundException_Exception,
                 WaitingForApprovalException_Exception {
             return null;
         }

         @Override
         public List<HardTokenDataWS> getHardTokenDatas(String arg0, boolean arg1, boolean arg2) throws AuthorizationDeniedException_Exception,
                 CADoesntExistsException_Exception, EjbcaException_Exception {
             return null;
         }

         @Override
         public void republishCertificate(String arg0, String arg1) throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                 EjbcaException_Exception, PublisherException_Exception {
         }

         @Override
         public void customLog(int arg0, String arg1, String arg2, String arg3, Certificate arg4, String arg5)
                 throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception {
         }

         @Override
         public boolean deleteUserDataFromSource(List<String> arg0, String arg1, boolean arg2) throws AuthorizationDeniedException_Exception,
                 EjbcaException_Exception, MultipleMatchException_Exception, UserDataSourceException_Exception {
             return false;
         }

         @Override
         public int isApproved(int arg0) throws ApprovalException_Exception, ApprovalRequestExpiredException_Exception, EjbcaException_Exception {
             return 0;
         }

         @Override
         public List<NameAndId> getAvailableCAs() throws AuthorizationDeniedException_Exception, EjbcaException_Exception {
             List<NameAndId> result = new ArrayList<NameAndId>();
             result.add(new NameAndId("AdminCA1", -1688117755));
             return result;
         }

         @Override
         public List<NameAndId> getAuthorizedEndEntityProfiles() throws AuthorizationDeniedException_Exception, EjbcaException_Exception {
             return null;
         }

         @Override
         public List<NameAndId> getAvailableCertificateProfiles(int arg0) throws AuthorizationDeniedException_Exception, EjbcaException_Exception {
             return null;
         }

         @Override
         public List<NameAndId> getAvailableCAsInProfile(int arg0) throws AuthorizationDeniedException_Exception, EjbcaException_Exception {
             return null;
         }

         @Override
         public void createCRL(String arg0) throws ApprovalException_Exception, ApprovalRequestExpiredException_Exception,
                 CADoesntExistsException_Exception, CAOfflineException_Exception, CryptoTokenOfflineException_Exception, EjbcaException_Exception {
             
         }

         @Override
         public String getEjbcaVersion() {
             return null;
         }

         @Override
         public int getPublisherQueueLength(String arg0) throws EjbcaException_Exception {
             return 0;
         }

         @Override
         public CertificateResponse certificateRequest(UserDataVOWS arg0, String arg1, int arg2, String arg3, String arg4)
                 throws ApprovalException_Exception, AuthorizationDeniedException_Exception, EjbcaException_Exception, NotFoundException_Exception,
                 UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception {
             return null;
         }

         @Override
         public KeyStore softTokenRequest(UserDataVOWS arg0, String arg1, String arg2, String arg3) throws ApprovalException_Exception,
                 AuthorizationDeniedException_Exception, CADoesntExistsException_Exception, EjbcaException_Exception, NotFoundException_Exception,
                 UserDoesntFullfillEndEntityProfile_Exception, WaitingForApprovalException_Exception {
             return null;
         }

         @Override
         public List<Certificate> getLastCAChain(String arg0) throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                 EjbcaException_Exception {
             return null;
         }
         
     }

 }
