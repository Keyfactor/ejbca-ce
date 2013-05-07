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
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509DefaultEntryConverter;
import org.bouncycastle.asn1.x509.X509NameEntryConverter;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.certificates.ca.internal.SernoGeneratorRandom;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ocsp.OcspKeyRenewalSessionLocal;
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
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "OcspKeyRenewalProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class OcspKeyRenewalProxySessionBean implements OcspKeyRenewalProxySessionRemote, OcspKeyRenewalProxySessionLocal {

    @EJB
    private OcspKeyRenewalSessionLocal ocspKeyRenewalSession;
  
    
    @Override
    public void setMockWebServiceObject() throws SecurityException, NoSuchFieldException, IllegalArgumentException, IllegalAccessException {
        EjbcaWSMock ejbcaWSMock = new EjbcaWSMock();
        ocspKeyRenewalSession.setEjbcaWs(ejbcaWSMock);

    }  
    
    @Override
    public void setManagementCaKeyPair(KeyPair caKeyPair) {
        SharedInformation.INSTANCE.setCaKeyPair(caKeyPair);
        
    }
    
    @Override
    public void setCaDn(String caDn) {
        SharedInformation.INSTANCE.setCaDn(caDn);
    }
    
    @Override
    public void setTimerToFireInOneSecond() throws InterruptedException {
        long oldValue = OcspConfiguration.getRekeyingUpdateTimeInSeconds();
        ConfigurationHolder.updateConfiguration(OcspConfiguration.REKEYING_UPDATE_TIME_IN_SECONDS, "1");
        try {
            ocspKeyRenewalSession.startTimer();
            //Sleep for a second before killing the timer. 
            Thread.sleep(1000);
        } finally {
            ConfigurationHolder.updateConfiguration(OcspConfiguration.REKEYING_UPDATE_TIME_IN_SECONDS, Long.toString(oldValue));
            ocspKeyRenewalSession.startTimer();
        }
    }

    @Override
    public void renewKeyStores(String signerSubjectDN) throws KeyStoreException, CryptoTokenOfflineException, InvalidKeyException {
        ocspKeyRenewalSession.renewKeyStores(signerSubjectDN);
    }

    private class EjbcaWSMock implements EjbcaWS, Serializable {
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
             resultValue.setCaName("OcspDefaultTestCA");
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
        public CertificateResponse pkcs10Request(final String username, final String password, final String pkcs10, final String hardTokenSN,
                final String responseType) throws AuthorizationDeniedException_Exception, CADoesntExistsException_Exception,
                CesecoreException_Exception, EjbcaException_Exception, NotFoundException_Exception {
            try {
                Date firstDate = new Date();
                // Set starting date to tomorrow
                firstDate.setTime(firstDate.getTime() + (24 * 3600 * 1000));
                Date lastDate = new Date();
                // Set Expiry in two days
                lastDate.setTime(lastDate.getTime() + ((2 * 24 * 60 * 60 * 1000)));
                BigInteger serno = SernoGeneratorRandom.instance().getSerno();
                final RequestMessage pkcs10req = RequestMessageUtils.genPKCS10RequestMessage(pkcs10.getBytes());
                final PublicKey pubKey = pkcs10req.getRequestPublicKey();
                SubjectPublicKeyInfo pkinfo = new SubjectPublicKeyInfo((ASN1Sequence)ASN1Primitive.fromByteArray(pubKey.getEncoded()));
                final X509NameEntryConverter converter = new X509DefaultEntryConverter();
                X500Name signerName = CertTools.stringToBcX500Name("CN=ocspTestSigner", converter, false);
                if( SharedInformation.INSTANCE.getCaDn() == null) {
                    throw new IllegalStateException("caDn is null, can not proceed.");
                }
                X500Name caName = CertTools.stringToBcX500Name(SharedInformation.INSTANCE.getCaDn(), converter, false);
                final X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(caName, serno, firstDate, lastDate, signerName, pkinfo);
                final ContentSigner signer = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).build(SharedInformation.INSTANCE.getCaKeyPair().getPrivate());
                final X509CertificateHolder certHolder = certbuilder.build(signer);
                final X509Certificate cert = (X509Certificate)CertTools.getCertfromByteArray(certHolder.getEncoded());
                
                byte[] data = cert.getEncoded();
                return new CertificateResponse(responseType, data);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
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
            result.add(new NameAndId("OcspDefaultTestCA", "CN=OcspDefaultTestCA".hashCode()));
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
        public byte[] getLatestCRL(final String caname, final boolean deltaCRL) throws CADoesntExistsException_Exception, EjbcaException_Exception {
            return null;
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

    private static enum SharedInformation {
        INSTANCE;

        private KeyPair caKeyPair;
        private String caDn;
        /**
         * @return the caKeyPair
         */
        public KeyPair getCaKeyPair() {
            return caKeyPair;
        }
        /**
         * @param caKeyPair the caKeyPair to set
         */
        public void setCaKeyPair(KeyPair caKeyPair) {
            this.caKeyPair = caKeyPair;
        }
        /**
         * @return the caDn
         */
        public String getCaDn() {
            return caDn;
        }
        /**
         * @param caDn the caDn to set
         */
        public void setCaDn(String caDn) {
            this.caDn = caDn;
        }
    }
    
}

