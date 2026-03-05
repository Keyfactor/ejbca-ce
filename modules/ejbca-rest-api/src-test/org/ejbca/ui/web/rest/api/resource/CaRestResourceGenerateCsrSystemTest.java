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
package org.ejbca.ui.web.rest.api.resource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.CaTestUtils;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CACommon;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.keys.token.CryptoTokenManagementProxySessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.web.rest.api.io.request.GenerateCsrCaRequest;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

public class CaRestResourceGenerateCsrSystemTest extends RestResourceSystemTestBase {
        
    private static final String ROOT_CA_DN = "CN=RootCaRestResourceGenerateCsrSystemTest,OU=test";
    private static final String SUB_CA_DN = "CN=SubCaRestResourceGenerateCsrSystemTest,OU=test";
    private static final String CA_GENERATE_CSR_URL = "/v1/ca/issuer_dn/generatecsr";
    
    private int rootCaCryptoTokenId;
    private int subCaCryptoTokenId;
    
    private CAToken rootCaToken;
    private CAToken subCaToken;
    
    private X509Certificate rootCaCert;
    
    private PublicKey rootCaPublicKey;
    private PublicKey subCaPublicKey;
    
    CryptoTokenManagementProxySessionRemote cryptoTokenManagementProxySession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CryptoTokenManagementProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    CaTestSessionRemote caTestSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(
            CaTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        RestResourceSystemTestBase.beforeClass();
    }

    @AfterClass
    public static void afterClass() throws Exception {
        RestResourceSystemTestBase.afterClass();
    }
    
    @Before
    public void before() throws Exception {
        String signingKeyNameRootCa = ROOT_CA_DN + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS;
        String encryptionKeyNameRootCa = ROOT_CA_DN + "_" + CAToken.SOFTPRIVATEDECKEYALIAS;
        rootCaCryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(INTERNAL_ADMIN_TOKEN, 
                "foo123".toCharArray(), true, SoftCryptoToken.class.getName(), ROOT_CA_DN, "RSA2048", "RSA2048", 
                signingKeyNameRootCa, encryptionKeyNameRootCa);
        rootCaToken = 
                CaTestUtils.createCaToken(rootCaCryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, 
                        AlgorithmConstants.SIGALG_SHA256_WITH_RSA, signingKeyNameRootCa, encryptionKeyNameRootCa);
        
        
        rootCaPublicKey = cryptoTokenManagementProxySession.getPublicKey(rootCaCryptoTokenId,
                signingKeyNameRootCa).getPublicKey();
        PrivateKey privateKey = cryptoTokenManagementProxySession.getPrivateKey(rootCaCryptoTokenId,
                signingKeyNameRootCa);
        rootCaCert = SimpleCertGenerator.forTESTCaCert()
                .setSubjectDn(ROOT_CA_DN)
                .setIssuerDn(ROOT_CA_DN)
                .setPolicyId("1.1.1.1")
                .setValidityDays(10)
                .setIssuerPrivKey(privateKey)
                .setEntityPubKey(rootCaPublicKey)
                .setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA)
                .setProvider("BC")
                .generateCertificate();
        
        String signingKeyNameSubCa = SUB_CA_DN + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS;
        String encryptionKeyNameSubCa = SUB_CA_DN + "_" + CAToken.SOFTPRIVATEDECKEYALIAS;
        subCaCryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(INTERNAL_ADMIN_TOKEN, 
                "foo123".toCharArray(), true, SoftCryptoToken.class.getName(), SUB_CA_DN, "RSA2048", "RSA2048", 
                signingKeyNameSubCa, encryptionKeyNameSubCa);
        subCaToken = 
                CaTestUtils.createCaToken(subCaCryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_RSA, 
                        AlgorithmConstants.SIGALG_SHA256_WITH_RSA, signingKeyNameSubCa, encryptionKeyNameSubCa);
        subCaPublicKey = cryptoTokenManagementProxySession.getPublicKey(subCaCryptoTokenId,
                signingKeyNameSubCa).getPublicKey();
        
    }
    
    @After
    public void after() {
        try {
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, rootCaCryptoTokenId);
            cryptoTokenSession.deleteCryptoToken(INTERNAL_ADMIN_TOKEN, subCaCryptoTokenId);
            
            if (caSession.existsCa(DnComponents.getPartFromDN(ROOT_CA_DN, "CN"))) {
                caSession.removeCA(INTERNAL_ADMIN_TOKEN, ROOT_CA_DN.hashCode());
            }
            
            if (caSession.existsCa(DnComponents.getPartFromDN(SUB_CA_DN, "CN"))) {
                caSession.removeCA(INTERNAL_ADMIN_TOKEN, SUB_CA_DN.hashCode());
            }
        } catch (AuthorizationDeniedException e) {
            // should not happen
        }
    }
    
    
    // x509 root ca
    // after uploading the signed certificate, these root CAs become signed by external CA
    private void generateCsrOfRootCa(String keyPairName, String responseFormat) throws Exception {
        
        String caname = DnComponents.getPartFromDN(ROOT_CA_DN, "CN");
        int certificateProfile = CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA;
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(ROOT_CA_DN, caname, CAConstants.CA_ACTIVE, certificateProfile, "3650d",
                CAInfo.SELFSIGNED, null, rootCaToken);
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        try {
            x509ca.setCAToken(rootCaToken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        // A CA certificate
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(rootCaCert);
        x509ca.setCertificateChain(cachain);
        
        caSession.addCA(INTERNAL_ADMIN_TOKEN, x509ca);
        
        GenerateCsrCaRequest requestObject = new GenerateCsrCaRequest();
        requestObject.setKeyPair(keyPairName);
        requestObject.setResponseFormat(responseFormat);
        
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(requestObject);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        Response response = newRequest(CA_GENERATE_CSR_URL.replace("issuer_dn", ROOT_CA_DN)).request().put(requestEntity);
        
        assertEquals(200, response.getStatus());
        
        // read file content
        InputStream inputStream = response.readEntity(InputStream.class);
        byte[] bytes = inputStream.readAllBytes();

        // read and assert file name
        String contentDisposition =
                response.getHeaderString("Content-Disposition");
        if ("PEM".equals(responseFormat)) {
            assertTrue(extractFileNameSuffix(contentDisposition).equals("pem"));
        } else {
            assertTrue(extractFileNameSuffix(contentDisposition).equals("der"));
        }
        
        response.close();
        
        // verify signature existing key  
        PKCS10CertificationRequest csr = "PEM".equals(responseFormat) ? 
                CertTools.getCertificateRequestFromPem(new String(bytes)):
                    new PKCS10CertificationRequest(bytes);
        ContentVerifierProvider verifierProvider =
                            new JcaContentVerifierProviderBuilder()
                                    .setProvider("BC")
                                    .build(rootCaPublicKey);
        boolean isValid = csr.isSignatureValid(verifierProvider);  
        
        // verify signature newly generated key  
        if (keyPairName.equals(GenerateCsrCaRequest.GENERATE_NEW_KEY_INDICATOR)) {
            assertFalse(isValid);
            PublicKey genereatedKey = cryptoTokenManagementProxySession.getPublicKey(rootCaCryptoTokenId, 
                    ROOT_CA_DN + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS + "00001").getPublicKey();
            verifierProvider =
                    new JcaContentVerifierProviderBuilder()
                            .setProvider("BC")
                            .build(genereatedKey);

            isValid = csr.isSignatureValid(verifierProvider);
            assertTrue(isValid);
        } else {
            assertTrue(isValid);
        }

    }
    
    private static String extractFileNameSuffix(String contentDisposition) {
        if (contentDisposition == null) return null;

        for (String part : contentDisposition.split(";")) {
            if (part.trim().startsWith("filename")) {
                String fileName = part.substring(part.indexOf("=")).trim().replace("\"", "");
                return fileName.substring(fileName.lastIndexOf(".")+1);
            }
        }
        return null;
    }
    
    @Test
    public void generateCsrOfRootCa() throws Exception {
        generateCsrOfRootCa(ROOT_CA_DN + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS, "PEM");
    }
    
    @Test
    public void generateCsrOfRootCaDerFormat() throws Exception {
        generateCsrOfRootCa(ROOT_CA_DN + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS, "DER");
    }
    
    @Test
    public void generateCsrOfRootCaGenerateNew() throws Exception {
        generateCsrOfRootCa(GenerateCsrCaRequest.GENERATE_NEW_KEY_INDICATOR, null);
    }
    
    // x509 sub ca + signed by external root
    // CA_UNINITIALIZED can be created by Configdump but not AdminWeb
    private void generateCsrOfSubCa(List<String> certificateChain) throws Exception {
        
        String keyPairName = SUB_CA_DN + "_" + CAToken.SOFTPRIVATESIGNKEYALIAS;
        String responseFormat = "PEM";
        
        String caname = DnComponents.getPartFromDN(SUB_CA_DN, "CN");
        int certificateProfile = CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA;
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(
                SUB_CA_DN, caname, CAConstants.CA_UNINITIALIZED, certificateProfile, "1730d",
                CAInfo.SIGNEDBYEXTERNALCA, null, subCaToken);
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        try {
            x509ca.setCAToken(subCaToken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        
        caSession.addCA(INTERNAL_ADMIN_TOKEN, x509ca);
        
        GenerateCsrCaRequest requestObject = new GenerateCsrCaRequest();
        requestObject.setKeyPair(keyPairName);
        requestObject.setResponseFormat(responseFormat);
        requestObject.setCertificateChain(certificateChain);
        
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(requestObject);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        Response response = newRequest(CA_GENERATE_CSR_URL.replace("issuer_dn", SUB_CA_DN)).request().put(requestEntity);
        
        assertEquals(200, response.getStatus());
        
        // read file content
        InputStream inputStream = response.readEntity(InputStream.class);
        byte[] bytes = inputStream.readAllBytes();

        // read and assert file name
        String contentDisposition =
                response.getHeaderString("Content-Disposition");
        if ("PEM".equals(responseFormat)) {
            assertTrue(extractFileNameSuffix(contentDisposition).equals("pem"));
        } else {
            assertTrue(extractFileNameSuffix(contentDisposition).equals("der"));
        }
        
        response.close();
        
        // verify signature existing key  
        PKCS10CertificationRequest csr = "PEM".equals(responseFormat) ? 
                CertTools.getCertificateRequestFromPem(new String(bytes)):
                    new PKCS10CertificationRequest(bytes);
        ContentVerifierProvider verifierProvider =
                            new JcaContentVerifierProviderBuilder()
                                    .setProvider("BC")
                                    .build(subCaPublicKey);
        boolean isValid = csr.isSignatureValid(verifierProvider);          
        assertTrue(isValid);

        if (certificateChain!=null) {
          CACommon subCa = caTestSessionRemote.getCA(INTERNAL_ADMIN_TOKEN, SUB_CA_DN.hashCode());
          assertEquals(subCa.getRequestCertificateChain().toArray()[0], rootCaCert);
        }
    }
    
    @Test
    public void generateCsrOfSubCa() throws Exception {
        generateCsrOfSubCa(null);
    }
    
    @Test
    public void generateCsrOfSubCaWithSingleCertificateInUploadedChain() throws Exception {
        generateCsrOfSubCa(List.of(CertTools.getPemFromCertificate(rootCaCert)));
    }

    @Test
    public void errorNonExistentKey() throws Exception {
        
        String caname = DnComponents.getPartFromDN(ROOT_CA_DN, "CN");
        int certificateProfile = CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA;
        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(ROOT_CA_DN, caname, CAConstants.CA_ACTIVE, certificateProfile, "3650d",
                CAInfo.SELFSIGNED, null, rootCaToken);
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        try {
            x509ca.setCAToken(rootCaToken);
        } catch (InvalidAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        // A CA certificate
        List<Certificate> cachain = new ArrayList<>();
        cachain.add(rootCaCert);
        x509ca.setCertificateChain(cachain);
        
        caSession.addCA(INTERNAL_ADMIN_TOKEN, x509ca);
        
        GenerateCsrCaRequest requestObject = new GenerateCsrCaRequest();
        requestObject.setKeyPair("unknown");
        
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(requestObject);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        Response response = newRequest(CA_GENERATE_CSR_URL.replace("issuer_dn", ROOT_CA_DN)).request().put(requestEntity);
        
        assertEquals(400, response.getStatus());
        assertTrue(response.readEntity(String.class).contains("CA cryptotoken is offline or the key pair not found."));
    }
    
    @Test
    public void errorNonExistentCa() throws Exception {
        GenerateCsrCaRequest requestObject = new GenerateCsrCaRequest();
        requestObject.setKeyPair("signKey");
        
        final ObjectMapper objectMapper = objectMapperContextResolver.getContext(null);
        final String requestBody = objectMapper.writeValueAsString(requestObject);
        final Entity<String> requestEntity = Entity.entity(requestBody, MediaType.APPLICATION_JSON);
        Response response = newRequest(CA_GENERATE_CSR_URL.replace("issuer_dn", "CN=Unknown")).request().put(requestEntity);
        
        assertEquals(400, response.getStatus());
        assertTrue(response.readEntity(String.class).contains("CA with DN: CN=Unknown does not exist."));
    }

}
