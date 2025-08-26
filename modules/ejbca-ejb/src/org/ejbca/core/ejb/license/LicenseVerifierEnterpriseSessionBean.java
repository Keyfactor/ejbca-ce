/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.ejb.license;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.time.Period;
import java.time.ZonedDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Set;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.license.model.License;
import org.ejbca.core.ejb.license.model.LicenseData;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import jakarta.ejb.EJB;
import jakarta.ejb.Schedule;
import jakarta.ejb.Singleton;
import jakarta.ejb.Startup;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import jakarta.xml.bind.JAXBContext;
import jakarta.xml.bind.JAXBException;

@Singleton
@Startup
public class LicenseVerifierEnterpriseSessionBean {
    
    private static final Logger log = Logger.getLogger(LicenseVerifierEnterpriseSessionBean.class);
    
    private static final String LICENCE_VERIFIER_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
                    + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1c186+3rkphInBdHUn4Z\n"
                    + "oWs1jehDnm3pys8nF2fByIQNhi60OvD2jpp+QlVMJCcUFe/O1LeG+CRFK1Z6fCVE\n"
                    + "r51mZR0XmUrrJ/EIPmDK87iLOKiEQ6frBlpeKt2+8LsF6OXJT0dyswk1QRLEurxG\n"
                    + "/pRHqnbegmcL3IZY7k1+L0iXR5hl6JfpBZbF78LfykvuzVMNZC97DpjlRACyz4CW\n"
                    + "fJ5SguVspJDiWofGMa9g7CjlV1NnYQ5Ca0uw7bXoF2x4Oui77atXzGeZy428zrzc\n"
                    + "V9Ut0N7UfSlgV2rE1QRhIkkMivXUaz6od7ZjQMQ7+OrKuffCspJ3y5eiSR6QVYrk\n"
                    + "MwIDAQAB\n"
                    + "-----END PUBLIC KEY-----";
    
    private static final String LICENCE_FILE_PATH = "/mnt/licence/ejbca-licence";
    
    private static final PublicKey LICENSE_VERIFIER_KEY = getPublicKeyFromPem();
    
    private static final int SOON_TO_EXPIRE_DAYS = 90;
    private static final int EXPIRED_TOO_LONG_DAYS = 100;
    
    @EJB
    private AuthorizationSessionLocal authorizationSession;
    
    private static int startUpCountDown = 3;
        
    @Schedule(hour = "*", minute = "*/1", persistent = false)
    public void runEveryMinute() {
        startUpCountDown--;
        log.info("EJBCA license check timer triggered: " + java.time.LocalDateTime.now());
        if (!EjbcaConfiguration.getIsInProductionMode() || startUpCountDown>0) {
        //if(startUpCountDown>0) {
            return;
        }
        
        boolean publicAccessEnabled = 
                authorizationSession.isAuthorizedNoLogging(new PublicAccessAuthenticationToken("LicenseVerifier", true), "/");
        log.info("EJBCA license check publicAccessEnabled: " + publicAccessEnabled);
        
        String licenseContent = readLicenseFile();
        if (licenseContent!=null) {
            validateLicense(licenseContent);
        }
        
        if (!publicAccessEnabled) {
            executeFailureFunction();
        }
    }
    
    private static String readLicenseFile() {
        Path path = Paths.get(LICENCE_FILE_PATH);
        if (!Files.exists(path)) {
            prepareFailureAction(LicenseState.MISSING);
            return null;
        }
        String content = null;
        try {
            content = Files.readString(path); // assume UTF-8
        } catch (IOException e) {
            log.error("File ", e);
        }
        if (content==null || content.length() < 100) {
            prepareFailureAction(LicenseState.MISSING);
            return null;
        } 
        return content;
    }
    
    private static void prepareFailureAction(LicenseState licenseState) {
        LicenseStateContainer.setLicenseState(licenseState);
        if (licenseState!=LicenseState.VALID) {
            decorateLicenseErrorMessage("EJBCA license " + licenseState.getStatusMessage() 
                                            + ". Please contact xxxx@keyfactor.com to renew license.");
        }
    }
    
    private static void executeFailureFunction() {
        if (System.getenv("SHOOT_MY_FOOT")!=null && System.getenv("NO_LICENSE_PUBLIC_ACCESS")==null &&
                LicenseStateContainer.getLicenseState() == LicenseState.EXPIRED_LONG_BACK) {
            decorateLicenseErrorMessage("EJBCA license is expired more than 3 months ago. Shutting down...");
            System.exit(1);
        }
    }
    
    private static void decorateLicenseErrorMessage(String message) {
        StringBuilder sb = new StringBuilder();
        final String banner = "###########################################################################";
        List.of(banner, banner, banner, "", message, "", banner, banner, banner).forEach(x -> {log.error(x); sb.append(x + "<br>");} );
        LicenseStateContainer.setLicenseInvalidWarning(sb.toString());
    }
    

    
    protected void validateLicense(String licenseContent) {
        byte[] licenseBytes = licenseContent.getBytes(StandardCharsets.UTF_8);
        Element doc;
        LicenseData license = null;
        doc = verifyXml(new ByteArrayInputStream(licenseBytes));
        if (doc == null) {
            return;
        }
        
        license = parse(doc);
        if (license == null) {
            return;
        }
        
        ValidatorFactory factory = Validation.byDefaultProvider()
                .configure()
                .messageInterpolator(new ParameterMessageInterpolator())
                .buildValidatorFactory();

        Validator validator = factory.getValidator();
        Set<ConstraintViolation<LicenseData>> violations = validator.validate(license);
        Period soonToExpireCheck = Period.between(ZonedDateTime.now().plusDays(SOON_TO_EXPIRE_DAYS).toLocalDate(),
                                                                license.getLicense().getExpirationDate().toLocalDate());
        if (violations.isEmpty()) {
            LicenseStateContainer.setLicenseState(LicenseState.VALID);
            if (soonToExpireCheck.isNegative()) {
                prepareFailureAction(LicenseState.TO_BE_EXPIRED);
            }
            return;
        }
        
        if (violations.stream().anyMatch(v -> v.getMessage().equals(License.LICENSE_EXPIRED))) {
            Period expireLongBackCheck = Period.between(ZonedDateTime.now().minusDays(EXPIRED_TOO_LONG_DAYS).toLocalDate(),
                    license.getLicense().getExpirationDate().toLocalDate());
            if (expireLongBackCheck.isNegative()) {
                prepareFailureAction(LicenseState.EXPIRED_LONG_BACK);
            } else {
                prepareFailureAction(LicenseState.EXPIRED);
            }
        } else {
            prepareFailureAction(LicenseState.INVALID);
        }
        return;
    }

    private LicenseData parse(Node node) {
        JAXBContext context;
        try {
            context = JAXBContext.newInstance(LicenseData.class);
            return (LicenseData) context.createUnmarshaller().unmarshal(node);
        } catch (JAXBException e) {
            log.error("Could not create xml parser", e);
            prepareFailureAction(LicenseState.EJBCA_SETUP_INVALID);
            return null;
        }
    }
    
    private Element verifyXml(InputStream xml) {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = null;
        try {
            dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
            dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            dbf.setNamespaceAware(true);
            builder = dbf.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            log.info("Could not create xml parser", e);
            prepareFailureAction(LicenseState.EJBCA_SETUP_INVALID);
            return null;
        }
        Document doc;
        try {
            doc = builder.parse(xml);
        } catch (Exception e) {
            log.info("Could not parse xml", e);
            prepareFailureAction(LicenseState.INVALID);
            return null;
        }
        NodeList nl = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl.getLength() == 0) {
            log.info("No signature found");
            prepareFailureAction(LicenseState.INVALID);
            return null;
        }

        XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

        for (int i = 0; i < nl.getLength(); i++) {
            if (isValid(nl.item(i), factory)) {
                return doc.getDocumentElement();
            }
        }
        log.info("Reject license. Could not verify Signature.");
        prepareFailureAction(LicenseState.INVALID);
        return null;
    }
    
    private static PublicKey getPublicKeyFromPem() {
        
        String keyPem = LICENCE_VERIFIER_KEY_PEM
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        
        byte[] encoded = Base64.getDecoder().decode(keyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // Ignore
        }
        
        log.info("Unable to parse license verification key.");
        prepareFailureAction(LicenseState.EJBCA_SETUP_INVALID);
        return null;
    }

    private boolean isValid(Node node, XMLSignatureFactory factory) {
        try {
            DOMValidateContext valContext = new DOMValidateContext(new KeySelector() {
                @Override
                public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) {
                    return () -> LICENSE_VERIFIER_KEY;
                }
            }, node);
            valContext.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
            XMLSignature signature = factory.unmarshalXMLSignature(valContext);
            return signature.validate(valContext);
        } catch (MarshalException e) {
            log.info("Could not parse signature in  xml", e);
            prepareFailureAction(LicenseState.INVALID);
        } catch (XMLSignatureException e) {
            log.info("Could not validate signature in xml", e);
            prepareFailureAction(LicenseState.INVALID);
        }
        return false;
    }

}
