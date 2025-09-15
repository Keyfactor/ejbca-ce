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
import org.cesecore.license.LicenseState;
import org.cesecore.license.LicenseStateContainer;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.license.model.License;
import org.ejbca.core.ejb.license.model.LicenseData;
import org.hibernate.validator.messageinterpolation.ParameterMessageInterpolator;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.keyfactor.util.CertTools;

import jakarta.annotation.PostConstruct;
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
    
    // see GenerateExampleLicense
    protected static String LICENCE_VERIFIER_KEY_PEM_NON_PRODUCTION = "-----BEGIN PUBLIC KEY-----\n"
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3cmMoNUCZ8ibP+znRrzH\n"
            + "rb/3gwsjH+6qs7yx4ctp/wARkyEUJycBBAoRjzDtTRjsQ5630LLtwPtBAzoSHgn5\n"
            + "jHQdOQmKo07VZVORKAeseLSbXemtIfgn7jEwTDw6i+fN7gzcY5VpUMGsPANZMfdn\n"
            + "4tQipResD37IC36/N4K3Y3dWmWOKtE8iGR+Phh85+q9WHTKe95TiyVVsSznh4CG2\n"
            + "IDmuqZZZniauM+Fd0BR7QGbZFwiBLAgikjodTjouDyyjL3piL4JgUN6csqFeaHwv\n"
            + "hr+/UcuU56g/wo14wrch1hbtIeiF3xOmxwC5KmCzrlPUGwRLiabjuY4XAlufIK0A\n"
            + "cwIDAQAB\n"
            + "-----END PUBLIC KEY-----";
        
    private static PublicKey licenseVerificationKey;
    private static final String LICENCE_FILE_PATH = "/mnt/license/ejbca-license";
            
    private static final int EXPIRED_TOO_LONG_DAYS = 100;
    
    private static final String LICENSE_MISSING_MESSAGE = "No license file is provided. Shutting down EJBCA...";
     
    @PostConstruct
    public void init() {
        // Run immediately at startup
        log.debug("EJBCA license check timer triggered immediate: " + java.time.LocalDateTime.now());
        validateLicenseInBackground();
    }
        
    @Schedule(hour = "*", minute = "*/1", persistent = false)
    public void validateLicenseInBackground() {
        log.debug("EJBCA license check timer triggered: " + java.time.LocalDateTime.now());
        
        String licenseContent = readLicenseFile();
        if (licenseContent!=null) {
            validateLicense(licenseContent);
        } else {
            if (!EjbcaConfiguration.getIsInProductionMode()) {
                log.debug("EJBCA license is missing in non-production mode. ignoring...");
                return;
            }
            decorateLicenseErrorMessage(LICENSE_MISSING_MESSAGE);
            System.exit(1);
        }
        
    }
    
    private static String readLicenseFile() {
        Path path = Paths.get(LICENCE_FILE_PATH);
        if (!Files.exists(path)) {
            return null;
        }
        String content = null;
        try {
            content = Files.readString(path); // assume UTF-8
        } catch (IOException e) {
            log.info("File could not be read", e);
        }
        if (content==null || content.length() < 100) {
            return null;
        } 
        return content;
    }
    
    private static void prepareFailureAction(LicenseState licenseState) {
        LicenseStateContainer.setLicenseState(licenseState);
        if (licenseState!=LicenseState.VALID) {
            decorateLicenseErrorMessage(licenseState.getStatusMessage() 
                                            + ". Please contact xxxx@keyfactor.com to renew license.");
        }
    }
    
    private static void decorateLicenseErrorMessage(String message) {
        StringBuilder sb = new StringBuilder();
        final String banner = "###########################################################################";
        List.of(banner, banner, banner, "", message, "", banner, banner, banner).forEach(log::error);
        List.of(banner, "", message, "", banner ).forEach(x -> sb.append("<b>" + x + "</b><br>"));
        LicenseStateContainer.setLicenseInvalidWarning(sb.toString());
    }
    
    protected void validateLicense(String licenseContent) {
        
        if (licenseVerificationKey==null) {
            if (EjbcaConfiguration.getIsInProductionMode()) {
                readPublicKeyFromPem(LICENCE_VERIFIER_KEY_PEM);
            } else {
                readPublicKeyFromPem(LICENCE_VERIFIER_KEY_PEM_NON_PRODUCTION);
            }
        }
                
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
        
        if (violations.isEmpty()) {
            Period soonToExpireCheck = Period.between(ZonedDateTime.now().toLocalDate(),
                    license.getLicense().getExpirationDate().toLocalDate());
            
            if (soonToExpireCheck.getDays() < 5) {
                prepareFailureAction(LicenseState.TO_BE_EXPIRED_5_DAYS);
            } else if (soonToExpireCheck.getDays() < 30) {
                prepareFailureAction(LicenseState.TO_BE_EXPIRED_30_DAYS);
            } else if (soonToExpireCheck.getDays() < 60) {
                prepareFailureAction(LicenseState.TO_BE_EXPIRED_60_DAYS);
            } else {
                LicenseStateContainer.setLicenseState(LicenseState.VALID);
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
            log.info("Could not create xml parser", e);
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
        } catch (SAXException | IOException e) {
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
    
    private static void readPublicKeyFromPem(String pemContent) {
        
        String keyPem = pemContent
                .replace(CertTools.BEGIN_PUBLIC_KEY, "")
                .replace(CertTools.END_PUBLIC_KEY, "")
                .replaceAll("\\s", "");
        
        byte[] encoded = Base64.getDecoder().decode(keyPem);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance("RSA");
            licenseVerificationKey = keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            log.info("Unable to parse license verification key.");
            prepareFailureAction(LicenseState.EJBCA_SETUP_INVALID);
        }
        
    }

    private boolean isValid(Node node, XMLSignatureFactory factory) {
        try {
            DOMValidateContext valContext = new DOMValidateContext(new KeySelector() {
                @Override
                public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method, XMLCryptoContext context) {
                    return () -> licenseVerificationKey;
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
