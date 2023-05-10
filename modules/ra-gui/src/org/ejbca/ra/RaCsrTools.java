package org.ejbca.ra;

import com.keyfactor.util.certificate.DnComponents;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.model.era.KeyToValueHolder;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import javax.faces.application.FacesMessage;
import javax.faces.validator.ValidatorException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.List;

public class RaCsrTools {
    private static final Logger log = Logger.getLogger(RaCsrTools.class);

    public static void validateCsr(Object value, EnrollWithRequestIdBean bean, RaLocaleBean raLocaleBean,
                                     final CertificateProfile certificateProfile, String usernameOrId, boolean isUsername) throws ValidatorException {
        bean.setSelectedAlgorithm(null);
        final String valueStr = value.toString();
        if (valueStr != null && valueStr.length() > EnrollMakeNewRequestBean.MAX_CSR_LENGTH) {
            log.info("CSR uploaded was too large: "+valueStr.length());
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_certificate_request")));
        }
        RequestMessage certRequest = RequestMessageUtils.parseRequestMessage(valueStr.getBytes());
        if (certRequest == null) {
            throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_certificate_request")));
        }
        //Get public key algorithm from CSR and check if it's allowed in certificate profile or by PQC configuration
        try {
            final String keySpecification = AlgorithmTools.getKeySpecification(certRequest.getRequestPublicKey());
            final String keyAlgorithm = AlgorithmTools.getKeyAlgorithm(certRequest.getRequestPublicKey());
            if (AlgorithmTools.isPQC(keyAlgorithm) && !WebConfiguration.isPQCEnabled()) {
                throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_key_algorithm_is_not_available", getKeyAlgorithmMessageString(keyAlgorithm, keySpecification))));
            }
            // If we have an End Entity, use this to verify that the algorithm and keyspec are allowed
            if (certificateProfile != null) {
                if (!certificateProfile.isKeyTypeAllowed(keyAlgorithm, keySpecification)) {
                    throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_key_algorithm_is_not_available", keyAlgorithm + "_" + keySpecification)));
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Ignoring algorithm validation on CSR because we can not find a Certificate Profile for "
                             + (isUsername ? "user: " : "request with ID: ")
                            + usernameOrId);
                }
            }
            bean.setSelectedAlgorithm(keyAlgorithm + " " + keySpecification);
            bean.setCertificateRequest(valueStr);
            bean.setAlgorithmUiRepresentationString(keyAlgorithm, keySpecification);
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            final String msg = raLocaleBean.getMessage("enroll_unknown_key_algorithm");
            if (log.isDebugEnabled()) {
                log.debug(msg + ": " + e.getMessage());
            }
            throw new ValidatorException(new FacesMessage(msg));
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e.getMessage());
        }
    }
    
    private static String getKeyAlgorithmMessageString(String alg, String spec ) {
        return alg.equals(spec)? alg : alg + "_" + spec;
    }

    public static void validetaNumberOfFieldsInSubjectDn(final KeyToValueHolder<EndEntityProfile> endEntityProfileKeyValue, String certificateRequest,
                                                         RaLocaleBean raLocaleBean, String usernameOrId, boolean isUsername) {
        if (endEntityProfileKeyValue != null) {
            EndEntityProfile endEntityProfile = endEntityProfileKeyValue.getValue();
            final RequestMessage certRequest = RequestMessageUtils.parseRequestMessage(certificateRequest.getBytes(StandardCharsets.UTF_8));
            String subject = certRequest.getRequestX500Name().toString();
            final DNFieldExtractor subjectDnFields = new DNFieldExtractor(subject, DNFieldExtractor.TYPE_SUBJECTDN);
            final List<String> dnFields = DnComponents.getDnProfileFields();
            final List<Integer> dnFieldExtractorIds = DnComponents.getDnDnIds();
            for (int i = 0; i < dnFields.size(); i++) {
                if (endEntityProfile.getNumberOfField(dnFields.get(i)) < subjectDnFields.getNumberOfFields(dnFieldExtractorIds.get(i))) {
                    throw new ValidatorException(new FacesMessage(raLocaleBean.getMessage("enroll_invalid_number_of_subjectdn_fields_in_request",  dnFields.get(i))));
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Ignoring subject DN validation on CSR because we can not find a End Entity Profile for "
                        + (isUsername ? "user: " : "request with ID: ")
                        + usernameOrId);
            }
        }
    }
}
