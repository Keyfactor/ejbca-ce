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
package org.ejbca.ra;

import com.keyfactor.util.CertTools;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.ra.dto.InspectType;
import org.ejbca.ra.dto.InspectedObject;

import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.Part;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;
import java.util.Objects;
import java.util.function.Supplier;
import java.util.stream.Collectors;

/**
 * Managed bean that backs up the inspect.xhtml page.
 */
@Named
@ViewScoped
public class RaInspectBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final long MAX_FILE_SIZE_IN_BYTES = 1048576L; // 1 MB
    private static final String LABEL_UNKNOWN_TYPE = "inspect_page_unknown_type";
    private static final String ERROR_LABEL_FILE_EMPTY = "inspect_page_error_file_empty";
    private static final String ERROR_LABEL_FILE_SIZE = "inspect_page_error_file_size";
    private static final Logger log = Logger.getLogger(RaInspectBean.class);

    @Inject
    private RaLocaleBean raLocaleBean;

    private transient Part uploadedFile;
    private String uploadedPlainTextContent;
    private InspectedObject inspectedObject;
    private boolean showInspectionResults;

    public void processPlainTextContent() {
        inspect(uploadedPlainTextContent.getBytes());
    }

    public void processFile() {
        if (checkFileSize(uploadedFile.getSize())) {
            final byte[] uploadedFileBytes = getBytesFromPart(uploadedFile);
            inspect(uploadedFileBytes);
        }
    }

    /**
     * Inspects the submitted plain text content or file and populates attributes of the inspectedObject.
     *
     * @param bytes bytes to inspect
     */
    private void inspect(final byte[] bytes) {
        final List<Supplier<InspectedObject>> objectDetectionMethods = List.of(
                () -> detectCvcObject(bytes),
                () -> detectPkcs10CertificationRequest(bytes),
                () -> detectX509Certificate(bytes),
                () -> detectAsn1Object(bytes)
        );

        inspectedObject = objectDetectionMethods.stream()
                .map(Supplier::get) // execute the method
                .filter(Objects::nonNull)
                .findFirst() // terminate as soon as the first non-null result is returned, without invoking the next method
                .orElse(unknownObject());

        // add common attributes
        inspectedObject.setFingerprintSha1(CertTools.getFingerprintAsString(bytes));
        inspectedObject.setFingerprintSha256(CertTools.getSHA256FingerprintAsString(bytes));

        if (inspectedObject.getSerialNumberHex() != null) {
            final String serialNumberDecimal = new BigInteger(inspectedObject.getSerialNumberHex(), 16).toString();
            inspectedObject.setSerialNumberDecimal(serialNumberDecimal);
        }

        if (uploadedFile != null) {
            inspectedObject.setFilename(uploadedFile.getSubmittedFileName());
        }

        showInspectionResults = true;
    }

    /**
     * Detects if the submitted bytes are a CVC object.
     *
     * @param bytes bytes to inspect
     * @return InspectedObject if the bytes are a CVC object, null otherwise
     */
    public InspectedObject detectCvcObject(final byte[] bytes) {
        CVCObject cvcObject;
        String serialNumber = null;
        final byte[] decodedBytes = RequestMessageUtils.getDecodedBytes(bytes);
        try {
            cvcObject = CertificateParser.parseCVCObject(decodedBytes);
        } catch (Exception e) {
            // this was not parseable, try to see if it was a PEM certificate
            try {
                final Certificate certificate = CertTools.getCertsFromPEM(new ByteArrayInputStream(decodedBytes), Certificate.class).get(0);
                cvcObject = CertificateParser.parseCVCObject(certificate.getEncoded());
                serialNumber = CertTools.getSerialNumberAsString(certificate);
            } catch (Exception e2) {
                // this was not a PEM cert, try to see if it was a PEM certificate request
                try {
                    final byte[] req = RequestMessageUtils.getRequestBytes(decodedBytes);
                    cvcObject = CertificateParser.parseCVCObject(req);
                } catch (Exception e3) {
                    // ignore & move on to the next type
                    return null;
                }
            }
        }
        return InspectedObject.builder()
                .type(InspectType.CVC)
                .content(cvcObject.getAsText(""))
                .serialNumberHex(serialNumber)
                .build();
    }

    /**
     * Detects if the submitted bytes are a PKCS#10 certification request.
     *
     * @param bytes bytes to inspect
     * @return InspectedObject if the bytes are a PKCS#10 certification request, null otherwise
     */
    private InspectedObject detectPkcs10CertificationRequest(final byte[] bytes) {
        final byte[] decodedBytes = RequestMessageUtils.getDecodedBytes(bytes);
        try {
            final PKCS10CertificationRequest pkcs10 = new PKCS10CertificationRequest(decodedBytes);
            final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(pkcs10.getEncoded()));
            final ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            asn1InputStream.close();
            final String dump = ASN1Dump.dumpAsString(asn1Primitive);
            return InspectedObject.builder()
                    .type(InspectType.PKCS10)
                    .content(dump)
                    .build();
        } catch (IOException | IllegalArgumentException | ClassCastException e) {
            // ignore & move on to the next type
            return null;
        }
    }

    /**
     * Detects if the submitted bytes are an X.509 certificate.
     *
     * @param bytes bytes to inspect
     * @return InspectedObject if the bytes are an X.509 certificate, null otherwise
     */
    private InspectedObject detectX509Certificate(final byte[] bytes) {
        Certificate certificate;
        try {
            certificate = CertTools.getCertsFromPEM(new ByteArrayInputStream(bytes), Certificate.class).get(0);
        } catch (CertificateException e) {
            // See if it's a single binary certificate
            try {
                certificate = CertTools.getCertfromByteArray(bytes, Certificate.class);
            } catch (CertificateException e1) {
                // ignore & move on to the next type
                return null;
            }
        }
        if (certificate != null) {
            final String dump = CertTools.dumpCertificateAsString(certificate);
            final String serialNumber = CertTools.getSerialNumberAsString(certificate);
            return InspectedObject.builder()
                    .type(InspectType.X509)
                    .content(dump)
                    .serialNumberHex(serialNumber)
                    .build();
        }
        return null;
    }

    /**
     * Detects if the submitted bytes are an ASN.1 object.
     *
     * @param bytes bytes to inspect
     * @return InspectedObject if the bytes are an ASN.1 object, null otherwise
     */
    private InspectedObject detectAsn1Object(final byte[] bytes) {
        try {
            final ASN1InputStream asn1InputStream = new ASN1InputStream(new ByteArrayInputStream(bytes));
            final ASN1Primitive asn1Primitive = asn1InputStream.readObject();
            asn1InputStream.close();
            final String dump = ASN1Dump.dumpAsString(asn1Primitive);
            return InspectedObject.builder()
                    .type(InspectType.ASN1)
                    .content(dump)
                    .build();
        } catch (IOException | IllegalArgumentException | ClassCastException e) {
            // ignore & move on to the next type
            return null;
        }
    }

    /**
     * Resets the bean to its initial state.
     */
    public void reset() {
        uploadedPlainTextContent = null;
        uploadedFile = null;
        inspectedObject = null;
        showInspectionResults = false;
    }

    /**
     * Utility method for getting bytes of the submitted file.
     *
     * @param part file submitted for inspection
     * @return file bytes
     */
    private byte[] getBytesFromPart(final Part part) {
        try (InputStream inputStream = part.getInputStream()) {
            return IOUtils.toByteArray(inputStream, part.getSize());
        } catch (IOException e) {
            log.error("Error reading bytes from file " + part.getSubmittedFileName() + ": " + e.getMessage());
        }
        return new byte[0];
    }

    /**
     * Checks if the submitted file is empty or exceeds the maximum allowed size.
     *
     * @param sizeInBytes file size in bytes
     * @return true if the file is not empty and does not exceed the maximum allowed size, false otherwise
     */
    private boolean checkFileSize(final long sizeInBytes) {
        if (sizeInBytes > MAX_FILE_SIZE_IN_BYTES) {
            final String displaySize = FileUtils.byteCountToDisplaySize(MAX_FILE_SIZE_IN_BYTES);
            raLocaleBean.addMessageError(ERROR_LABEL_FILE_SIZE, displaySize);
            return false;
        } else if (sizeInBytes == 0) {
            raLocaleBean.addMessageError(ERROR_LABEL_FILE_EMPTY);
            return false;
        }
        return true;
    }

    /**
     * Returns an InspectedObject of type UNKNOWN.
     * Used when the uploaded content can't be parsed to a Certificate or CSR.
     *
     * @return InspectedObject of type UNKNOWN
     */
    private InspectedObject unknownObject() {
        final String supportedTypes = InspectType.getSupportedTypes().stream()
                .map(InspectType::getName)
                .collect(Collectors.joining(", "));
        final String message = raLocaleBean.getMessage(LABEL_UNKNOWN_TYPE, supportedTypes);
        return InspectedObject.builder()
                .type(InspectType.UNKNOWN)
                .content(message)
                .build();
    }

    public RaLocaleBean getRaLocaleBean() {
        return raLocaleBean;
    }

    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    public Part getUploadedFile() {
        return uploadedFile;
    }

    public void setUploadedFile(final Part uploadedFile) {
        this.uploadedFile = uploadedFile;
    }

    public String getUploadedPlainTextContent() {
        return uploadedPlainTextContent;
    }

    public void setUploadedPlainTextContent(final String uploadedPlainTextContent) {
        this.uploadedPlainTextContent = uploadedPlainTextContent;
    }

    public boolean isShowInspectionResults() {
        return showInspectionResults;
    }

    public void setShowInspectionResults(final boolean showInspectionResults) {
        this.showInspectionResults = showInspectionResults;
    }

    public InspectedObject getInspectedObject() {
        return inspectedObject;
    }
}
