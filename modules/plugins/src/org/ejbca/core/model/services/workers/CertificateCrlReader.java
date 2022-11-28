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
package org.ejbca.core.model.services.workers;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.collections4.BidiMap;
import org.apache.commons.collections4.bidimap.TreeBidiMap;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.crl.CrlStoreException;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.LookAheadObjectInputStream;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.CustomServiceWorkerProperty;
import org.ejbca.core.model.services.CustomServiceWorkerUiSupport;
import org.ejbca.core.model.services.ServiceExecutionFailedException;
import org.ejbca.core.model.services.ServiceExecutionResult;
import org.ejbca.core.model.services.ServiceExecutionResult.Result;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.scp.publisher.ScpContainer;

/**
 * This custom worker reads Certificates and CRLs from a local directory periodically and inserts them into the database. 
 * 
 * @version $Id$
 *
 */
public class CertificateCrlReader extends BaseWorker implements CustomServiceWorkerUiSupport {

    private static final Logger log = Logger.getLogger(CertificateCrlReader.class);

    public static final String CERTIFICATE_DIRECTORY_KEY = "certificate.directory";
    public static final String CRL_DIRECTORY_KEY = "crl.directory";
    public static final String SIGNING_CA_ID_KEY = "signing.ca.id";

    private final JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder;

    public CertificateCrlReader() {
        super();
        try {
            jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME);
        } catch (OperatorCreationException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public List<CustomServiceWorkerProperty> getCustomUiPropertyList(AuthenticationToken authenticationToken, Properties currentProperties,
            Map<String, String> languageResource) {
        final List<CustomServiceWorkerProperty> workerProperties = new ArrayList<>();
        workerProperties.add(new CustomServiceWorkerProperty(CERTIFICATE_DIRECTORY_KEY, CustomServiceWorkerProperty.UI_TEXTINPUT,
                getCertificateDirectory(currentProperties)));
        workerProperties.add(
                new CustomServiceWorkerProperty(CRL_DIRECTORY_KEY, CustomServiceWorkerProperty.UI_TEXTINPUT, getCRLDirectory(currentProperties)));

        final CaSessionLocal caSession = new EjbLocalHelper().getCaSession();
        final Collection<String> caNames = caSession.getAuthorizedCaNames(authenticationToken);
        final List<String> authorizedCaNames = (caNames != null ? new ArrayList<>(caNames) : new ArrayList<>());
        Collections.sort(authorizedCaNames, String.CASE_INSENSITIVE_ORDER);
        final Map<Integer, String> caIdToNameMap = caSession.getCAIdToNameMap();
        // We need two sorted lists, both CAIds and name, so this gets a bit convoluted because we use two different ArrayLists to worker properties
        // Another way of sorting, which gets CA names per CA ID, can be found in OcspResponseUpdaterWorker, 
        // just to show that there are different ways to do the same thing :-) 
        final BidiMap<Integer, String> idNameBidiMap = new TreeBidiMap<>(caIdToNameMap);
        caIdToNameMap.entrySet();
        final List<String> authorizedCaIds = new ArrayList<>();
        for (String caName : authorizedCaNames) {
            final Integer id = (Integer)idNameBidiMap.getKey(caName); // belt and suspenders
            authorizedCaIds.add(id != null ? id.toString() : "-1");
        }
        // "None" CA first in list
        authorizedCaIds.add(0,"-1");
        authorizedCaNames.add(0, "None");
        final int caId = getCaId(currentProperties);
        workerProperties.add(new CustomServiceWorkerProperty(SIGNING_CA_ID_KEY, CustomServiceWorkerProperty.UI_SELECTONE, authorizedCaIds,
                authorizedCaNames, Integer.valueOf(caId).toString()));

        return workerProperties;
    }

    @Override
    public void canWorkerRun(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        File certificateDirectory = getDirectory(getCertificateDirectory(properties));;
        File crlDirectory = getDirectory(getCRLDirectory(properties));
        if (certificateDirectory != null) {
            if (!certificateDirectory.canRead() || !certificateDirectory.canWrite()) {
                throw new ServiceExecutionFailedException("Certificate Reader lacks read and/or write rights to directory " + certificateDirectory);
            }
            final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
            int caId = getCaId(properties);
            if (caId != -1) {
                try {
                    caSession.getCAInfo(admin, getCaId(properties));
                } catch (AuthorizationDeniedException e) {
                    throw new ServiceExecutionFailedException("Certificate Reader does not have access to CA with id " + getCaId(properties));
                }
            }
        }
        if (crlDirectory != null) {
            if (!crlDirectory.canRead() || !crlDirectory.canWrite()) {
                throw new ServiceExecutionFailedException("Certificate Reader lacks read and/or write rights to directory " + crlDirectory);
            }
        }
    
    }
    
    @Override
    public ServiceExecutionResult work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
        // Read certificate directory
        File certificateDirectory = getDirectory(getCertificateDirectory(properties));
        File crlDirectory = getDirectory(getCRLDirectory(properties));
        List<String> failedFiles = new ArrayList<>();       
        int readCertificates = 0;
        int readCrls = 0;
        if (certificateDirectory != null) {
            if (!certificateDirectory.canRead() || !certificateDirectory.canWrite()) {
                throw new ServiceExecutionFailedException("Certificate Reader lacks read and/or write rights to directory " + certificateDirectory);
            }
            final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
            int caId = getCaId(properties);
            List<Certificate> caChain;
            if (caId != -1) {
                CAInfo signingCa;
                try {
                    signingCa = caSession.getCAInfo(admin, getCaId(properties));
                } catch (AuthorizationDeniedException e) {
                    throw new ServiceExecutionFailedException("Certificate Reader does not have access to CA with id " + getCaId(properties));
                }
                caChain = signingCa.getCertificateChain();
            } else {
                caChain = null;
            }
            for (final File file : certificateDirectory.listFiles()) {
                final String fileName = file.getName();
                byte[] signedData;
                try {
                    signedData = getFileFromDisk(file);
                } catch (IOException e) {
                    log.error("File '" + fileName + "' could not be read.");
                    failedFiles.add(fileName);
                    continue;
                }

                byte[] data;
                try {
                    data = getAndVerifySignedData(signedData, caChain);
                } catch (SignatureException | CertificateException e) {
                    log.error("Could not get/verify signed certificate file. Certificate saved in file " + fileName, e);
                    failedFiles.add(fileName);
                    continue;
                }
                if (log.isDebugEnabled()) {
                    log.debug("File '" + fileName + "' successfully verified");
                }
                try {
                    storeCertificate(ejbs, data);
                    readCertificates++;
                    file.delete();
                } catch (AuthorizationDeniedException e) {
                    log.error("Service not authorized to store certificates in database. Certificate saved in file " + fileName, e);
                    continue;
                } catch(ServiceExecutionFailedException e) {
                    log.error("Could not store certificate " + fileName + " in the database.", e);
                    failedFiles.add(fileName);
                    continue;
                }
                
                if (log.isDebugEnabled()) {
                    log.debug("File '" + fileName + "' successfully decoded");
                }

            }

        }
        if (crlDirectory != null) {
            if (!crlDirectory.canRead() || !crlDirectory.canWrite()) {
                throw new ServiceExecutionFailedException("Certificate Reader lacks read and/or write rights to directory " + crlDirectory);
            }
            for (final File file : crlDirectory.listFiles()) {
                final String fileName = file.getName();
                byte[] crlData = null;
                try {
                    crlData = getFileFromDisk(file);
                } catch (IOException e) {
                    log.error("File '" + fileName + "' could not be read.");
                    failedFiles.add(fileName);
                    continue;
                }
                try {
                    storeCrl(ejbs, crlData);
                    readCrls++;
                    file.delete();
                } catch (CRLException e) {
                    log.error("CRL could not be stored on the database. CRL stored in file " + fileName, e);
                    failedFiles.add(fileName);
                    continue;
                } catch (CADoesntExistsException e) {
                    log.error("CA that issued imported CRL does not exist on this CRL stored in file " + fileName, e);
                    continue;
                } catch(ServiceExecutionFailedException e) {
                    log.error("Could not store CRL " + fileName + " in the database.", e);
                    failedFiles.add(fileName);
                    continue;
                }
      
            }
        }
        if (crlDirectory == null && certificateDirectory == null) {
            return new ServiceExecutionResult(Result.NO_ACTION, "No scan directories defined, service exited without action.");
        } else if (failedFiles.isEmpty() && readCertificates == 0 && readCrls == 0) {
            return new ServiceExecutionResult(Result.NO_ACTION, "CertificateCrlReader ran, but no certificates or CRLs were encountered.");
        } else {
            StringBuilder result = new StringBuilder("CertificateCrlReader ran: ");
            if (readCertificates != 0) {
                result.append(readCertificates + " certificates ");
                if (readCrls != 0) {
                    result.append("and ");
                }
            }
            if (readCrls != 0) {
                result.append(readCrls + " CRLs ");
            }
            result.append("were imported. ");
            if (failedFiles.isEmpty()) {
                return new ServiceExecutionResult(Result.SUCCESS, result.toString());
            } else {
                result.append("The following file scans failed: " + constructNameList(failedFiles));
                return new ServiceExecutionResult(Result.FAILURE, result.toString());
            }
        }
    }
    
    private byte[] getFileFromDisk(final File file) throws IOException {
        FileInputStream fileInputStream = new FileInputStream(file);
        ByteArrayOutputStream baos = new ByteArrayOutputStream(10000);
        byte[] buffer = new byte[10000];
        int bytes;
        while ((bytes = fileInputStream.read(buffer)) != -1) {
            baos.write(buffer, 0, bytes);
        }
        fileInputStream.close();
        return baos.toByteArray();
    }

    /**
     * Stores the certificate to the database, alternatively only the revocation information if it was anonymized. 
     * 
     * @param ejbs a map of EJB Session Beans
     * @param data a serialized ScpContainer
     * @throws AuthorizationDeniedException if the worker was not auhtorized to write to the certificate table
     * @throws ServiceExecutionFailedException if the ScpContainer object couldn't be deserialized
     */
    private void storeCertificate(final Map<Class<?>, Object> ejbs, final byte[] data)
            throws AuthorizationDeniedException, ServiceExecutionFailedException {
        final ScpContainer scpObject = unwrapScpContainer(data);
        final CertificateStoreSessionLocal certificateStoreSession = (CertificateStoreSessionLocal) ejbs.get(CertificateStoreSessionLocal.class);
        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        final int caId = scpObject.getIssuer().hashCode();
        final CAInfo caInfo = caSession.getCAInfoInternal(caId);
        final String caFingerprint = CertTools.getFingerprintAsString(caInfo.getCertificateChain().iterator().next());
        final Certificate certificate = scpObject.getCertificate();
        final CertificateDataWrapper storedCertificate = certificateStoreSession.getCertificateDataByIssuerAndSerno(scpObject.getIssuer(), scpObject.getSerialNumber());
        if (storedCertificate != null) {
            // Certificate already exist, just update status
            try {
                certificateStoreSession.setRevokeStatus(admin, storedCertificate, new Date(scpObject.getRevocationDate()), scpObject.getRevocationReason());
            } catch (CertificateRevokeException e) {
                log.info("Certificate with issuer " + scpObject.getIssuer() + " and serial number " + scpObject + " was already revoked.", e);
            }
        } else {     
            if (certificate == null) {
                // Information has been redacted, just write the minimum
                certificateStoreSession.updateLimitedCertificateDataStatus(admin, caId, scpObject.getIssuer(), "CN=limited", scpObject.getUsername(),
                        scpObject.getSerialNumber(), scpObject.getCertificateStatus(), new Date(scpObject.getRevocationDate()),
                        scpObject.getRevocationReason(), caFingerprint);
            } else {
                // Certificate doesn't exist, create new entry
                final int endEntityProfileId = EndEntityConstants.NO_END_ENTITY_PROFILE;
                final String username = scpObject.getUsername();
                final int certificateStatus = scpObject.getCertificateStatus();
                final int certificateType = scpObject.getCertificateType();
                final int certificateProfile = scpObject.getCertificateProfile();
                final int crlPartitionIndex = caInfo.determineCrlPartitionIndex(certificate);
                final long updateTime = scpObject.getUpdateTime();
                certificateStoreSession.storeCertificateNoAuth(admin, certificate, username, caFingerprint, null, certificateStatus, certificateType,
                        certificateProfile, endEntityProfileId, crlPartitionIndex, null, updateTime, null);
            }
        }
    }

    /**
     * Stores an imported CRL to the database. 
     * log.error("CRL from file " + fileName + " couldn't be read.");
     * @param ejbs
     * @param crlData
     * @throws CRLException if the CRL specified by the byte array couldn't be read
     * @throws CADoesntExistsException if the CA that issued the CRL hasn't been imported on this machine 
     * @throws ServiceExecutionFailedException if the CRL could not be stored on the database
     */
    private void storeCrl(final Map<Class<?>, Object> ejbs, final byte[] crlData) throws CRLException, CADoesntExistsException, ServiceExecutionFailedException {
        CrlStoreSessionLocal crlStoreSession = (CrlStoreSessionLocal) ejbs.get(CrlStoreSessionLocal.class);
        X509CRL crl = CertTools.getCRLfromByteArray(crlData);

        final CaSessionLocal caSession = (CaSessionLocal) ejbs.get(CaSessionLocal.class);
        CAInfo caInfo = caSession.getCAInfoInternal(CertTools.getIssuerDN(crl).hashCode());
        if(caInfo == null) {
            throw new CADoesntExistsException("CA with subject DN " + CertTools.getIssuerDN(crl) + " does not exist, cannot import CRL for it.");
        }
        final String caFingerprint = CertTools.getFingerprintAsString(caInfo.getCertificateChain().iterator().next());
        BigInteger crlnumber = CrlExtensions.getCrlNumber(crl);
        final String issuerDn = CertTools.getIssuerDN(crl);
        final int crlPartitionIndex = caInfo.determineCrlPartitionIndex(crl);
        int isDeltaCrl = (crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null ? -1 : 1);
        if(crlStoreSession.getCRL(issuerDn, crlPartitionIndex, crlnumber.intValue()) == null) {
            try {
                crlStoreSession.storeCRL(admin, crlData, caFingerprint, crlnumber.intValue(), issuerDn, crlPartitionIndex, crl.getThisUpdate(), crl.getNextUpdate(), isDeltaCrl);
            } catch (CrlStoreException e) {
                throw new ServiceExecutionFailedException("An error occurred while storing the CRL.", e);
            } catch (AuthorizationDeniedException e) {
                throw new ServiceExecutionFailedException("Service not authorized to store CRLs in database.", e);
            }
        } else {
            if(log.isDebugEnabled()) {
                log.debug("CRL with number " + crlnumber.intValue() + " and issuer " + issuerDn + " already found in DB - skipping.");
            }
        }
    }
    
    /**
     * Deserialize an {@link ScpContainer} object read from disk.
     * 
     * @param data a serialized ScpContainer as a byte array.
     * @return the deserialized ScpContainer object.
     * @throws ServiceExecutionFailedException if the data cannot be read from disk or if the class to be deserialized cannot be found on the classpath.
     * @throws SecurityException if the class is not an instance of {@link ScpContainer}.
     */
    private ScpContainer unwrapScpContainer(final byte[] data) throws ServiceExecutionFailedException {
        try (final LookAheadObjectInputStream ois = new LookAheadObjectInputStream(new ByteArrayInputStream(data))) {
            ois.setAcceptedClasses(Arrays.asList(ScpContainer.class, UpgradeableDataHashMap.class, LinkedHashMap.class, HashMap.class));
            ois.setEnabledMaxObjects(false);
            return (ScpContainer) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new ServiceExecutionFailedException(
                    "Couldn't deserialize ScpContainer, possibly due to a signed ScpContainer being processed without a signing CA declared.", e);
        }
    }

    /**
     * Retrieves a piece of data from within a signed envelope
     * 
     * @param signedData the signed data, as a byte array
     * @param signingCertificateChain the signing certificate chain.
     * @return the byte array in its original form
     * @throws SignatureException if an issue was found with the signature
     * @throws CertificateException if the certificate couldn't be extracted from signedData
     */
    private byte[] getAndVerifySignedData(final byte[] signedData, final List<Certificate> signingCertificateChain)
            throws SignatureException, CertificateException {
        if (signingCertificateChain == null || signingCertificateChain.isEmpty()) {
            //We're going to have to presume that the data wasn't signed at, since no signing CA was provided. 
            return signedData;
        }

        CMSSignedData csd;
        try {
            csd = new CMSSignedData(signedData);
        } catch (CMSException e) {
            throw new SignatureException("Could not unwrap signed byte array.", e);
        }
        Store<X509CertificateHolder> certs = csd.getCertificates();
        SignerInformation signer = csd.getSignerInfos().getSigners().iterator().next();
        @SuppressWarnings("unchecked")
        List<X509CertificateHolder> certCollection = (List<X509CertificateHolder>) certs.getMatches(signer.getSID());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certCollection.get(0));
        try {
            if (!signer.verify(jcaSignerInfoVerifierBuilder.build(cert.getPublicKey()))) {
                throw new SignatureException("Could not verify signature.");
            }
        } catch (OperatorCreationException e) {
            throw new SignatureException("Could not create verified from public key.", e);
        } catch (CMSException e) {
            throw new SignatureException("Signature on data is no longer valid", e);
        }
        CMSProcessableByteArray cpb = (CMSProcessableByteArray) csd.getSignedContent();
        return (byte[]) cpb.getContent();
    }

    /**
     * 
     * @param directoryName a local path to a directory
     * @return the directory as a File, or null if it was never defined. 
     * @throws ServiceExecutionFailedException if the directory was defined but does not exist, or is not a directory. 
     */
    private File getDirectory(final String directoryName) throws ServiceExecutionFailedException {
        File directory = null;
        if (StringUtils.isNotEmpty(directoryName)) {
            directory = new File(directoryName);
            if (!directory.exists() || !directory.isDirectory()) {
                final String msg = "Directory '" + directoryName + "' is defined, but not a directory.";
                log.error(msg);
                throw new ServiceExecutionFailedException(msg);
            }
        }
        return directory;
    }

    private String getCertificateDirectory(final Properties properties) {
        return properties.getProperty(CERTIFICATE_DIRECTORY_KEY, "");
    }

    private String getCRLDirectory(final Properties properties) {
        return properties.getProperty(CRL_DIRECTORY_KEY, "");
    }

    private int getCaId(final Properties properties) {
        String propertyValue = properties.getProperty(SIGNING_CA_ID_KEY, "-1");
        if (StringUtils.isNotEmpty(propertyValue)) {
            return Integer.parseInt(propertyValue);
        } else {
            return -1;
        }
    }
}
