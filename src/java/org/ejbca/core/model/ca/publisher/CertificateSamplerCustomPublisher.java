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
package org.ejbca.core.model.ca.publisher;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * Publisher storing certificates to a specified folder.
 * 
 * The configured sampling method and its parameters (if any) determines which 
 * certificates that should be sampled.
 * 
 * @see SamplingMethod
 * @version $Id$
 */
public class CertificateSamplerCustomPublisher implements ICustomPublisher {
    private static final Logger LOG = Logger.getLogger(CertificateSamplerCustomPublisher.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final String PROPERTY_OUTPUTFOLDER = "outputfolder";
    
    private static final String PROPERTYPREFIX_PROFILEID = "profileid.";
    
    private static final String PROPERTYSUFFIX_PVALUE = ".pvalue";
    private static final String PROPERTYSUFFIX_SAMPLINGMETHOD = ".samplingmethod";
    
    private static final String PROPERTY_DEFAULT_SAMPLINGMETHOD = "default" + PROPERTYSUFFIX_SAMPLINGMETHOD;
    private static final String PROPERTY_DEFAULT_PVALUE = "default" + PROPERTYSUFFIX_PVALUE;
    
    private Properties config;
    
    @Override
    public void init(Properties config) {
    	if (LOG.isTraceEnabled()) {
    		LOG.trace(">init: " + this);
    	}
        this.config = config;
    }
    
    @Override
    public void testConnection() throws PublisherConnectionException {
        if (LOG.isTraceEnabled()) {
        	LOG.trace(">testConnection, Testing connection");
        }
        
        // Test output folder
        File outputFolder;
        try {
            outputFolder = getOutputFolder();
        } catch (PublisherException ex) {
            LOG.error(null, ex);
            throw new PublisherConnectionException(ex.getLocalizedMessage());
        }
        if (!outputFolder.exists() || !outputFolder.isDirectory()) {
            final String msg = intres.getLocalizedMessage("publisher.erroroutputpath", outputFolder.getAbsolutePath());
            LOG.error(msg);
            throw new PublisherConnectionException(msg);
        }
        
        // Test default samplingmethod
        SamplingMethod defaultMethod = null;
        try {
            String methodString = config.getProperty(PROPERTY_DEFAULT_SAMPLINGMETHOD);
            if (methodString == null) {
                final String msg = intres.getLocalizedMessage("publisher.errormissingproperty", PROPERTY_DEFAULT_SAMPLINGMETHOD);
                LOG.error(msg);
                throw new PublisherConnectionException(msg);
            } else {
                defaultMethod = SamplingMethod.valueOf(methodString);
            }
        } catch (IllegalArgumentException ex) {
            final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", PROPERTY_DEFAULT_SAMPLINGMETHOD, ex.getLocalizedMessage());
            LOG.error(msg, ex);
            throw new PublisherConnectionException(msg);
        }
        
        // Test default pvalue
        final String pvalueString = config.getProperty(PROPERTY_DEFAULT_PVALUE);
        if (pvalueString == null) {
            if (SamplingMethod.SAMPLE_PROBABILISTIC.equals(defaultMethod)) {
                final String msg = intres.getLocalizedMessage("publisher.errormissingproperty", PROPERTY_DEFAULT_PVALUE);
                LOG.error(msg);
                throw new PublisherConnectionException(msg);
            }
        } else {
            try {
                final double defaultPvalue = Double.parseDouble(pvalueString);
                if (defaultPvalue < 0.0 || defaultPvalue > 1.0) {
                    final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", PROPERTY_DEFAULT_PVALUE, intres.getLocalizedMessage("publisher.pvalueinterval"));
                    LOG.error(msg);
                    throw new PublisherConnectionException(msg);
                }
            } catch (NumberFormatException ex) {
                final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", PROPERTY_DEFAULT_PVALUE, ex.getLocalizedMessage());
                LOG.error(msg, ex);
                throw new PublisherConnectionException(msg);
            }
        }
        
        // Test every profile specific values
        for (String name : config.stringPropertyNames()) {
            if (name.startsWith(PROPERTYPREFIX_PROFILEID)) {
                if (name.endsWith(PROPERTYSUFFIX_SAMPLINGMETHOD) && name.length() > PROPERTYPREFIX_PROFILEID.length() + PROPERTYSUFFIX_SAMPLINGMETHOD.length()) {
                    final String profileIdString = name.substring(PROPERTYPREFIX_PROFILEID.length(), name.indexOf(PROPERTYSUFFIX_SAMPLINGMETHOD));
                    int profileId;
                    try {
                        profileId = Integer.parseInt(profileIdString);
                    } catch (NumberFormatException ex) {
                        final String msg = intres.getLocalizedMessage("publisher.errorinvalidkey", name);
                        LOG.error(msg, ex);
                        throw new PublisherConnectionException(msg);
                    }
                    try {
                        SamplingMethod profileMethod = SamplingMethod.valueOf(config.getProperty(name));
                        
                        // Check that there is an pvalue for this profile
                        if (SamplingMethod.SAMPLE_PROBABILISTIC.equals(profileMethod)) {
                            getPvalue(profileId); // Throws exception if the value (or default value) does not exist
                        }
                    } catch (PublisherException ex) {
                        throw new PublisherConnectionException(ex.getLocalizedMessage());
                    } catch (IllegalArgumentException ex) {
                        final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", name, ex.getLocalizedMessage());
                        LOG.error(msg, ex);
                        throw new PublisherConnectionException(msg);
                    }
                } else if (name.endsWith(PROPERTYSUFFIX_PVALUE) && name.length() > PROPERTYPREFIX_PROFILEID.length() + PROPERTYSUFFIX_PVALUE.length()) {
                    final String profileIdString = name.substring(PROPERTYPREFIX_PROFILEID.length(), name.indexOf(PROPERTYSUFFIX_PVALUE));
                    try {
                        Integer.parseInt(profileIdString);
                    } catch (NumberFormatException ex) {
                        final String msg = intres.getLocalizedMessage("publisher.errorinvalidkey", name);
                        LOG.error(msg, ex);
                        throw new PublisherConnectionException(msg);
                    }
                    try {
                        final double pvalue = Double.parseDouble(config.getProperty(name));
                        if (pvalue < 0.0 || pvalue > 1.0) {
                            final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", name, intres.getLocalizedMessage("publisher.pvalueinterval"));
                            LOG.error(msg);
                            throw new PublisherConnectionException(msg);
                        }
                    } catch (NumberFormatException ex) {
                        final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", name, ex.getLocalizedMessage());
                        LOG.error(msg, ex);
                        throw new PublisherConnectionException(msg);
                    }
                }
            }
        }
    }
    
    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (LOG.isTraceEnabled()) {
        	LOG.trace("CRL sampling is not supported");
        }
        return true; // This ICustomPublisher does not care about CRLs and chooses to simply return SUCCESS for those.
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate, org.cesecore.certificates.endentity.ExtendedInformation extendedinformation) throws PublisherException {
        if (LOG.isTraceEnabled()) {
            LOG.trace(">storeCertificate, Storing Certificate of profileid: " + certificateProfileId);
        }
        if (status == CertificateConstants.CERT_ACTIVE) {
            // Sample the certificate if it is time for that
            if (isTimeToSample(certificateProfileId)) {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("Sample");
                }
                writeCertificate(incert, getOutputFolder(), username + "-", ".crt");
            } else {
                if (LOG.isTraceEnabled()) {
                    LOG.trace("No sampling");
                }
            }
        }
        if (LOG.isTraceEnabled()) {
            LOG.trace("<storeCertificate");
        }
        return true; // If we got this far either we chose to not store the certificate or it was stored correctly
    }

    protected void writeCertificate(Certificate cert, File outFolder, String prefix, String suffix) throws PublisherException {
        FileOutputStream fos = null;
        try {
            final File destFile = File.createTempFile(prefix, suffix, outFolder);
            fos = new FileOutputStream(destFile);
            fos.write(cert.getEncoded());
        } catch (CertificateEncodingException ex) {
            final String msg = intres.getLocalizedMessage("publisher.errorcertconversion");
            LOG.error(msg);
            throw new PublisherException(msg);
        } catch (IOException e) {
            final String msg = intres.getLocalizedMessage("publisher.errortempfile");
            LOG.error(msg, e);
            throw new PublisherException(msg);
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException ignored) {} // NOPMD
            }
        }
    }
    
    /**
     * Checks if the certificate should be sampled according to the sampling 
     * method.
     * @param profileId The profileId the certificate was issued for
     * @return True if it is "time" to take a sample.
     * @throws PublisherException in case of configuration errors
     */
    private boolean isTimeToSample(int profileId) throws PublisherException {
        final boolean result;
        
        SamplingMethod theMethod = getMethod(profileId);
        if (LOG.isTraceEnabled()) {
            LOG.trace("samplingMethod: " + theMethod);
        }
        
        switch (theMethod) {
            case SAMPLE_NONE: {
                result = false;
                break;
            } 
            case SAMPLE_ALL: {
                result = true;
                break;
            }
            case SAMPLE_PROBABILISTIC: {
                // Get the ratio
                Double p = getPvalue(profileId);
                if (LOG.isTraceEnabled()) {
                    LOG.trace("pvalue: " + p);
                }

                // Gets an pseudorandomly value between 0 and 1 from an approximately uniform distribution
                // Notice: This method call is thread-safe, however uses synchronization which might decrease performance
                //         We can not use a random object as instance variable as a new instance of this class is created for every request and requests at the same time would then be initialized with the same seed
                //         When we switch to Java 7 we could possibly use ThreadLocalRandom instead.
                final double r = Math.random();

                // r will be less than our p with the probability of p
                result = r < p;
                    break;
                }
            default: {
                final String msg = intres.getLocalizedMessage("publisher.errorsamplingmethod");
                LOG.error(msg);
                throw new PublisherException(msg);
            }
        }
        return result;
    }
    
    private SamplingMethod getMethod(int profileId) throws PublisherException {
        final SamplingMethod result;
        
        String propertyKey = PROPERTYPREFIX_PROFILEID + profileId + PROPERTYSUFFIX_SAMPLINGMETHOD;
        String propertyString = config.getProperty(propertyKey);
        if (propertyString == null) {
            propertyKey = PROPERTY_DEFAULT_SAMPLINGMETHOD;
            propertyString = config.getProperty(propertyKey);
        }
        if (propertyString == null) {
            final String msg = intres.getLocalizedMessage("publisher.errormissingproperty", propertyKey);
            LOG.error(msg);
            throw new PublisherException(msg);
        }
        try {
            result = SamplingMethod.valueOf(propertyString);
        } catch (IllegalArgumentException ex) {
            final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", PROPERTY_DEFAULT_PVALUE, ex.getLocalizedMessage());
            LOG.debug(msg, ex);
            throw new PublisherException(msg);
        }
        return result;
    }
    
    private Double getPvalue(int profileId) throws PublisherException {
        final Double result;
        
        String propertyKey = PROPERTYPREFIX_PROFILEID + profileId + PROPERTYSUFFIX_PVALUE;
        String propertyString = config.getProperty(propertyKey);
        if (propertyString == null) {
            propertyKey = PROPERTY_DEFAULT_PVALUE;
            propertyString = config.getProperty(propertyKey);
        }
        if (propertyString == null) {
            final String msg = intres.getLocalizedMessage("publisher.errormissingproperty", propertyKey);
            LOG.error(msg);
            throw new PublisherException(msg);
        }
        try {
            result = Double.parseDouble(propertyString);
        } catch (NumberFormatException ex) {
            final String msg = intres.getLocalizedMessage("publisher.errorinvalidvalue", PROPERTY_DEFAULT_PVALUE, ex.getLocalizedMessage());
            LOG.debug(msg, ex);
            throw new PublisherException(msg);
        }
        return result;
    }
    
    private File getOutputFolder() throws PublisherException {
        final File result;
        String outputFolderString = config.getProperty(PROPERTY_OUTPUTFOLDER, "").trim();
        if (outputFolderString.length() < 1) {
            final String msg = intres.getLocalizedMessage("publisher.errormissingproperty", PROPERTY_OUTPUTFOLDER);
            LOG.error(msg);
            throw new PublisherException(msg);
        } else {
            result = new File(outputFolderString);
        }
        return result;
    }
    
    public enum SamplingMethod {
        /** No certificates are sampled. */
        SAMPLE_NONE,
        
        /** All certificates are sampled. */ 
        SAMPLE_ALL,
        
        /** Every certificate is sampled with the probability as specified as the pvalue. */
        SAMPLE_PROBABILISTIC,
    }

    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        return true;
    }
    
    @Override
    public boolean isReadOnly() {
        return false;
    }
}
