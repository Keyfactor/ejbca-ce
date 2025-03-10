/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca.internal;

import java.security.SecureRandom;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.config.CesecoreConfiguration;

import com.keyfactor.util.RandomHelper;


/**
 * Generates random CRL partition indexes. Used in {@link org.cesecore.certificates.certificate.certextensions.standard.CrlDistributionPoints CrlDistributionPoints}.
 * @version $Id$
 */
public enum CrlPartitionIndexGeneratorRandom {
    INSTANCE;

    private SecureRandom random;
    private Throwable initializationFailure;

    private CrlPartitionIndexGeneratorRandom() {
        try {
            String algorithm = CesecoreConfiguration.getCaSerialNumberAlgorithm();
            random = RandomHelper.getInstance(algorithm);
        } catch (IllegalStateException e) {
            initializationFailure = e;
            Logger.getLogger(CrlPartitionIndexGeneratorRandom.class).error("Could not initialize random generator", e);
        }
    }

    /**
     * Generates a CRL Partition Index based on the setting in the given CA.
     * @param caInfo X509CAInfo object containing partitioned CRL settings.
     * @return CRL Partition Index, or {@link CertificateConstants#NO_CRL_PARTITION} if CRL partitioning is not being used.
     */
    public int generateCrlPartitionIndex(final X509CAInfo caInfo) {
        if (!caInfo.getUsePartitionedCrl()) {
            return CertificateConstants.NO_CRL_PARTITION;
        } else if (random == null) {
            throw new IllegalStateException("Cannot generate CRL Partition Index because the random generator initialization failed.", initializationFailure);
        }
        final int partitions = caInfo.getCrlPartitions();
        final int suspended = caInfo.getSuspendedCrlPartitions();
        return random.nextInt(partitions - suspended) + suspended + 1;
    }

}
