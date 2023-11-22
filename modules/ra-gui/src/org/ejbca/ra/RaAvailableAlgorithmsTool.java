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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.faces.model.SelectItem;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.config.CesecoreConfiguration;
import org.ejbca.config.WebConfiguration;

import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConfigurationCache;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;

public class RaAvailableAlgorithmsTool {
    private static final Logger log = Logger.getLogger(RaAvailableAlgorithmsTool.class);

    public static List<SelectItem> getAvailableAlgorithmSelectItems(final CertificateProfile certificateProfile, final String noChoiceMessage){
        final List<SelectItem> availableAlgorithmSelectItems = new ArrayList<>();
        if (certificateProfile!=null) {
            final List<String> availableKeyAlgorithms = certificateProfile.getAvailableKeyAlgorithmsAsList();
            final List<Integer> availableBitLengths = certificateProfile.getAvailableBitLengthsAsList();
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_DSA)) {
                for (final int availableBitLength : availableBitLengths) {
                    if (availableBitLength == 1024) {
                        availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_DSA + "_" + availableBitLength,
                                AlgorithmConstants.KEYALGORITHM_DSA + " " + availableBitLength + " bits"));
                    }
                }
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_RSA)) {
                for (final int availableBitLength : availableBitLengths) {
                    if (availableBitLength >= 1024) {
                        availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_RSA + "_" + availableBitLength,
                                AlgorithmConstants.KEYALGORITHM_RSA + " " + availableBitLength + " bits"));
                    }
                }
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ED25519)) {
                availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED25519,
                        AlgorithmConstants.KEYALGORITHM_ED25519));
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ED448)) {
                availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ED448,
                        AlgorithmConstants.KEYALGORITHM_ED448));
            }
            if (availableKeyAlgorithms.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                final Set<String> ecChoices = new HashSet<>();
                if (certificateProfile.getAvailableEcCurvesAsList().contains(CertificateProfile.ANY_EC_CURVE)) {
                    for (final String ecNamedCurve : AlgorithmTools.getNamedEcCurvesMap(false).keySet()) {
                        if (CertificateProfile.ANY_EC_CURVE.equals(ecNamedCurve)) {
                            continue;
                        }
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(ecNamedCurve);
                        if (availableBitLengths.contains(bitLength)) {
                            ecChoices.add(ecNamedCurve);
                        }
                    }
                }
                ecChoices.addAll(certificateProfile.getAvailableEcCurvesAsList());
                ecChoices.remove(CertificateProfile.ANY_EC_CURVE);
                final List<String> ecChoicesList = new ArrayList<>(ecChoices);
                Collections.sort(ecChoicesList);
                for (final String ecNamedCurve : ecChoicesList) {
                    if (!AlgorithmTools.isKnownAlias(ecNamedCurve)) {
                        log.warn("Ignoring unknown curve " + ecNamedCurve + " from being displayed in the RA web.");
                        continue;
                    }
                    availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConstants.KEYALGORITHM_ECDSA + "_" + ecNamedCurve, AlgorithmConstants.KEYALGORITHM_ECDSA + " "
                            + StringTools.getAsStringWithSeparator(" / ", AlgorithmTools.getAllCurveAliasesFromAlias(ecNamedCurve))));
                }
            }
            if (WebConfiguration.isPQCEnabled()) {
                for (String algorithm : availableKeyAlgorithms) {
                    if (AlgorithmTools.isPQC(algorithm)) {
                            availableAlgorithmSelectItems.add(new SelectItem(algorithm));
                    }
                }
            }
            for (final String algName : AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithms()) {
                if (availableKeyAlgorithms.contains(AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithmTitle(algName))) {
                    for (final String subAlg : CesecoreConfiguration.getExtraAlgSubAlgs(algName)) {
                        final String name = CesecoreConfiguration.getExtraAlgSubAlgName(algName, subAlg);
                        final int bitLength = AlgorithmTools.getNamedEcCurveBitLength(name);
                        if (availableBitLengths.contains(bitLength)) {
                            availableAlgorithmSelectItems.add(new SelectItem(AlgorithmConfigurationCache.INSTANCE.getConfigurationDefinedAlgorithmTitle(algName) + "_" + name,
                                    CesecoreConfiguration.getExtraAlgSubAlgTitle(algName, subAlg)));
                        } else {
                            if (log.isTraceEnabled()) {
                                log.trace("Excluding " + name + " from enrollment options since bit length " + bitLength + " is not available.");
                            }
                        }
                    }
                }
            }
            if (availableAlgorithmSelectItems.size() < 1) {
                availableAlgorithmSelectItems.add(new SelectItem(null, noChoiceMessage, noChoiceMessage, true));
            }
        }
        return availableAlgorithmSelectItems;
    }
}
