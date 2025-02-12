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
package org.ejbca.core.model.era;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfile;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;

/**
 * RaResponse for Certificate Profile Info.
 * 
 */
public class RaCertificateProfileResponseV2 implements Serializable {

    private static final long serialVersionUID = 1L;

    private Integer certificateProfileId;
    private List<String> availableAlgorithms;
    private List<String> availableAlternativeAlgorithms;
    private List<String> availableEcdsaCurves;
    private List<String> availableCas;
    private List<Integer> availableBitLengths;
    private List<Integer> keyUsages;
    private List<String> extendedKeyUsages;
    private String validity;

    public List<Integer> getKeyUsages() {
        return keyUsages;
    }

    public List<String> getExtendedKeyUsages() {
        return extendedKeyUsages;
    }

    public String getValidity() {
        return validity;
    }

    public Integer getCertificateProfileId() {
        return certificateProfileId;
    }

    public List<String> getAvailableAlgorithms(){
        return availableAlgorithms;
    }

    public List<String> getAvailableAlternativeAlgorithms(){
        return availableAlternativeAlgorithms;
    }

    public List<String> getAvailableEcdsaCurves(){
        return availableEcdsaCurves;
    }

    public List<String> getAvailableCas(){
        return availableCas;
    }

    public List<Integer> getAvailableBitLengths(){
        return availableBitLengths;
    }

    public static RaCertificateProfileResponseConverter converter () {
        return new RaCertificateProfileResponseConverter();
    }

    public static class RaCertificateProfileResponseConverter{
        RaCertificateProfileResponseConverter(){
        }
        
        private List<Integer> getCertProfileKeyUsages(final CertificateProfile certificateProfile ) {
            
            List<Integer> results = new ArrayList<>();

            if (certificateProfile.getKeyUsage(CertificateConstants.DIGITALSIGNATURE)) {
                results.add(CertificateConstants.DIGITALSIGNATURE);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.NONREPUDIATION)) {
                results.add(CertificateConstants.NONREPUDIATION);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.KEYENCIPHERMENT)) {
                results.add(CertificateConstants.KEYENCIPHERMENT);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.DATAENCIPHERMENT)) {
                results.add(CertificateConstants.DATAENCIPHERMENT);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.KEYAGREEMENT)) {
                results.add(CertificateConstants.KEYAGREEMENT);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.KEYCERTSIGN)) {
                results.add(CertificateConstants.KEYCERTSIGN);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.CRLSIGN)) {
                results.add(CertificateConstants.CRLSIGN);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.ENCIPHERONLY)) {
                results.add(CertificateConstants.ENCIPHERONLY);
            }
            if (certificateProfile.getKeyUsage(CertificateConstants.DECIPHERONLY)) {
                results.add(CertificateConstants.DECIPHERONLY);
            }

            return results;
        }

        private List<String> getAvailableCasFromProfile(List<Integer>caIds, IdNameHashMap<CAInfo> caInfos) {
            List<String> availableCas = new ArrayList<>();
            Set<Integer> caInfoCaIds = caInfos.idKeySet();
            if (caIds.contains(CertificateProfile.ANYCA)) {
                availableCas.add("ANY_CA");
            } else {
                for (Integer caInfoCaId : caInfoCaIds) {
                    if (caIds.contains(caInfoCaId)) {
                        availableCas.add(caInfos.get(caInfoCaId).getName());
                    }
                }
            }
            return availableCas;
        }

        public RaCertificateProfileResponseV2 toRaResponse(final CertificateProfile certificateProfile, final IdNameHashMap<CAInfo> caInfos,
                                                           final Integer certProfileId) {
            RaCertificateProfileResponseV2 response = new RaCertificateProfileResponseV2();

            final List<Integer> caIds = certificateProfile.getAvailableCAs();
            final List<String> availableKeyAlgorithmsFromProfile = certificateProfile.getAvailableKeyAlgorithmsAsList();

            final List<String> availableAlternativeKeyAlgorithmsFromProfile = certificateProfile.getAlternativeAvailableKeyAlgorithmsAsList();
            final boolean useAlternativeSignature = certificateProfile.getUseAlternativeSignature();

            List<String> availableEcdsaCurvesFromProfile = new ArrayList<>();
            List<Integer> availableBitLengthsFromProfile = new ArrayList<>();

            if (!availableKeyAlgorithmsFromProfile.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                availableEcdsaCurvesFromProfile.add("No ECDSA curves available.");
            } else {
                availableEcdsaCurvesFromProfile = certificateProfile.getAvailableEcCurvesAsList();
            }

            if ((!availableKeyAlgorithmsFromProfile.contains(AlgorithmConstants.KEYALGORITHM_RSA)) && 
                    (!availableEcdsaCurvesFromProfile.contains(CertificateProfile.ANY_EC_CURVE))) {
                availableBitLengthsFromProfile.add(0);
            } else {
                availableBitLengthsFromProfile = certificateProfile.getAvailableBitLengthsAsList();
            }

            response.certificateProfileId = certProfileId;
            response.availableAlgorithms = availableKeyAlgorithmsFromProfile;
            response.availableBitLengths = availableBitLengthsFromProfile;
            response.availableEcdsaCurves = availableEcdsaCurvesFromProfile;
            response.availableCas = getAvailableCasFromProfile(caIds, caInfos);
            
            if (certificateProfile.getUseKeyUsage()) {
                response.keyUsages = getCertProfileKeyUsages(certificateProfile);
            }
            if (certificateProfile.getUseExtendedKeyUsage()) {
                response.extendedKeyUsages = certificateProfile.getExtendedKeyUsageOids();
            }
            response.validity = certificateProfile.getEncodedValidity();

            if (useAlternativeSignature) {
                response.availableAlternativeAlgorithms = availableAlternativeKeyAlgorithmsFromProfile;
            }

            return response;
        }
    }
}
