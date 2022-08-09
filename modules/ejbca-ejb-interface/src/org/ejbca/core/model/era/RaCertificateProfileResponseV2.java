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

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.util.AlgorithmConstants;

/**
 * RaResponse for Certificate Profile Info.
 * 
 */
public class RaCertificateProfileResponseV2 implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<String> availableAlgorithms;
    private List<String> availableEcdsaCurves;
    private List<String> availableCas;
    private List<Integer> availableBitLengths;

    public List<String> getAvailableAlgorithms(){
        return availableAlgorithms;
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

        private List<String> getAvailableCasFromProfile(List<Integer>caIds, IdNameHashMap<CAInfo> caInfos) {
            List<String> availableCas = new ArrayList<String>();
            for (final int id : caIds) {
                if (id == CertificateProfile.ANYCA) {
                    availableCas.add("ANY_CA");
                } else {
                    availableCas.add(caInfos.get(id).getName());
                }    
            }
            return availableCas;
        }

        public RaCertificateProfileResponseV2 toRaResponse(
                CertificateProfile certificateProfile, IdNameHashMap<CAInfo> caInfos) {
            RaCertificateProfileResponseV2 response = new RaCertificateProfileResponseV2();
            final List<Integer> caIds = certificateProfile.getAvailableCAs();
            final List<String> availableKeyAlgorithmsFromProfile = certificateProfile.getAvailableKeyAlgorithmsAsList();
            List<String> availableEcdsaCurvesFromProfile = new ArrayList<>();
            List<Integer> availableBitLengthsFromProfile = new ArrayList<>();
            if (!availableKeyAlgorithmsFromProfile.contains(AlgorithmConstants.KEYALGORITHM_ECDSA)) {
                availableEcdsaCurvesFromProfile.add("No ECDSA curves available.");
            }else {
                availableEcdsaCurvesFromProfile = certificateProfile.getAvailableEcCurvesAsList();
            }
            if ((!availableKeyAlgorithmsFromProfile.contains(AlgorithmConstants.KEYALGORITHM_RSA)) && 
                    (!availableEcdsaCurvesFromProfile.contains(CertificateProfile.ANY_EC_CURVE))) {
                availableBitLengthsFromProfile.add(0);
            }else {
                availableBitLengthsFromProfile = certificateProfile.getAvailableBitLengthsAsList();
            }
            response.availableAlgorithms = availableKeyAlgorithmsFromProfile;
            response.availableBitLengths = availableBitLengthsFromProfile;
            response.availableEcdsaCurves = availableEcdsaCurvesFromProfile;
            response.availableCas = getAvailableCasFromProfile(caIds, caInfos);
            return response;
        }
    }
}
