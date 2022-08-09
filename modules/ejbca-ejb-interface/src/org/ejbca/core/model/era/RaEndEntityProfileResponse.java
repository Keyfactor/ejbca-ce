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

import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.certificates.util.DnComponents;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Response of end entity profile from RA UI.
 *
 */
public class RaEndEntityProfileResponse  implements Serializable {
    private static final long serialVersionUID = 1L;

    private String eepName;
    private List<String> availableCAs;
    private List<String> availableCertificateProfiles;
    private List<String> subdjectDNFields;
    private List<String> subjectANFields;

    public String getEepName() {
        return eepName;
    }

    public List<String> getAvailableCAs() {
        return availableCAs;
    }

    public List<String> getAvailableCertificateProfiles() {
        return availableCertificateProfiles;
    }

    public List<String> getSubdjectDNFields() {
        return subdjectDNFields;
    }

    public List<String> getSubjectANFields() {
        return subjectANFields;
    }

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static RaEndEntityProfileResponseConverter converter() {
        return new RaEndEntityProfileResponseConverter();
    }

    /**
     * Converter of this class.
     */
    public static class RaEndEntityProfileResponseConverter {
        public RaEndEntityProfileResponseConverter() {
        }
        public RaEndEntityProfileResponse toRaResponse(final String profileName,
                                                       final EndEntityProfile endEntityProfile,
                                                       final Map<Integer, String> caIdToNameMap,
                                                       final Map<Integer, String> certificateProfileIdToNameMap){

            RaEndEntityProfileResponse raEndEntityProfileResponse = new RaEndEntityProfileResponse();
            raEndEntityProfileResponse.eepName = profileName;
            raEndEntityProfileResponse.availableCertificateProfiles = getListOfNamesFromMap(certificateProfileIdToNameMap, endEntityProfile.getAvailableCertificateProfileIds());
            raEndEntityProfileResponse.availableCAs = getListOfNamesFromMap(caIdToNameMap, endEntityProfile.getAvailableCAs());
            raEndEntityProfileResponse.subdjectDNFields = getListOfSDNFieldNames(endEntityProfile);
            raEndEntityProfileResponse.subjectANFields = getListOfSANFieldNames(endEntityProfile);
            return raEndEntityProfileResponse;
        }

        private List<String> getListOfNamesFromMap(Map<Integer, String> idToNameMap,  List<Integer> availableIds) {
            List<String> list = new ArrayList<>();
            for (Integer id : availableIds) {
                String name = idToNameMap.get(id);
                if (name != null) {
                    list.add(name);
                } else {
                    if (id == SecConst.ALLCAS) {
                        list.add("ANY CA");
                    }
                }
            }
            return list;
        }

        private List<String> getListOfSDNFieldNames(EndEntityProfile endEntityProfile) {
            List<String> fieldNameList = new ArrayList<>();
            final int numberOfFields = endEntityProfile.getSubjectDNFieldOrderLength();
            final List<int[]> fieldDataList = new ArrayList<>();
            for (int i = 0; i < numberOfFields; i++) {
                fieldDataList.add(endEntityProfile.getSubjectDNFieldsInOrder(i));
            }
            for (int[] field : fieldDataList) {
                final String fieldComponent = DNFieldExtractor.getFieldComponent(
                        DnComponents.profileIdToDnId(field[EndEntityProfile.FIELDTYPE]), DNFieldExtractor.TYPE_SUBJECTDN);
                fieldNameList.add(fieldComponent.replace("=", ""));
            }
            return fieldNameList;
        }

        private List<String> getListOfSANFieldNames(EndEntityProfile endEntityProfile) {
            List<String> fieldNameList = new ArrayList<>();
            final int numberOfFields = endEntityProfile.getSubjectAltNameFieldOrderLength();
            final List<int[]> fieldDataList = new ArrayList<>();
            for (int i = 0; i < numberOfFields; i++) {
                fieldDataList.add(endEntityProfile.getSubjectAltNameFieldsInOrder(i));
            }
            for (int[] field : fieldDataList) {
                final String fieldComponent = DNFieldExtractor.getFieldComponent(
                        DnComponents.profileIdToDnId(field[EndEntityProfile.FIELDTYPE]), DNFieldExtractor.TYPE_SUBJECTALTNAME);
                fieldNameList.add(fieldComponent.replace("=", ""));
            }
            return fieldNameList;
        }
    }
}
