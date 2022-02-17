/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ui.web.rest.api.io.request;

import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ra.ExtendedInformationFields;
import org.ejbca.ui.web.rest.api.exception.RestException;
import org.ejbca.ui.web.rest.api.validator.ValidItsRegistrationRestRequest;

@ValidItsRegistrationRestRequest
public class ItsRegistrationRequestMessage {
    
    private String canonicalId;
    private String canonicalPublicKey;
    private String certificateProfileName;
    private String endEntityProfileName;
    private String caName;

    public ItsRegistrationRequestMessage() {}

    /**
     * Returns a converter instance for this class.
     *
     * @return instance of converter for this class.
     */
    public static ItsRegistrationRequestMessageConverter converter() {
        return new ItsRegistrationRequestMessageConverter();
    }

    public static class ItsRegistrationRequestMessageConverter {

        public EndEntityInformation toEntity(final ItsRegistrationRequestMessage itsRegistrationRequestMessage, Integer caId,
        		Integer endEntityProfileId, Integer certificateProfileId) throws RestException {
            final EndEntityInformation eeInformation = new EndEntityInformation();
            final ExtendedInformation extendedInfo = new ExtendedInformation();
            extendedInfo.setCustomData(ExtendedInformationFields.CUSTOM_CANONICAL_PUBLICKEY, itsRegistrationRequestMessage.getCanonicalPublicKey());
            eeInformation.setExtendedInformation(extendedInfo);
            eeInformation.setUsername(itsRegistrationRequestMessage.getCanonicalId());
            eeInformation.setCertificateProfileId(certificateProfileId);
            eeInformation.setEndEntityProfileId(endEntityProfileId);
            eeInformation.setCAId(caId);
            return eeInformation;
        }
    }

    public String getCanonicalId() {
        return this.canonicalId;
    }

    public void setCanonicalId(String canonicalId) {
        this.canonicalId = canonicalId;
    }
    
    public String getCanonicalPublicKey() {
        return this.canonicalPublicKey;
    }

    public void setCanonicalPublicKey(String canonicalPublicKey) {
        this.canonicalPublicKey = canonicalPublicKey;
    }

    public String getCertificateProfileName() {
        return this.certificateProfileName;
    }

    public void setCertificateProfileName(String certificateProfileName) {
        this.certificateProfileName = certificateProfileName;
    }

    public String getEndEntityProfileName() {
        return this.endEntityProfileName;
    }

    public void setEndEntityProfileName(String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    public String getCaName() {
        return this.caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

}
