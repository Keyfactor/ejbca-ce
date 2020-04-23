package org.ejbca.core.model.ca.publisher;

import org.cesecore.oscp.OcspResponseData;

/**
 * 
 * 
 * @version $Id$
 *
 */
public interface CustomPublisherOcspResponse {

    /**
     * Signature of method that must be implemented by classes which are responsible for
     * publishing the OCSP response data.
     * 
     * @param ocspResponseData Data to be published by the custom publisher
     * @return True in case of successful publishing 
     * @throws PublisherException Throws {@link #PublisherException} in case of not being able to publish the data
     */
    public boolean storeOcspResponseData(final OcspResponseData ocspResponseData) throws PublisherException;

}
