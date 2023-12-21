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
package org.ejbca.scp.publisher;

import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.junit.Test;

import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class ScpPublisherUnitTest {

    @Test
    public void shouldFailConnectionTestWhenDestinationUrlsAreBlank() {
        // given
        final String expectedErrorMessage = "Neither Certificate nor CRL destination URLs are configured.";
        final ScpPublisher scpPublisher = new ScpPublisher();
        final Properties properties = new Properties();
        properties.setProperty(ScpPublisher.CERT_SCP_DESTINATION_PROPERTY_NAME, "");
        properties.setProperty(ScpPublisher.CRL_SCP_DESTINATION_PROPERTY_NAME, " ");
        scpPublisher.init(properties);
        // when, then
        var exception = assertThrows("Should throw a PublisherConnectionException when both Certificate and CRL" +
                "destination URLs are blank", PublisherConnectionException.class, scpPublisher::testConnection);
        assertEquals(expectedErrorMessage, exception.getMessage());
    }

}
