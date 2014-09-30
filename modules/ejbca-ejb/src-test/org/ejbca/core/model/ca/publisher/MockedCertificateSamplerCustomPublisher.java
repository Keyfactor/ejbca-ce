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
import java.security.cert.Certificate;

/**
 * Mocked version of CertificateSamplerCustomPublisher to be able to easily test 
 * if the writeCertificate method was called.
 *
 * @version $Id$
 */
public class MockedCertificateSamplerCustomPublisher extends CertificateSamplerCustomPublisher {
    private boolean writeCertificateCalled;

    public MockedCertificateSamplerCustomPublisher() {
        super();
    }

    @Override
    protected void writeCertificate(Certificate cert, File outFolder, String prefix, String suffix) throws PublisherException {
        writeCertificateCalled = true;
    }

    public boolean isWriteCertificateCalled() {
        return writeCertificateCalled;
    }

    public void reset() {
        writeCertificateCalled = false;
    }
    
}
