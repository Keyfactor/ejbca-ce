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
package org.cesecore.certificates.certificate.certextensions.standard;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.junit.Test;

/**
 * Unit tests for the {@link NameConstraint} class
 */
public class NameConstraintTest {

    /**
     * From RFC 5280 4.2.1.10: 
     * 
     * For URIs, the constraint applies to the host part of the name.  The constraint MUST be specified as a fully qualified domain name and MAY
     * specify a host or a domain.  Examples would be "host.example.com" and  ".example.com".  When the constraint begins with a period, it MAY be
     * expanded with one or more labels.  That is, the constraint ".example.com" is satisfied by both host.example.com and my.host.example.com.  However,
     * the constraint ".example.com" is not satisfied by "example.com".  When the constraint does not begin with  a period, it specifies a host.  
     * If a constraint is applied to the uniformResourceIdentifier name form and a subsequent certificate includes a subjectAltName extension with a 
     * uniformResourceIdentifier that does not include an authority component with a host name specified as a fully qualified domain name (e.g., if 
     * the URI either does not include an authority component or includes an authority component in which the host name is specified as an IP address), 
     * then the application MUST reject the certificate.
     */
    @Test
    public void testUriParsing() throws CertificateExtensionException {
        //Prefix defined in RFC 5280 as above
        final String uriPrefix = "uniformResourceIdentifier:";
        assertTrue("host.example.com did not parse as a correct URI name constraint",
                NameConstraint.parseNameConstraintEntry("uri:host.example.com").startsWith(uriPrefix));
        assertTrue(".example.com did not parse as a correct URI name constraint",
                NameConstraint.parseNameConstraintEntry("uri:.example.com").startsWith(uriPrefix));
        try {
            NameConstraint.parseNameConstraintEntry("uri:http://example.com");
            fail("URI name constraint should not contain a protocol.");
        } catch(CertificateExtensionException e) {
            //Expected
        }
        


    }

}
