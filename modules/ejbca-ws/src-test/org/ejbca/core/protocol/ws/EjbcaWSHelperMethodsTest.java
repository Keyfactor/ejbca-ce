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
package org.ejbca.core.protocol.ws;

import static org.junit.Assert.assertEquals;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.xml.bind.DatatypeConverter;

import org.ejbca.core.ejb.dto.CertRevocationDto;
import org.ejbca.ui.web.protocol.DateNotValidException;
import org.ejbca.util.KeyValuePair;
import org.junit.Test;

/**
 * Tests EjbcaWS helper methods.
 * 
 * @version $Id: EjbcaWSHelperMethodsTest.java 22930 2016-03-04 14:02:35Z tarmo_r_helmes $
 */
public class EjbcaWSHelperMethodsTest {

    private EjbcaWS ejbcaWS = new EjbcaWS();
    
    @Test
    public void testParseRevocationMetadataNormalFlow() throws DateNotValidException {
        CertRevocationDto certRevocationDto = new CertRevocationDto("issuerDN", "certificateSN");
        
        String reason = "4";
        String date = "2012-06-07T23:55:59+02:00";
        String certProfileId = "1200";
                
        List<KeyValuePair> metadata = new ArrayList<KeyValuePair>();
        metadata.add(new KeyValuePair("reason", reason));
        metadata.add(new KeyValuePair("revocationdate", date));
        metadata.add(new KeyValuePair("certificateprofileid", certProfileId));
        
        CertRevocationDto result = ejbcaWS.parseRevocationMetadata(certRevocationDto, metadata);
        assertEquals(Integer.valueOf(reason), result.getReason());
        assertEquals(DatatypeConverter.parseDateTime(date).getTime(), result.getRevocationDate());
        assertEquals(Integer.valueOf(certProfileId), result.getCertificateProfileId());
    }

    @Test
    public void testParseRevocationMetadataWithEmptyKeyvalueList() throws DateNotValidException {
        CertRevocationDto certRevocationDto = new CertRevocationDto("issuerDN", "certificateSN");

        List<KeyValuePair> metadata = Collections.emptyList();

        CertRevocationDto result = ejbcaWS.parseRevocationMetadata(certRevocationDto, metadata);
        assertEquals(null, result.getReason());
        assertEquals(null, result.getRevocationDate());
        assertEquals(null, result.getCertificateProfileId());
    }

    @Test
    public void testParseRevocationMetadataWithNullMetadataArgument() throws DateNotValidException {
        CertRevocationDto certRevocationDto = new CertRevocationDto("issuerDN", "certificateSN");

        List<KeyValuePair> metadata = null;

        CertRevocationDto result = ejbcaWS.parseRevocationMetadata(certRevocationDto, metadata);
        assertEquals(null, result.getReason());
        assertEquals(null, result.getRevocationDate());
        assertEquals(null, result.getCertificateProfileId());
    }

    @Test
    public void testParseRevocationMetadataWithUnknownKeyValue() throws DateNotValidException {
        CertRevocationDto certRevocationDto = new CertRevocationDto("issuerDN", "certificateSN");

        List<KeyValuePair> metadata = new ArrayList<KeyValuePair>();
        metadata.add(new KeyValuePair("unknownkey", "irrelevant value"));

        CertRevocationDto result = ejbcaWS.parseRevocationMetadata(certRevocationDto, metadata);
        assertEquals(null, result.getReason());
        assertEquals(null, result.getRevocationDate());
        assertEquals(null, result.getCertificateProfileId());
    }
}
