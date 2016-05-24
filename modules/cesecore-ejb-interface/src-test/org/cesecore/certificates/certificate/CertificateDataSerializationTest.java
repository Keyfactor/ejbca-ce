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
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.Date;

import org.apache.commons.codec.binary.Base64InputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests backwards and forwards compatibility with the CertificateData class,
 * and indirectly CertificateDataWrapper.
 * 
 * @version $Id$
 */
public class CertificateDataSerializationTest {

    private static final Logger log = Logger.getLogger(CertificateDataSerializationTest.class);
    
    /** CertificateData object that's intentionally missing the endEntityProfileId column */
    private static final String OLD_DATA = "rO0ABXNyADVvcmcuY2VzZWNvcmUuY2VydGlmaWNhdGVzLmNlcnRpZmljYXRlLkNlcnRpZmljYXRl" +
            "RGF0YYoibbY+5VZeAgASSgAKZXhwaXJlRGF0ZUoADnJldm9jYXRpb25EYXRlSQAQcmV2b2NhdGlv" +
            "blJlYXNvbkkACnJvd1ZlcnNpb25JAAZzdGF0dXNJAAR0eXBlSgAKdXBkYXRlVGltZUwACmJhc2U2" +
            "NENlcnR0ABJMamF2YS9sYW5nL1N0cmluZztMAA1jQUZpbmdlcnByaW50cQB+AAFMABRjZXJ0aWZp" +
            "Y2F0ZVByb2ZpbGVJZHQAE0xqYXZhL2xhbmcvSW50ZWdlcjtMAAtmaW5nZXJwcmludHEAfgABTAAI" +
            "aXNzdWVyRE5xAH4AAUwADXJvd1Byb3RlY3Rpb25xAH4AAUwADHNlcmlhbE51bWJlcnEAfgABTAAJ" +
            "c3ViamVjdEROcQB+AAFMAAxzdWJqZWN0S2V5SWRxAH4AAUwAA3RhZ3EAfgABTAAIdXNlcm5hbWVx" +
            "AH4AAXhwAAABnfKkEeD///////////////8AAAAAAAAAFAAAAAEAAAFUhbhajXB0ABAxMjM0NTY3" +
            "ODEyMzQ1Njc4c3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZh" +
            "LmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAF0ACgxOTRiNDcxMjJmMTcwMjA2NzcxNWVjZmIx" +
            "MTYyMTE1N2M5NmNmMmFidAALQ049Y2VydHVzZXJwdAATODc2NzYzODEyNDM1MTIyMjgzMXQAC0NO" +
            "PWNlcnR1c2VydAAcY1U1UXF2NDR1T0JzVGpnQXh5WmNVYnZGNnNrPXB0AAhjZXJ0dXNlcg==";
    
    /** CertificateData object that intentionally has a non-existing column called "testFutureColumn" */
    private static final String FUTURE_DATA = "rO0ABXNyADVvcmcuY2VzZWNvcmUuY2VydGlmaWNhdGVzLmNlcnRpZmljYXRlLkNlcnRpZmljYXRl" +
            "RGF0YYoibbY+5VZeAgAUSgAKZXhwaXJlRGF0ZUoADnJldm9jYXRpb25EYXRlSQAQcmV2b2NhdGlv" +
            "blJlYXNvbkkACnJvd1ZlcnNpb25JAAZzdGF0dXNJAAR0eXBlSgAKdXBkYXRlVGltZUwACmJhc2U2" +
            "NENlcnR0ABJMamF2YS9sYW5nL1N0cmluZztMAA1jQUZpbmdlcnByaW50cQB+AAFMABRjZXJ0aWZp" +
            "Y2F0ZVByb2ZpbGVJZHQAE0xqYXZhL2xhbmcvSW50ZWdlcjtMABJlbmRFbnRpdHlQcm9maWxlSWRx" +
            "AH4AAkwAC2ZpbmdlcnByaW50cQB+AAFMAAhpc3N1ZXJETnEAfgABTAANcm93UHJvdGVjdGlvbnEA" +
            "fgABTAAMc2VyaWFsTnVtYmVycQB+AAFMAAlzdWJqZWN0RE5xAH4AAUwADHN1YmplY3RLZXlJZHEA" +
            "fgABTAADdGFncQB+AAFMABB0ZXN0RnV0dXJlQ29sdW1ucQB+AAJMAAh1c2VybmFtZXEAfgABeHAA" +
            "AAGd8rEtWP///////////////wAAAAAAAAAUAAAAAQAAAVSFxXkJcHQAEDEyMzQ1Njc4MTIzNDU2" +
            "NzhzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5O" +
            "dW1iZXKGrJUdC5TgiwIAAHhwAAAAAXB0ACg0YTcyYTk0MGRhY2U3ZjcxYWE4OWYzYTcyNjVmYTRm" +
            "MGUwYzFlMGY3dAALQ049Y2VydHVzZXJwdAATMzUwNzY2NTg4NjI3NTcyOTY3NXQAC0NOPWNlcnR1" +
            "c2VydAAcUFg0eUc4cEs0b3JPZFBTU0hLMDMvOWtUcjBNPXBwdAAIY2VydHVzZXI=";
    
    /** CertificateData object that has a non-existent field "testNonExistentClass" with of a non-existent type "org.cesecore.certificates.certificate.NonExistent" */
    private static final String FUTURE_NEW_CLASS_DATA = "rO0ABXNyADVvcmcuY2VzZWNvcmUuY2VydGlmaWNhdGVzLmNlcnRpZmljYXRlLkNlcnRpZmljYXRl" +
            "RGF0YYoibbY+5VZeAgAUSgAKZXhwaXJlRGF0ZUoADnJldm9jYXRpb25EYXRlSQAQcmV2b2NhdGlv" +
            "blJlYXNvbkkACnJvd1ZlcnNpb25JAAZzdGF0dXNJAAR0eXBlSgAKdXBkYXRlVGltZUwACmJhc2U2" +
            "NENlcnR0ABJMamF2YS9sYW5nL1N0cmluZztMAA1jQUZpbmdlcnByaW50cQB+AAFMABRjZXJ0aWZp" +
            "Y2F0ZVByb2ZpbGVJZHQAE0xqYXZhL2xhbmcvSW50ZWdlcjtMABJlbmRFbnRpdHlQcm9maWxlSWRx" +
            "AH4AAkwAC2ZpbmdlcnByaW50cQB+AAFMAAhpc3N1ZXJETnEAfgABTAANcm93UHJvdGVjdGlvbnEA" +
            "fgABTAAMc2VyaWFsTnVtYmVycQB+AAFMAAlzdWJqZWN0RE5xAH4AAUwADHN1YmplY3RLZXlJZHEA" +
            "fgABTAADdGFncQB+AAFMABR0ZXN0Tm9uRXhpc3RlbnRDbGFzc3QAI0xvcmcvY2VzZWNvcmUvaW50" +
            "ZXJuYWwvTm9uRXhpc3RlbnQ7TAAIdXNlcm5hbWVxAH4AAXhwAAABnk5S8Nj///////////////8A" +
            "AAAAAAAAFAAAAAEAAAFU4Wc5Z3B0ABAxMjM0NTY3ODEyMzQ1Njc4c3IAEWphdmEubGFuZy5JbnRl" +
            "Z2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAA" +
            "AAFwdAAoNjlkOWEzYzI3N2ViYjg4ODZmMzQzYTRiNWEzM2ViYTVlNDJlZmEyM3QAC0NOPWNlcnR1" +
            "c2VycHQAEzYyODQxMDQwODE0Mjg3NzQxMTJ0AAtDTj1jZXJ0dXNlcnQAHFdXaUJwdTZidFVTRzZZ" +
            "RE4yT1dnazJsYi95ND1wcHQACGNlcnR1c2Vy";
    
    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }
    
    /** This test prints the serialized form of a CertificateData object, and was used to generated the data above. */
    @Test
    public void testSerializeCurrent() throws Exception {
        log.trace(">testSerializeCurrent");
        final KeyPair kp = KeyTools.genKeys("1024", "RSA");
        final Certificate cert = CertTools.genSelfCert("CN=certuser", 10*365, null, kp.getPrivate(), kp.getPublic(), "SHA256withRSA", false);
        final CertificateData certData = new CertificateData(cert, kp.getPublic(), "certuser", "1234567812345678", CertificateConstants.CERT_ACTIVE, CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, new Date().getTime(), false);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final Base64OutputStream b64os = new Base64OutputStream(baos);
        final ObjectOutputStream oos = new ObjectOutputStream(b64os);
        oos.writeObject(certData);
        oos.close();
        b64os.close();
        log.info("Base 64 of serialized CertData is: " + baos.toString("US-ASCII"));
        log.trace("<testSerializeCurrent");
    }
    
    @Test
    public void testDeserializeOld() throws Exception {
        log.trace(">testDeserializeOld");
        final ByteArrayInputStream bais = new ByteArrayInputStream(OLD_DATA.getBytes("US-ASCII"));
        final Base64InputStream b64is = new Base64InputStream(bais);
        final ObjectInputStream ois = new ObjectInputStream(b64is);
        final CertificateData certData = (CertificateData) ois.readObject();
        ois.close();
        assertEquals("certuser", certData.getUsername()); // unrelated column. should not be affected
        assertNull("End Entity Profile Id in CertificateData with old serialization.", certData.getEndEntityProfileId());
        assertEquals(EndEntityInformation.NO_ENDENTITYPROFILE, certData.getEndEntityProfileIdOrZero());
        log.trace("<testDeserializeOld");
    }
    
    @Test
    public void testDeserializeFuture() throws Exception {
        log.trace(">testDeserializeFuture");
        final ByteArrayInputStream bais = new ByteArrayInputStream(FUTURE_DATA.getBytes("US-ASCII"));
        final Base64InputStream b64is = new Base64InputStream(bais);
        final ObjectInputStream ois = new ObjectInputStream(b64is);
        final CertificateData certData = (CertificateData) ois.readObject();
        ois.close();
        assertEquals("certuser", certData.getUsername()); // unrelated column. should not be affected
        log.trace("<testDeserializeFuture");
    }
    
    @Test
    public void testDeserializeFutureFieldNewClass() throws Exception {
        log.trace(">testDeserializeFutureFieldNewClass");
        final ByteArrayInputStream bais = new ByteArrayInputStream(FUTURE_NEW_CLASS_DATA.getBytes("US-ASCII"));
        final Base64InputStream b64is = new Base64InputStream(bais);
        final ObjectInputStream ois = new ObjectInputStream(b64is);
        final CertificateData certData = (CertificateData) ois.readObject();
        ois.close();
        assertEquals("certuser", certData.getUsername()); // unrelated column. should not be affected
        log.trace("<testDeserializeFutureFieldNewClass");
    }
}
