package se.anatom.ejbca.protocol.junit;

import org.apache.log4j.Logger;

import junit.framework.*;

import com.meterware.httpunit.*;

import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.protocol.ScepRequestMessage;
import se.anatom.ejbca.util.Base64;

/** Tests http pages of ocsp and scep 
 **/
public class ProtocolHttpTest extends TestCase {
    private static Logger log = Logger.getLogger(TestMessages.class);

    private static final String httpReqPath = "http://127.0.0.1:8080/ejbca";
    private static final String resourceOcsp = "publicweb/status/ocsp";
    private static final String resourceScep = "publicweb/apply/scep/pkiclient.exe";

    static byte[] openscep = Base64.decode(("MIIGqwYJKoZIhvcNAQcCoIIGnDCCBpgCAQExDjAMBggqhkiG9w0CBQUAMIICuwYJ" +
            "KoZIhvcNAQcBoIICrASCAqgwggKkBgkqhkiG9w0BBwOgggKVMIICkQIBADGB1TCB" +
            "0gIBADA7MC8xDzANBgNVBAMTBlRlc3RDQTEPMA0GA1UEChMGQW5hVG9tMQswCQYD" +
            "VQQGEwJTRQIIbzEhUVZYO3gwDQYJKoZIhvcNAQEBBQAEgYCksIoSXYsCQPot2DDW" +
            "dexdFqLj1Fuz3xSpu/rLozXKxEY0n0W0JXRR9OxxuyqNw9cLZhiyWkNsJGbP/rEz" +
            "yrXe9NXuLK5U8+qqE8OhnY9BhCxjeUJSLni6oCSi7YzwOqdg2KmifJrQQI/jZIiC" +
            "tSISAtE6qi6DKQwLCkQLmokLrjCCAbIGCSqGSIb3DQEHATARBgUrDgMCBwQILYvZ" +
            "rBWuC02AggGQW9o5MB/7LN4o9G4ZD1l2mHzS+g+Y/dT2qD/qIaQi1Mamv2oKx9eO" +
            "uFtaGkBBGWZlIKg4mm/DFtvXqW8Y5ijAiQVHHPuRKNyIV6WVuFjNjhNlM+DWLJR+" +
            "rpHEhvB6XeDo/pd+TyOKFcxedMPTD7U+j46yd46vKdmoKAiIF21R888uVSz3GDts" +
            "NlqgvZ7VlaI++Tj7aPdOI7JTdQXZk2FWF7Ql0LBIPwk9keffptF5if5Y+aHqB0a2" +
            "uQj1aE8Em15VG8p8MmLJOX0OA1aeqfxR0wk343r44UebliY2DE8cEnym/fmya30/" +
            "7WYzJ7erWofO2ukg1yc93wUpyIKxt2RGIy5geqQCjCYSSGgaNFafEV2pnOVSx+7N" +
            "9z/ICNQfDBD6b83MO7yPHC1cXcdREKHHeqaKyQLiVRk9+R/3D4vEZt682GRaUKOY" +
            "PQXK1Be2nyZoo4gZs62nZVAliJ+chFkEUog9k9OsIvZRG7X+VEjVYBqxlE1S3ikt" +
            "igFXiuLC/LDCi3IgVwQjfNx1/mhxsO7GSaCCAfswggH3MIIBYKADAgEDAiA4OEUy" +
            "REVFNDcwNjhCQjM3RjE5QkE2NDdCRjAyRkQwRjANBgkqhkiG9w0BAQQFADAyMQsw" +
            "CQYDVQQGEwJTZTERMA8GA1UEChMIUHJpbWVLZXkxEDAOBgNVBAMTB1RvbWFzIEcw" +
            "HhcNMDMwNjAxMDgzNDQyWhcNMDMwNzAxMDgzNDQyWjAyMQswCQYDVQQGEwJTZTER" +
            "MA8GA1UEChMIUHJpbWVLZXkxEDAOBgNVBAMTB1RvbWFzIEcwgZ8wDQYJKoZIhvcN" +
            "AQEBBQADgY0AMIGJAoGBAOu47fpIQfzfSnEBTG2WJpKZz1891YLNulc7XgMk8hl3" +
            "nVC4m34SaR7eXR3nCsorYEpPPmL3affaPFsBnNBQNoZLxKmQ1RKiDyu8dj90AKCP" +
            "CFlIM2aJbKMiQad+dt45qse6k0yTrY3Yx0hMH76tRkDif4DjM5JUvdf4d/zlYcCz" +
            "AgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAGNoWI02kXNEA5sPHb3KEY8QZoYM5Kha1" +
            "JA7HLmlXKy6geeJmk329CUnvF0Cr7zxbMkFRdUDUtR8omDDnGlBSOCkV6LLYH939" +
            "Z8iysfaxigZkxUqUYGLtYHhsEjVgcpfKZVxTz0E2ocR2P+IuU04Duel/gU4My6Qv" +
            "LDpwo1CQC10xggHDMIIBvwIBATBWMDIxCzAJBgNVBAYTAlNlMREwDwYDVQQKEwhQ" +
            "cmltZUtleTEQMA4GA1UEAxMHVG9tYXMgRwIgODhFMkRFRTQ3MDY4QkIzN0YxOUJB" +
            "NjQ3QkYwMkZEMEYwDAYIKoZIhvcNAgUFAKCBwTASBgpghkgBhvhFAQkCMQQTAjE5" +
            "MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTAzMDYw" +
            "MTA4MzQ0MlowHwYJKoZIhvcNAQkEMRIEEBqGJFo7n4B8sFBCi54PckIwIAYKYIZI" +
            "AYb4RQEJBTESBBA77Owxh2rbflhXsDYw3xsLMDAGCmCGSAGG+EUBCQcxIhMgODhF" +
            "MkRFRTQ3MDY4QkIzN0YxOUJBNjQ3QkYwMkZEMEYwDQYJKoZIhvcNAQEBBQAEgYB4" +
            "BPcw4NPIt4nMOFKSGg5oM1nGDPGFN7eorZV+/2uWiQfdtK4B4lzCTuNxWRT853dW" +
            "dRDzXBCGEArlG8ef+vDD/HP9SX3MQ0NJWym48VI9bTpP/mJlUKSsfgDYHohvUlVI" +
            "E5QFC6ILVLUmuWPGchUEAb8t30DDnmeXs8QxdqHfbQ==").getBytes());

    static byte[] ocspcert = Base64.decode(("MIICfjCCAeegAwIBAgIIZTV+M+6x7q8wDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE" +
            "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMTIx" +
            "NTE0MDEyNloXDTA1MTIxNDE0MTEyNlowLzENMAsGA1UEAxMEVGVzdDERMA8GA1UE" +
            "ChMIUHJpbWVLZXkxCzAJBgNVBAYTAlNFMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB" +
            "iQKBgQCZSidwhgAWl79g3p2ZcBBIhKMSobNol10Gjl7QZMD6rUqxsh+H08Ni1Vld" +
            "dC9Lexiz+kp19LFzUEzuvZ8YcImemIHKUliO2ldRao2exq07rTAs4223MnFNeot2" +
            "1IgV/MSdPE5y8ZM9jgwD5W2eOyJa6Trn2YXj2S6I+Y2m21zhbwIDAQABo4GiMIGf" +
            "MA8GA1UdEwEB/wQFMAMBAQAwDwYDVR0PAQH/BAUDAwegADA7BgNVHSUENDAyBggr" +
            "BgEFBQcDAQYIKwYBBQUHAwIGCCsGAQUFBwMEBggrBgEFBQcDBQYIKwYBBQUHAwcw" +
            "HQYDVR0OBBYEFFJN5Z8dFNQEOVySeuz5celOKQYCMB8GA1UdIwQYMBaAFIed05jl" +
            "6vEGOIJw7X61o03WDfkvMA0GCSqGSIb3DQEBBQUAA4GBABDU2mB8ti0XKhEyI957" +
            "PPDpz+Bcd8fG2K7HkIC3DU2E61gSAXD05CFolCmGWxINU+eobrdXS8BWwc0fWi48" +
            "/BI8lmrDYNKodjfsn36jyi1M96ljSLwm/oWbxWdVQdC90tJz/S0BoP7tynCpRxdr" +
            "eIrDbfGEmrxcOBpUPTkK0tqL").getBytes());

    static byte[] ocspreq = Base64.decode(("MHAwbqACBQAwRTBDMEEwCQYFKw4DAhoFAAQUleclaLzPjnIsGxKO0zDiqGjYYgoE" +
            "FIed05jl6vEGOIJw7X61o03WDfkvAghlNX4z7rHur6IhMB8wHQYJKwYBBQUHMAEC" +
            "BBBgNVPKHnmzW70ZU1R8Nnw+").getBytes());
            
    public static void main( String args[] ) {
        junit.textui.TestRunner.run( suite() );
    }


    public static TestSuite suite() {
        return new TestSuite( ProtocolHttpTest.class );
    }


    public ProtocolHttpTest( String name ) {
        super( name );
    }

    protected void setUp() throws Exception {
        log.debug(">setUp()");

        // Install BouncyCastle provider
        CertTools.installBCProvider();

        // We want to get error responses without exceptions
        HttpUnitOptions.setExceptionsThrownOnErrorStatus(false);

        log.debug("<setUp()");
    }

    protected void tearDown() throws Exception {
    }


    public void test01Access() throws Exception {

        WebConversation wc   = new WebConversation();
        
        // Hit ocsp, gives a 500: Internal server error (TODO)
        WebRequest request   = new GetMethodWebRequest( httpReqPath + '/' + resourceOcsp );
        WebResponse response = wc.getResponse( request );
        assertEquals( "Response code", 500, response.getResponseCode() );
        // Hit scep, gives a 400: Bad Request
        request   = new GetMethodWebRequest( httpReqPath + '/' + resourceScep );
        response = wc.getResponse( request );
        assertEquals( "Response code", 400, response.getResponseCode() );
    }

    /** Tests scep message from OpenScep
     * Prerequisites for running the tests is to have a CA setup with 
     * issuerDN: CN=TestCA,O=AnaTom,C=SE.
     * @throws Exception error
     */
    public void test02OpenScep() throws Exception {
        log.debug(">test02OpenScep()");
        ScepRequestMessage msg = new ScepRequestMessage(openscep);
        // send message to server and see what happens
        WebConversation wc   = new WebConversation();
        WebRequest request = new GetMethodWebRequest( httpReqPath + '/' + resourceScep );
        request.setParameter("operation", "PKIOperation");
        request.setParameter("message", new String(Base64.encode(openscep)));
        WebResponse response = wc.getResponse( request );
        // TODO: since we our request most certainly uses the wrong CA cert to encrypt the 
        // request, it will fail. If we get something back, we came a little bit at least :)
        assertEquals( "Response code", 400, response.getResponseCode() );
        // TODO: send crap message and get good error
        
        log.debug("<test02OpenScep()");
    }
    /** Tests ocsp message
     * @throws Exception error
     */
    public void test03Ocsp() throws Exception {
        log.debug(">test03Ocsp()");
        // TODO: add  certificate with good status, 
        // send message to server and get good response
        // change status of cert to bad status
        // send message and get bad status
        // (send crap message and get good error)
        log.debug("<test03Ocsp()");
    }

}
