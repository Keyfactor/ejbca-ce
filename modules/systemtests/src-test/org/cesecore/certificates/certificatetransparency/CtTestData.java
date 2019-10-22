/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificatetransparency;

import java.util.Arrays;
import java.util.LinkedHashSet;

/**
 * Test data for {@link CTLogTest}, {@link CtSubmissionUnitTest} and {@link org.ejbca.core.protocol.ocsp.extension.certificatetransparency.OcspCtSctListExtensionUnitTest OcspCtSctListExtensionUnitTest}
 * @version $Id: CtTestData.java 32399 2019-05-23 12:38:25Z samuellb $
 */
public final class CtTestData {

    /** Contains constants only, cannot be instantiated */
    private CtTestData() { }

    /** ECC (secp256r1) CT log public key for tests. */
    public static final String CTLOG_PUBKEY =
        "-----BEGIN PUBLIC KEY-----\n"+
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAnXBeTH4xcl2c8VBZqtfgCTa+5sc\n"+
        "wV+deHQeaRJQuM5DBYfee9TQn+mvBfYPCTbKEnMGeoYq+BpLCBYgaqV6hw==\n"+
        "-----END PUBLIC KEY-----\n";

    /** RSA CT log public key for tests. */
    public static final String CTLOG_PUBKEY_RSA =
        "-----BEGIN PUBLIC KEY-----\n"+
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAz2chYUrdonHHL2hUCaP4\n"+
        "WkJllWsdT4aJsVlJMeNN0kOQ9z7LX6PuWVMd/NuzOqDqunWAJ4Tehl8QBV65mfok\n"+
        "lYFeqW4I+1ntwgj5neHKbIC2DHUDIk8vw2KdM4HqJczLucvVF9L7l9ZnS5mZI8jl\n"+
        "vi7Ccty5EuV9ukPn00TvJLD5FvyzR2w4YsrBgh2WRmcTM+nBxvTH0+VXEszUafcv\n"+
        "2pXn0CvJiy4Q3UOCvuodo177MZbYW8G6YfpeHVF6h4gjRGRekmaNuVAQ7hCXnR6n\n"+
        "QYDnNDmp0a/sSMEUwQ8VxGRmh7I7VTipBjNpyz9cKpKIv1HEiKAOLtZJ9oa1j8tZ\n"+
        "RQIDAQAB\n"+
        "-----END PUBLIC KEY-----\n";

    /*
       For reference, here are the corresponding private keys:
         -----BEGIN EC PRIVATE KEY-----
         MHcCAQEEIMB3j4gK7fPI6KsQfvlUHefxBXJSZT/9hwExN+lcq15WoAoGCCqGSM49
         AwEHoUQDQgAEAnXBeTH4xcl2c8VBZqtfgCTa+5scwV+deHQeaRJQuM5DBYfee9TQ
         n+mvBfYPCTbKEnMGeoYq+BpLCBYgaqV6hw==
         -----END EC PRIVATE KEY-----

         -----BEGIN PRIVATE KEY-----
         MIIEowIBAAKCAQEAz2chYUrdonHHL2hUCaP4WkJllWsdT4aJsVlJMeNN0kOQ9z7L
         X6PuWVMd/NuzOqDqunWAJ4Tehl8QBV65mfoklYFeqW4I+1ntwgj5neHKbIC2DHUD
         Ik8vw2KdM4HqJczLucvVF9L7l9ZnS5mZI8jlvi7Ccty5EuV9ukPn00TvJLD5Fvyz
         R2w4YsrBgh2WRmcTM+nBxvTH0+VXEszUafcv2pXn0CvJiy4Q3UOCvuodo177MZbY
         W8G6YfpeHVF6h4gjRGRekmaNuVAQ7hCXnR6nQYDnNDmp0a/sSMEUwQ8VxGRmh7I7
         VTipBjNpyz9cKpKIv1HEiKAOLtZJ9oa1j8tZRQIDAQABAoIBAQC5BbbIlcIs5bWc
         /ERkKUwoMS1wY5NNW6dAeHeMssu89RvBBdrmYlcChtyss84rUly0pJgEKUtesjWX
         pM6Mp5O1cCjjm08V9D7fp6QPjdtIenZtnIGEPQJOGo5E4fPhbtab1FQwob5i0Rlr
         XwY330PdKte7Il9UlThZT7TjS47PuhmXDKgSBgx4CIbQ8210Fp3f1dk5xncP1at6
         fDsMq8UQictNR9PGHS5z3TZMOJiveAMZY318JvNxAla5P1+qWVflzEdPB5gCh6ca
         ABE4PRa98HnYxNeQoKC1QyBtXGDOAgNRva+4088aqt/xlJM0xQu5PRLIPLLO+47I
         VUefr/2hAoGBAPGWnd0LTlD2VD1WrhryeYO3bYx2pDRJaPMPjR4g5VnrAxP6DBhg
         H29qGcwGzm97K6qEqzDjEWHAvBf3wq6WghDRZrUhuTcfoyTZChyi8FjmddHR9krt
         JNtw0EvQGvKhyKhFLoh4OM3KhVzHdcflSeMKCsV7LSHMMRqPHubyYQK5AoGBANvG
         dGSCMVxY8VovSaOs2Z2goMq71bTo3YWQ3rwiwuXZ3DlIEv99c3ykdI7WEC2KonqR
         qjy1G8QWYOXAb5pu0aq2i2QKfNpXYjS0Rei6TaB9rqDjRPnnrpEVJ8T8MdGwnUmW
         HMIRdmn+aLPv6QhAd1OKcQb4441Cfa6CS3SMwHTtAoGACwHby3h6ZwHyMKFEaYHm
         u3OeECpPrPozR+/LdDX3fTNR/pUD/BBVHlRtPHiK61VnVeuZiS6vWg7YAxeMzTua
         TX3c+h/BOpu8aS9iYI+j98j4UUkJubw4U68+LlYbBDcO12vfhORFYkr57JJB8Yum
         5CtO9lR4Z/PPwPAIbmlYtjECgYBAVgMinR44C21z2h3zhRkbVLddQclYsUaP4A3k
         A0UMpk8akafGFQJmvXnFipKn0kqoGNY9+UKMj4SEHWZOThygndmGSq+r9yKvjQpe
         C5PH5KLnRECf65ulqwy+VJl86ffRX9lBUn1Yn/okmpmcKcsEsKVPxjJO2uUR3eCa
         2M1KLQKBgAIFtWmhJ9YTqq17EHIfg1/ZczZquRSIC2ARPP2cuY15wNDZY3vn7xF6
         vu8EBLn6mEsqw0V1neTRJgH7tpToKpJoTIwjWbuBfWzGxr4AaQGsPz1VqSvnv+lp
         1ruRNPUo4njx19N/N7oGQ0BhasqLN3isyKP9BoRCCtKJ3GZdpFoh
         -----END PRIVATE KEY-----

    */

    /** A pre-certificate that can be used in tests to submit to logs */
    public static final String TESTCERT_PRECERTIFICATE =
        "-----BEGIN CERTIFICATE-----\n"+
        "MIIC/TCCAeWgAwIBAgIIbbcUPEaKD9swDQYJKoZIhvcNAQEFBQAwEDEOMAwGA1UE\n"+
        "AwwFQ1RfQ0EwHhcNMTQwMTI0MTUyNjIwWhcNMTYwMTI0MTUyNjIwWjAUMRIwEAYD\n"+
        "VQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJZrH/VY\n"+
        "DMTpygXGexMA3EiWQImUnBXckRqNRCavlahfr5dJjwLoWU6PdJ1lXj7/Jd+G/bkH\n"+
        "4numNYMJaMuM8BSuHzYFCv5X2PT3jfvGTqRcaLiUaiBg5w/I7OeUdpghGUTOVSfh\n"+
        "Rq40AG/rf862pI8uvP47UIVUbZ3TF/jB4WQtAgMBAAGjgdowgdcwTQYIKwYBBQUH\n"+
        "AQEEQTA/MD0GCCsGAQUFBzABhjFodHRwOi8vbG9jYWxob3N0OjgwODAvZWpiY2Ev\n"+
        "cHVibGljd2ViL3N0YXR1cy9vY3NwMB0GA1UdDgQWBBSBeGqpCRQonbKazBbc8XLr\n"+
        "uQoYJDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFL0BDnDYpt3yd21xDfPSB1Rq\n"+
        "xJLlMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATATBgorBgEE\n"+
        "AdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQUFAAOCAQEANjq3mbCMLZD5e4NSaM4t\n"+
        "qp4duuoB8g0osJoEsizcwrRqvOcTHQVJtSeq0kXvp22vO+Zpexn+/h+G0qzJi1rl\n"+
        "cMTkOFPg7mzXNX4hEbl2Ev8jg6WZkmPwPUwi9B3ih4Z6lgyxtPBxWrNSILkn8DXM\n"+
        "maq6KaF4LF0uHP2CoGlBuD3dQgryal4fX3LD0TpflGPX9JBVjAeb4hGF9BMMfjza\n"+
        "UHUypjZut38DcdpKiYqDAqWRqzUAzjWSkw2zXdmKbR4mbWjB98rox87sXccDgPMm\n"+
        "v5JvTL3eFR6U6pUVg5zQu/LKAMNvJZI76ohsLzt4+mqDZpKzWzbJhDsfdNEoCIrc\n"+
        "Ow==\n"+
        "-----END CERTIFICATE-----";

    /** Certificate that issued the above pre-certificate */
    public static final String ISSUER_CERT =
        "-----BEGIN CERTIFICATE-----\n"+
        "MIIDBTCCAe2gAwIBAgIIdBK7GhWMJRUwDQYJKoZIhvcNAQEFBQAwEDEOMAwGA1UE\n"+
        "AwwFQ1RfQ0EwHhcNMTQwMTE1MTYzNzA5WhcNMzkwMTE2MTYzNzA5WjAQMQ4wDAYD\n"+
        "VQQDDAVDVF9DQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJImASBN\n"+
        "WCU8Hp9/9Gx0Qdkm/sT2SCTd/rebFoVcSs6IIezxelTe78APjrTlMUcW1kgJpdBL\n"+
        "F7Wop63eIIIYXYZ51frJpFv+G+ajE9rv3UOWY0KrFLsvQVobjj6YlPK+oymRhr7N\n"+
        "EAmx1qHqs395TFp0fHipglnPd9GtbOxNisbgBMKf6Fa8zMu1eIGskkJJq5Gxb1x/\n"+
        "8FXq9z0iKtyqaBEZUTg/9bmmAQQbdAPErCdqToVxAmfAA8fbJz8TLDef5k9YLkN3\n"+
        "56hKeatve9yERpwGCtiAP9lysnRFrbKSnuTIQK4W16VGy1iiH3bqYMa0GJ0byUI1\n"+
        "QvjCwWtDoNQ3GIECAwEAAaNjMGEwHQYDVR0OBBYEFL0BDnDYpt3yd21xDfPSB1Rq\n"+
        "xJLlMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUvQEOcNim3fJ3bXEN89IH\n"+
        "VGrEkuUwDgYDVR0PAQH/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQCIQFQKdExf\n"+
        "QT5QXqDdayLv+c+O4WhTbUgoPgBPfSFjITFXu1BKT0MH9/mEzEur7LrKdl+DVCF/\n"+
        "U1cmJqFsZ0DibTUz8qaFPQWdLXWwO1EUFyYt5DhLd6zFDDvdQhOZwKhn4lw3G2wo\n"+
        "zlE1cFZftYxXx1VRyu6SORyuK9phXI5b9LwjVh2cq+AFdW5xPeuwFv+ilBYWLtbg\n"+
        "3pDra15oIiZBXWOWDzKsO6VjaoGT1cd30vXNjSQOWilzITjeeuhxehB33zOAz7zK\n"+
        "1ANve5w3xQaHP+O2T2J1FRkQdEvQ9K237HLUffdnX6rSKPAgHTFkhvHpTNfPbvWe\n"+
        "FMhasVpiobc6\n"+
        "-----END CERTIFICATE-----\n";

    /** Request for the {@link #TESTCERT_PRECERTIFICATE pre-certificate} */
    public static final String REQUEST = "{\"chain\":[\"MIIC\\/TCCAeWgAwIBAgIIbbcUPEaKD9swDQYJKoZIhvcNAQEFBQAwEDEOMAwGA1UEAwwFQ1RfQ0EwHhcNMTQwMTI0MTUyNjIwWhcNMTYwMTI0MTUyNjIwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJZrH\\/VYDMTpygXGexMA3EiWQImUnBXckRqNRCavlahfr5dJjwLoWU6PdJ1lXj7\\/Jd+G\\/bkH4numNYMJaMuM8BSuHzYFCv5X2PT3jfvGTqRcaLiUaiBg5w\\/I7OeUdpghGUTOVSfhRq40AG\\/rf862pI8uvP47UIVUbZ3TF\\/jB4WQtAgMBAAGjgdowgdcwTQYIKwYBBQUHAQEEQTA\\/MD0GCCsGAQUFBzABhjFodHRwOi8vbG9jYWxob3N0OjgwODAvZWpiY2EvcHVibGljd2ViL3N0YXR1cy9vY3NwMB0GA1UdDgQWBBSBeGqpCRQonbKazBbc8XLruQoYJDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFL0BDnDYpt3yd21xDfPSB1RqxJLlMA4GA1UdDwEB\\/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDATATBgorBgEEAdZ5AgQDAQH\\/BAIFADANBgkqhkiG9w0BAQUFAAOCAQEANjq3mbCMLZD5e4NSaM4tqp4duuoB8g0osJoEsizcwrRqvOcTHQVJtSeq0kXvp22vO+Zpexn+\\/h+G0qzJi1rlcMTkOFPg7mzXNX4hEbl2Ev8jg6WZkmPwPUwi9B3ih4Z6lgyxtPBxWrNSILkn8DXMmaq6KaF4LF0uHP2CoGlBuD3dQgryal4fX3LD0TpflGPX9JBVjAeb4hGF9BMMfjzaUHUypjZut38DcdpKiYqDAqWRqzUAzjWSkw2zXdmKbR4mbWjB98rox87sXccDgPMmv5JvTL3eFR6U6pUVg5zQu\\/LKAMNvJZI76ohsLzt4+mqDZpKzWzbJhDsfdNEoCIrcOw==\",\"MIIDBTCCAe2gAwIBAgIIdBK7GhWMJRUwDQYJKoZIhvcNAQEFBQAwEDEOMAwGA1UEAwwFQ1RfQ0EwHhcNMTQwMTE1MTYzNzA5WhcNMzkwMTE2MTYzNzA5WjAQMQ4wDAYDVQQDDAVDVF9DQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJImASBNWCU8Hp9\\/9Gx0Qdkm\\/sT2SCTd\\/rebFoVcSs6IIezxelTe78APjrTlMUcW1kgJpdBLF7Wop63eIIIYXYZ51frJpFv+G+ajE9rv3UOWY0KrFLsvQVobjj6YlPK+oymRhr7NEAmx1qHqs395TFp0fHipglnPd9GtbOxNisbgBMKf6Fa8zMu1eIGskkJJq5Gxb1x\\/8FXq9z0iKtyqaBEZUTg\\/9bmmAQQbdAPErCdqToVxAmfAA8fbJz8TLDef5k9YLkN356hKeatve9yERpwGCtiAP9lysnRFrbKSnuTIQK4W16VGy1iiH3bqYMa0GJ0byUI1QvjCwWtDoNQ3GIECAwEAAaNjMGEwHQYDVR0OBBYEFL0BDnDYpt3yd21xDfPSB1RqxJLlMA8GA1UdEwEB\\/wQFMAMBAf8wHwYDVR0jBBgwFoAUvQEOcNim3fJ3bXEN89IHVGrEkuUwDgYDVR0PAQH\\/BAQDAgGGMA0GCSqGSIb3DQEBBQUAA4IBAQCIQFQKdExfQT5QXqDdayLv+c+O4WhTbUgoPgBPfSFjITFXu1BKT0MH9\\/mEzEur7LrKdl+DVCF\\/U1cmJqFsZ0DibTUz8qaFPQWdLXWwO1EUFyYt5DhLd6zFDDvdQhOZwKhn4lw3G2wozlE1cFZftYxXx1VRyu6SORyuK9phXI5b9LwjVh2cq+AFdW5xPeuwFv+ilBYWLtbg3pDra15oIiZBXWOWDzKsO6VjaoGT1cd30vXNjSQOWilzITjeeuhxehB33zOAz7zK1ANve5w3xQaHP+O2T2J1FRkQdEvQ9K237HLUffdnX6rSKPAgHTFkhvHpTNfPbvWeFMhasVpiobc6\"]}";
    /** Response from log with ECC key */
    public static final String RESPONSE1 = "{ \"sct_version\": 0, \"id\": \"lGljh1qL8fzjxhH73aEKyd9JDiyTYHrNI7+aBxUtqSI=\", \"timestamp\": 1390577780967, \"extensions\": \"\", \"signature\": \"BAMASDBGAiEA\\/tWriYIw7e1ykLy4sfjvpA7nmaab9egkZ\\/ntPlSVyY8CIQDC96pimyvkaHxM4PQj5v0CD9qByuX96yVYTAmotrFU8A==\" }";
    /** Response from log with RSA key. The test server software does not support RSA keys, so this was generated by modifying LogSignatureVerifier.verifySCTSignatureOverBytes so it prints the data, and then by signing it. */
    public static final String RESPONSE2 = "{ \"sct_version\": 0, \"id\": \"WbLMe8HhGCzC9okx7xkREyB2NjYfgQlxduhVaI7IAJM=\", \"timestamp\": 1390577780967, \"extensions\": \"\", \"signature\": \"BAEBAKIRTUIAFXcX5LJIBMByotTbMqkDFbBLUKTYVthsF2rzu00GuZ82wjCpI/q2DKaok3c7nVaJg0jJS+oQ4IoXo/6EWpiCvHUU0N/vaE75W5HhaJb1z0nEL0Yy4cgrbCK8XpQQy+c7G9uU4MsohUwWqauJoMOAdlPooXQZYapyH8JvNEt/l75vdPI5drNgw0i/Knmqs02jBocEuZr82BwLNiygyJE5IC2DI9li9lixYtBuvFYPGgf0huU4BJgUIynbImcAMdeuflBXEM1howyrpWY3IBTZJxFB2BqBHV4da+ozb4JMxbqGWzUs02kV+3dJ13YwM3YNruUOz5n+o9blQ7c=\" }";
    /**
     * An ECC log SCT for {@link #RESPONSE1}. Generated by Google's old CT server software, from https://github.com/google/certificate-transparency/ .
     * This includes the length header for the SCT List extension.
     */
    public static final byte[] RESPONSE_SCT1 = new byte[] { 0, 121, 0, 119, 0, -108, 105, 99, -121, 90, -117, -15, -4, -29, -58, 17, -5, -35, -95, 10, -55, -33, 73, 14, 44, -109, 96, 122, -51, 35, -65, -102, 7, 21, 45, -87, 34, 0, 0, 1, 67, -60, -27, 8, -25, 0, 0, 4, 3, 0, 72, 48, 70, 2, 33, 0, -2, -43, -85, -119, -126, 48, -19, -19, 114, -112, -68, -72, -79, -8, -17, -92, 14, -25, -103, -90, -101, -11, -24, 36, 103, -7, -19, 62, 84, -107, -55, -113, 2, 33, 0, -62, -9, -86, 98, -101, 43, -28, 104, 124, 76, -32, -12, 35, -26, -3, 2, 15, -38, -127, -54, -27, -3, -21, 37, 88, 76, 9, -88, -74, -79, 84, -16 };
    /**
     * An RSA log SCT for {@link #RESPONSE1}. Generated by Google's old CT server software, from https://github.com/google/certificate-transparency/ .
     * This includes the length header for the SCT List extension.
     */
    public static final byte[] RESPONSE_SCT2 = new byte[] { 1, 49, 1, 47, /* = length */ 0, /* = version (v1) */
        /* LogID = */89, -78, -52, 123, -63, -31, 24, 44, -62, -10, -119, 49, -17, 25, 17, 19, 32, 118, 54, 54, 31, -127, 9, 113, 118, -24, 85, 104, -114, -56, 0, -109,
        /* timestamp = */ 0, 0, 1, 67, -60, -27, 8, -25,
        /* extensions = */ 0, 0,
        /* Sign info = SHA256, RSA */4, 1,
        /* Sign length */1, 0,
        /* Sign =  */-94, 17, 77, 66, 0, 21, 119, 23, -28, -78, 72, 4, -64, 114, -94, -44, -37, 50, -87, 3, 21, -80, 75, 80, -92, -40, 86, -40, 108, 23, 106, -13, -69, 77, 6, -71, -97, 54, -62, 48, -87, 35, -6, -74, 12, -90, -88, -109, 119, 59, -99, 86, -119, -125, 72, -55, 75, -22, 16, -32, -118, 23, -93, -2, -124, 90, -104, -126, -68, 117, 20, -48, -33, -17, 104, 78, -7, 91, -111, -31, 104, -106, -11, -49, 73, -60, 47, 70, 50, -31, -56, 43, 108, 34, -68, 94, -108, 16, -53, -25, 59, 27, -37, -108, -32, -53, 40, -123, 76, 22, -87, -85, -119, -96, -61, -128, 118, 83, -24, -95, 116, 25, 97, -86, 114, 31, -62, 111, 52, 75, 127, -105, -66, 111, 116, -14, 57, 118, -77, 96, -61, 72, -65, 42, 121, -86, -77, 77, -93, 6, -121, 4, -71, -102, -4, -40, 28, 11, 54, 44, -96, -56, -111, 57, 32, 45, -125, 35, -39, 98, -10, 88, -79, 98, -48, 110, -68, 86, 15, 26, 7, -12, -122, -27, 56, 4, -104, 20, 35, 41, -37, 34, 103, 0, 49, -41, -82, 126, 80, 87, 16, -51, 97, -93, 12, -85, -91, 102, 55, 32, 20, -39, 39, 17, 65, -40, 26, -127, 29, 94, 29, 107, -22, 51, 111, -126, 76, -59, -70, -122, 91, 53, 44, -45, 105, 21, -5, 119, 73, -41, 118, 48, 51, 118, 13, -82, -27, 14, -49, -103, -2, -93, -42, -27, 67, -73
        };

    // Since we're communicating with a web server we might perhaps get a HTML message back instead of JSON
    public static final String NON_JSON_RESPONSE = "<html><head><title>I'm a HTML page</title></head>\n<body background=\"red\">&lt; Error! &gt;</body></html>";

    public static final String LOG_LABEL_A = "Log Label A";
    public static final String LOG_LABEL_B = "Log Label B";
    public static final String LOG_LABEL_C = "Log Label C";
    public static final LinkedHashSet<String> LABELS_A = new LinkedHashSet<>(Arrays.asList(LOG_LABEL_A));
    public static final LinkedHashSet<String> LABELS_A_B = new LinkedHashSet<>(Arrays.asList(LOG_LABEL_A, LOG_LABEL_B));
}
