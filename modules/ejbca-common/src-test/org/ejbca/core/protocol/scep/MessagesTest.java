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

package org.ejbca.core.protocol.scep;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.Base64;
import org.cesecore.util.CryptoProviderTools;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Protocol messages.
 *
 * @version $Id$
 */
public class MessagesTest {

    private static PrivateKey privateKey = null;
    private static X509Certificate caCert = null;
    private static final Logger log = Logger.getLogger(MessagesTest.class);

    @BeforeClass
    public static void beforeClass() throws Exception {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProvider();

        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        InputStream is = new ByteArrayInputStream(p12);
        String keyStorePass = "foo123";
        keyStore.load(is, keyStorePass.toCharArray());

        String privateKeyAlias = "signKey";
        char[] pkPass = null;
        privateKey = (PrivateKey) keyStore.getKey(privateKeyAlias, pkPass);

        if (privateKey == null) {
            log.error("Cannot load key with alias '" + privateKeyAlias + "' from keystore.");
            throw new Exception("Cannot load key with alias '" + privateKeyAlias +
                    "' from keystore.");
        }

        Certificate[] certchain = KeyTools.getCertChain(keyStore, privateKeyAlias);
        caCert = (X509Certificate) certchain[0];
        //log.debug(caCert.toString());
    }

    @Test
    public void test01TestOpenScep() throws Exception {
        log.trace(">test01TestOpenScep()");
        ScepRequestMessage msg = new ScepRequestMessage(openscep, true);
        // You should be able to get issuer DN before anything else
        String issuerdn = msg.getIssuerDN();
        log.debug("IssuerDN: " + issuerdn);
        assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", issuerdn);
        if (msg.requireKeyInfo()) {
            msg.setKeyInfo(caCert, privateKey, null);
        }
        boolean ret = msg.verify();
        assertTrue("Failed to verify SCEP message from OpenSCEP.", ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("C=SE,O=Foo,CN=openscep", dn);
        String username = msg.getUsername();
        assertEquals("openscep", username);
        String pwd = msg.getPassword();
        log.debug("Pwd: " + pwd);
        assertEquals("foo123", pwd);
        log.trace("<test01TestOpenScep()");
    }

    /** Tests scep message from Simple Scep
     * @throws Exception error
     */
    @Test
    public void test02TestSimpleScep() throws Exception {
        log.trace(">test02TestSimpleScep()");
        ScepRequestMessage msg = new ScepRequestMessage(sscep, true);
        // You should be able to get issuer DN before anything else
        String issuerdn = msg.getIssuerDN();
        log.debug("IssuerDN: " + issuerdn);
        assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", issuerdn);
        if (msg.requireKeyInfo()) {
            msg.setKeyInfo(caCert, privateKey, null);
        }
        boolean ret = msg.verify();
        assertTrue("Failed to verify SCEP message from Simple Scep.", ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("C=SE,O=Foo,CN=openscep", dn);
        String username = msg.getUsername();
        assertEquals("openscep", username);
        String pwd = msg.getPassword();
        log.debug("Pwd: " + pwd);
        assertEquals("foo123", pwd);
        log.trace("<test02TestSimpleScep()");
    }

    /** Tests scep message from Java Scep Client
     * @throws Exception error
     */
    @Test
    public void test03TestJavaScepClient() throws Exception {
        log.trace(">test03TestJavaScepClient()");
        ScepRequestMessage msg = new ScepRequestMessage(scepclient, true);
        // You should be able to get issuer DN before anything else
        String issuerdn = msg.getIssuerDN();
        log.debug("IssuerDN: " + issuerdn);
        assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", issuerdn);
        if (msg.requireKeyInfo()) {
            msg.setKeyInfo(caCert, privateKey, null);
        }
        // This message is missing an IV which apparently wasn't required in
        // PKCS#7 but is in the RFCs. BouncyCastle 1.47 used to not allow this,
        // since but BC 1.48 does, we now allow also.
        boolean ret = msg.verify();
        assertTrue("Failed to verify SCEP message from Java Scep Client (without IV).", ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("C=SE,ST=Some-State,O=Foo,CN=scepclient", dn);
        String username = msg.getUsername();
        assertEquals("scepclient", username);
        String pwd = msg.getPassword();
        log.debug("Pwd: " + pwd);
        assertEquals("foo123", pwd);
        log.trace("<test03TestJavaScepClient()");
    }
    /** Tests scep message from Cisco VPN client
     * @throws Exception error
     */
    @Test
    public void test03TestCiscoVPNScep() throws Exception {
        log.trace(">test03TestCiscoVPNScep()");
        ScepRequestMessage msg = new ScepRequestMessage(ciscovpnscep, true);
        // You should be able to get issuer DN before anything else
        String issuerdn = msg.getIssuerDN();
        log.debug("IssuerDN: " + issuerdn);
        assertEquals("CN=AdminCA1,O=EJBCA Sample,C=SE", issuerdn);
        if (msg.requireKeyInfo()) {
            msg.setKeyInfo(caCert, privateKey, null);
        }
        boolean ret = msg.verify();
        assertTrue("Failed to verify SCEP message from Cisco VPN client.", ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("CN=ciscovpn", dn);
        String username = msg.getUsername();
        assertEquals("ciscovpn", username);
        String pwd = msg.getPassword();
        log.debug("Pwd: " + pwd);
        assertEquals("foo123", pwd);
        log.trace("<test03TestCiscoVPNScep()");
    }
    /** Tests scep message from Cisco PIX
     * @throws Exception error
     */
    /* This doesn't work because we don't have the right CA
    public void test04TestPixScep() throws Exception {
        log.trace(">test02TestPixScep()");
        ScepRequestMessage msg = new ScepRequestMessage(pixscep);
        // You should be able to get issuer DN before anything else
        String issuerdn = msg.getIssuerDN();
        log.debug("IssuerDN: " + issuerdn);
        assertEquals("E=postmaster@tdconline.dk,CN=tdcoca,OU=Online Privat,O=TDC", issuerdn);
        if (msg.requireKeyInfo()) {
            msg.setKeyInfo(caCert, privateKey);
        }
        boolean ret = msg.verify();
        assertTrue(ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("C=Se,O=PrimeKey,CN=Tomas G", dn);
        String pwd = msg.getPassword();
        log.debug("Pwd: " + pwd);
        assertEquals("foo123", pwd);
        assertTrue("Failed to verify SCEP message from PIX.", ret);
        log.trace("<test04TestPixScep()");
    } */
    
    @Test
    public void test05KeyToolP10() throws Exception {
        log.trace(">test05KeyToolP10()");
        PKCS10RequestMessage msg = new PKCS10RequestMessage(keytoolp10);

        boolean ret = msg.verify();
        assertTrue(ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("CN=Test,O=AnaTom,C=SE", dn);
        String pwd = msg.getPassword();
        assertNull(pwd);
        String username = msg.getUsername();
        assertEquals("Test", username);
        PublicKey pk = msg.getRequestPublicKey();
        assertNotNull(pk);
        String alg = pk.getAlgorithm();
        assertEquals("RSA",alg);
        
        log.trace("<test05KeyToolP10()");        
    }

    @Test
    public void test06OldBCP10() throws Exception {
        log.trace(">test06OldBCP10()");
        PKCS10RequestMessage msg = new PKCS10RequestMessage(oldbcp10);

        boolean ret = msg.verify();
        assertTrue(ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("C=SE,O=AnaTom,CN=Test", dn);
        String pwd = msg.getPassword();
        assertNull(pwd);
        String username = msg.getUsername();
        assertEquals("Test", username);
        PublicKey pk = msg.getRequestPublicKey();
        assertNotNull(pk);
        String alg = pk.getAlgorithm();
        assertEquals("RSA",alg);
        
        log.trace("<test06OldBCP10()");        
    }
    @Test
    public void test07IEP10() throws Exception {
        log.trace(">test07IEP10()");
        PKCS10RequestMessage msg = new PKCS10RequestMessage(iep10);

        boolean ret = msg.verify();
        assertTrue(ret);
        String dn = msg.getRequestDN();
        log.debug("DN: " + dn);
        assertEquals("CN=6AEK347fw8vWE424", dn);
        String pwd = msg.getPassword();
        assertNull(pwd);
        String username = msg.getUsername();
        assertEquals("6AEK347fw8vWE424", username);
        PublicKey pk = msg.getRequestPublicKey();
        assertNotNull(pk);
        String alg = pk.getAlgorithm();
        assertEquals("RSA",alg);
        
        log.trace("<test07IEP10()");        
    }

    @Test
    public void test08AltNameP10() throws Exception {
    	
    	// P10 generated with openssl
        PKCS10RequestMessage msg = new PKCS10RequestMessage(altnamep10);

        boolean ret = msg.verify();
        assertTrue(ret);
        String dn = msg.getRequestDN();
        assertEquals("C=AU,CN=asd,E=asd@sdf.se", dn);
        String pwd = msg.getPassword();
        assertEquals("dsfsdf", pwd);
        String username = msg.getUsername();
        assertEquals("asd", username);
        PublicKey pk = msg.getRequestPublicKey();
        assertNotNull(pk);
        String alg = pk.getAlgorithm();
        assertEquals("RSA",alg);
        
        // Get altNames if we can find them
        String altNames = msg.getRequestAltNames();
        assertEquals("rfc822name=foo@bar.se",altNames);
    }

    static byte[] keytoolp10 = Base64.decode(("MIIBbDCB1gIBADAtMQ0wCwYDVQQDEwRUZXN0MQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDY+ATE4ZB0oKfmXStu8J+do0GhTag6rOGtoydI" +
            "eNX9DdytlsmXDyONKl8746478/3HXdx9rA0RevUizKSataMpDsb3TjprRjzBTvYPZSIfzko6s8g6" +
            "AZLO07xCFOoDmyRzb9k/KEZsMls0ujx79CQ9p5K4rg2ksjmDeW7DaPMphQIDAQABoAAwDQYJKoZI" +
            "hvcNAQEFBQADgYEAyJVobqn6wGRoEsdHxjoqPXw8fLrQyBGEwXccnVpI4kv9iIZ45Xres0LrOwtS" +
            "kFLbpn0guEzhxPBbL6mhhmDDE4hbbHJp1Kh6gZ4Bmbb5FrwpvUyrSjTIwwRC7GAT00A1kOjl9jCC" +
    "XCfJkJH2QleCy7eKANq+DDTXzpEOvL/UqN0=").getBytes());
    static byte[] oldbcp10 = Base64.decode(("MIIBbDCB1gIBADAtMQswCQYDVQQGEwJTRTEPMA0GA1UEChMGQW5hVG9tMQ0wCwYDVQQDEwRUZXN0" +
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzN9nDdwmq23/RLGisvR3CRO9JSem2QZ7JC7nr" +
            "NlbxQBLVqlkypT/lxMMur+lTX1S+jBaqXjtirhZTVaV5C/+HObWZ5vrj30lmsCdgzFybSzVxBz0l" +
            "XC0UEDbgBml/hO70cSDdmyw3YE9g5eH3wdYs2FCTzexRF3kNAVHNUa8svwIDAQABoAAwDQYJKoZI" +
            "hvcNAQEFBQADgYEAm6uRSyEmyCcs652Ttg2npm6JZPFT2qwSl4dviyIKJbn6j+meCzvn2TMP10d8" +
            "7Ak5sv5NJew1XGkM4mGpF9cfcVshxLVlW+cgq0749fWbyS8KlgQP/ANh3DkLl8k5E+3Wnbi0JjCV" +
    "Xe1s44+K2solX8jOtryoR4TMJ6p9HpsuO68=").getBytes());
    static byte[] iep10 = Base64.decode(("MIICnTCCAgYCAQAwGzEZMBcGA1UEAxMQNkFFSzM0N2Z3OHZXRTQyNDCBnzANBgkq" +
            "hkiG9w0BAQEFAAOBjQAwgYkCgYEAukW70HN9bt5x2AiSZm7y8GXQuyp1jN2OIvqU" +
            "sr0dzLIOFt1H8GPJkL80wx3tLDj3xJfWJdww3TqExsxMSP+qScoYKIOeNBb/2OMW" +
            "p/k3DThCOewPebmt+M08AClq5WofXTG+YxyJgXWbMTNfXKIUyR0Ju4Spmg6Y4eJm" +
            "GXTG7ZUCAwEAAaCCAUAwGgYKKwYBBAGCNw0CAzEMFgo1LjAuMjE5NS4yMCAGCisG" +
            "AQQBgjcCAQ4xEjAQMA4GA1UdDwEB/wQEAwIE8DCB/wYKKwYBBAGCNw0CAjGB8DCB" +
            "7QIBAR5cAE0AaQBjAHIAbwBzAG8AZgB0ACAARQBuAGgAYQBuAGMAZQBkACAAQwBy" +
            "AHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAgAHYAMQAu" +
            "ADADgYkAjuYPzZPpbLgCWYnXoNeX2gS6nuI4osrWHlQQKcS67VJclhELlnT3hBb9" +
            "Blr7I0BsJ/lguZvZFTZnC1bMeNULRg17bhExTg+nUovzPcJhMvG7G3DR17PrJ7V+" +
            "egHAsQV4dQC2hOGGhOnv88JhP9Pwpso3t2tqJROa5ZNRRSJSkw8AAAAAAAAAADAN" +
            "BgkqhkiG9w0BAQQFAAOBgQCL5k4bJt265j63qB/9GoQb1XFOPSar1BDFi+veCPA2" +
            "GJ/vRXt77Vcr4inx9M51iy87FNcGGsmyesBoDg73p06UxpIDhkL/WpPwZAfQhWGe" +
            "o/gWydmP/hl3uEfE0E4WG02UXtNwn3ziIiJM2pBCGQQIN2rFggyD+aTxwAwOU7Z2" + 
            "fw==").getBytes());
    static byte[] openscep = Base64.decode(("MIIF3AYJKoZIhvcNAQcCoIIFzTCCBckCAQExDjAMBggqhkiG9w0CBQUAMIICvgYJ"+
            "KoZIhvcNAQcBoIICrwSCAqswggKnBgkqhkiG9w0BBwOgggKYMIIClAIBADGCAV8w"+
            "ggFbAgEAMEMwNzERMA8GA1UEAxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNh"+
            "bXBsZTELMAkGA1UEBhMCU0UCCFKNUA0mbQyIMA0GCSqGSIb3DQEBAQUABIIBADv6"+
            "P/L3m1syqxfcN8hTnLhEKDpV2381g6/C7TDHTI/2Ro8C8x1p9FP9AFJQv4XDCncB"+
            "EMeTyJxjuaHLdbx35uAZdOex38zwrczaaT+uf74OUVuyTKrRofctqjLFlaTXy8WL"+
            "KqUXwt0fefDmnZhThiXXcplnTs5/CgfQAyHOYI9/PvdUyIqEfK+/ixvVWSYk0vp6"+
            "jlYVwkSm06LiOysYbYp9B7nnbxBjjqKxK8vT7zjoId1U1ip2XB8mmfpw8Ahf3Mr2"+
            "508krK+pen3uwawVaeucqN2b1xySKxox/FFwkHfif1L33esx65mp4661SFUdHjOH"+
            "zuijrocx+Rj3S0w5/LUwggEqBgkqhkiG9w0BBwEwEQYFKw4DAgcECAMrD4EmoGjY"+
            "gIIBCJYOYZ8RkGoH/U9j7rzMxWPGbUmlEtNERUowB9dg+lWftUHuWwmao8uGwRHr"+
            "rPQ+QhTkGdMzwNG0PRAsG61M4Z7cF1o3URmAsXJpb/LiCGJoTX91L4SLtmBH9MRr"+
            "ZGPFWKzm7kzVWpcpXO2+/Gv9bdSt8hJWWaceZFJeB6q7yHu/Y/Eofj7biz5C3+v8"+
            "NcmDwsmNwBQwjTqpAVQ/1x52uA1lvaw7SKQ24L1kqm6nWA1XipbYRxBwvo23S5yb"+
            "CJrEwp4swLkccesTESOLoN4gM0WN2EBHnpdOL7ZcWQBOg/+/6oxeaXPw96lW1Q77"+
            "tYZuTnOfeaP5DY5lkUIEL4Yr81VloaPzsXo81qCCAW4wggFqMIIBFKADAgEDAiAw"+
            "QzUyMzQzNjcyNzEyRjczNEQ4M0M1MkRBMTg3RkExNDANBgkqhkiG9w0BAQQFADAu"+
            "MQswCQYDVQQGEwJTRTEMMAoGA1UEChMDRm9vMREwDwYDVQQDEwhvcGVuc2NlcDAe"+
            "Fw0wNTA4MDMxMTI4MTVaFw0wNTA5MDIxMTI4MTVaMC4xCzAJBgNVBAYTAlNFMQww"+
            "CgYDVQQKEwNGb28xETAPBgNVBAMTCG9wZW5zY2VwMFwwDQYJKoZIhvcNAQEBBQAD"+
            "SwAwSAJBAKk7hSPJ2yobo/jFJTucp6fjO+w//giNNloBR66DvFKkuJrmrf59Li8J"+
            "QXE3hOXWHgXUokYm3aVhMm9zomDh+F0CAwEAATANBgkqhkiG9w0BAQQFAANBADCU"+
            "MOSzoqI97EYM7ut0FzsKKe4MWr4ftMKyK/1if6ZmrqKhB5W/k7yHfmrFXc5PySAE"+
            "9NkIlvSO+ve9MTV1rkAxggF+MIIBegIBATBSMC4xCzAJBgNVBAYTAlNFMQwwCgYD"+
            "VQQKEwNGb28xETAPBgNVBAMTCG9wZW5zY2VwAiAwQzUyMzQzNjcyNzEyRjczNEQ4"+
            "M0M1MkRBMTg3RkExNDAMBggqhkiG9w0CBQUAoIHBMBIGCmCGSAGG+EUBCQIxBBMC"+
            "MTkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMDUw"+
            "ODAzMTEyODE1WjAfBgkqhkiG9w0BCQQxEgQQpw/eMRfE6qbrkh3Aw7ByQjAgBgpg"+
            "hkgBhvhFAQkFMRIEEDBi3ch9EaexEb/QHSvGkqIwMAYKYIZIAYb4RQEJBzEiEyAw"+
            "QzUyMzQzNjcyNzEyRjczNEQ4M0M1MkRBMTg3RkExNDANBgkqhkiG9w0BAQEFAARA"+
            "Y5xIjYsxIQLVM8M3B9/mxni08SEqVSXwWJYjFfg9ISx/j/IaDwHCisn7by4zW06e"+
    "4JaIa/rgTnUOJCZnLf4IuA==").getBytes());
    static byte[] sscep = Base64.decode(("MIIF3AYJKoZIhvcNAQcCoIIFzTCCBckCAQExDjAMBggqhkiG9w0CBQUAMIICvgYJ"+
            "KoZIhvcNAQcBoIICrwSCAqswggKnBgkqhkiG9w0BBwOgggKYMIIClAIBADGCAV8w"+
            "ggFbAgEAMEMwNzERMA8GA1UEAxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNh"+
            "bXBsZTELMAkGA1UEBhMCU0UCCFKNUA0mbQyIMA0GCSqGSIb3DQEBAQUABIIBACje"+
            "wUlnG2qbzoLZ0ZFovNZCtWbvEJKbYLX0sl7DUAzmGIjoEfQE1THar7Xzgj+xwnEk"+
            "ZoxJCu3JwzElpXd8ptPCe3gvdRv7XAqh0kZ2hgrHa51D/xX1j2pU0Fl6IkbEzFej"+
            "V8pN/7IqgB81g/neleo+k2UA0Jn2afKRoUZlZDidJz9tK+fumWOfPJBqTPghsVxx"+
            "+LPFZEeE1OOT/fnH0uuNRiFj43vY+CfY+YrspSadthRdWbDJTUJ+sBVBnh1xX83Q"+
            "6CjG22A4b+q8FUUta3+H8nnVLtAZfAwaU5/beTiw1t3UPMoJn8judZun2otWQbN0"+
            "az2XiiYvhapEvwLth2wwggEqBgkqhkiG9w0BBwEwEQYFKw4DAgcECPHxpAekbhIP"+
            "gIIBCKmFl5f+6wl04t9g2mD5vGwe1Nn/nG7tFn+m78HBdm+2DA03B+fCUu/Qvqnb"+
            "CeTd5qnLD90nOqzX73BUSTTnlttKG4kN4wmdTd603saz3OeCV3urrnRpVh7SIeAh"+
            "QMCG/Ul6XHTTCS1eVR88IbJmaLjNFeePQe1jz+yuJA/sikOlWPFiFkfJMMRhxxev"+
            "4+VOcpi+z4jKzQhkNkWUA2HqutnE7GZg4wiyn+iIXXHCeT4HnrqIIgEcuiJRVUIu"+
            "V/ySyE8TWg7mkJFEn/1rKo6J1V6Q8svFaziMvYFPw6h4ZHGJT6buTrjIEP6hZN+P"+
            "nf9ePrjLunkqexpIR+Ejrzlg4KYef692PEny9qCCAW4wggFqMIIBFKADAgECAiAw"+
            "QzUyMzQzNjcyNzEyRjczNEQ4M0M1MkRBMTg3RkExNDANBgkqhkiG9w0BAQQFADAu"+
            "MQswCQYDVQQGEwJTRTEMMAoGA1UEChMDRm9vMREwDwYDVQQDEwhvcGVuc2NlcDAe"+
            "Fw0wNTA4MDMxMTI2NTNaFw0wNTA4MDkxMzI2NTNaMC4xCzAJBgNVBAYTAlNFMQww"+
            "CgYDVQQKEwNGb28xETAPBgNVBAMTCG9wZW5zY2VwMFwwDQYJKoZIhvcNAQEBBQAD"+
            "SwAwSAJBAKk7hSPJ2yobo/jFJTucp6fjO+w//giNNloBR66DvFKkuJrmrf59Li8J"+
            "QXE3hOXWHgXUokYm3aVhMm9zomDh+F0CAwEAATANBgkqhkiG9w0BAQQFAANBADU3"+
            "m4OiT5RxWBb8tJE5LqQuz/kBH9qdwG+Bws/qVtsQjNGby1cY7QXNcBiUtmv3DTCo"+
            "WPWuJdJCC7C8s+iiAokxggF+MIIBegIBATBSMC4xCzAJBgNVBAYTAlNFMQwwCgYD"+
            "VQQKEwNGb28xETAPBgNVBAMTCG9wZW5zY2VwAiAwQzUyMzQzNjcyNzEyRjczNEQ4"+
            "M0M1MkRBMTg3RkExNDAMBggqhkiG9w0CBQUAoIHBMBIGCmCGSAGG+EUBCQIxBBMC"+
            "MTkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMDUw"+
            "ODAzMTEyNjUzWjAfBgkqhkiG9w0BCQQxEgQQNE7agWOiOWxGiuNFoVJ5vTAgBgpg"+
            "hkgBhvhFAQkFMRIEENX1p6qK9g+/tP1K8FPkOzwwMAYKYIZIAYb4RQEJBzEiEyAw"+
            "QzUyMzQzNjcyNzEyRjczNEQ4M0M1MkRBMTg3RkExNDANBgkqhkiG9w0BAQEFAARA"+
            "huyzMfvqURfBh3YZLyzLiKjucS2b72/TsN4Wo6Bes9mxIZOjc+BZ60M1MVhJtq0/"+
    "1ttZ62RT+p4E0axVW1bwWw==").getBytes());
    static byte[] scepclient = Base64.decode(("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"+
    "hQo=").getBytes());
    static byte[] ciscovpnscep = Base64.decode(("MIIGewYJKoZIhvcNAQcCoIIGbDCCBmgCAQExDjAMBggqhkiG9w0CBQUAMIIDJgYJ"+
            "KoZIhvcNAQcBoIIDFwSCAxMwggMPBgkqhkiG9w0BBwOgggMAMIIC/AIBADGCAV8w"+
            "ggFbAgEAMEMwNzERMA8GA1UEAxMIQWRtaW5DQTExFTATBgNVBAoTDEVKQkNBIFNh"+
            "bXBsZTELMAkGA1UEBhMCU0UCCFKNUA0mbQyIMA0GCSqGSIb3DQEBAQUABIIBAGnE"+
            "mtuxxdoWr+dr8OikckNWTQqT0JQoYh4sQRfE/PdQk1LEnkecdexEWCE51q+r2WN4"+
            "9iyUWOvmBA+xZEaZlFxTTZDx4YWJ/RDU91ZuVdLBxtCsSBo8p9gxMIWJCaqm+CMJ"+
            "R7jvUBWFUtI/0Z1ED7a/mYtI7OSc/awYAgjDEyCwxJIg9BYuPGJUxCuLdcQw2jHg"+
            "VLWfeZSnJyNoL+xCF53bvH8NG31ipfihpqlbbZLcigt9irxHst7d0VQdOVe0GH1z"+
            "TDW8yGNEwLB0+gCoGPnbzG6vMBURQtwS6cBBmWy5n/G5t1iS4IgITkqzE5VDdUsO"+
            "cAsJC0CFmooc2R1Kj1YwggGSBgkqhkiG9w0BBwEwEQYFKw4DAgcECE6lRDTM/hQ3"+
            "gIIBcM/ZXsVuwI/V1xPXJP4zjK3kiT5YM59ahj3Q+cL1eo7b9hYW9jqhczMsJP4B"+
            "Bt5slCouugiiinwQjkft5fdR95qAJx7LfG2T5KF+PiGIoeKWBduuoV8tdvyhE8Ag"+
            "0t9o9y43CdCQkA9OfHzGdS4QrpkaS3DlVUlD1QIQCTERCnOQvptIWkF3mDpbtjwM"+
            "PvmjiZXK1N+AoBmU0RFBqtrIySNRoZn4f+h/oUIfaJ2AUraPY9518ZRNQjbPoLMM"+
            "wdwQ8KuXgv0Ah7BR3ccDE+2Nen+k+8CAqJI73nxe6/Eq4VX32hwYmTkPY9dN1WtQ"+
            "sSIq8oFa2NhASc68FiNJEDDbdTgNvuIperePC/I/CzfRcBDAjGpCRioI8lymNQDA"+
            "xeWXHqGZjzs8h9FFF+5xM6SYSH9WRMmBCZGnayYMRvzVYpcp5tYkPI9OnPGwxKNw"+
            "dORv3INxwEoXtF8i0Pyc6138ZXgZ1l+sOjVYnmCkvMfZ8dQuoIIBrTCCAakwggES"+
            "oAMCAQICEF2HNzgvaHHRvp9UVOGL41IwDQYJKoZIhvcNAQEEBQAwEzERMA8GA1UE"+
            "AxMIY2lzY292cG4wHhcNMDUwODA0MTQzOTUyWhcNMDUwOTAzMTQzOTUyWjATMREw"+
            "DwYDVQQDEwhjaXNjb3ZwbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAp2LH"+
            "i5opb2EfEeVLiWNAYX8bM+Me5WQt2txneT0zfvoMmQixLIIMBzLlcsKrkATI/Ber"+
            "PgDNWlW9f0zXk71lYufijtf7TMNcwrjdDLQ3q9B1/PELkFicKpGLZ1z7Y4890pq0"+
            "YYIModioC5TxnSB/rSAG5VPIR9IeDirXQ19+wbMCAwEAATANBgkqhkiG9w0BAQQF"+
            "AAOBgQBa7jf/YY6mnP991J8HwWvHMs1gdMDLaBlA3ypQ9MYwUaNqduZDPnEAxhPz"+
            "fMuQncB1TIjAGbK24NtV3IOWWu+JMQmT2OL7Z8md5j/sVMAvlaVzWjAEfKq2dgEV"+
            "spo/lDwwbW8+WMgEnDrXOao/5zy1H0SB8XVsC+Jk9r8yT7eO+TGCAXYwggFyAgEB"+
            "MCcwEzERMA8GA1UEAxMIY2lzY292cG4CEF2HNzgvaHHRvp9UVOGL41IwDAYIKoZI"+
            "hvcNAgUFAKCBozASBgpghkgBhvhFAQkCMQQTAjE5MBgGCSqGSIb3DQEJAzELBgkq"+
            "hkiG9w0BBwEwHwYJKoZIhvcNAQkEMRIEELGqr8B3gk4zDxcuarvrVXIwIAYKYIZI"+
            "AYb4RQEJBTESBBDSWdNXDqxf6kR0/lhgow/mMDAGCmCGSAGG+EUBCQcxIhMgNUQ4"+
            "NzM3MzgyRjY4NzFEMUJFOUY1NDU0RTE4QkUzNTIwDQYJKoZIhvcNAQEBBQAEgYBt"+
            "aq3dXfzHpidRFn0iLdjlar0IqQVSyOiQHEaUanmCCk39QJ3pWmnXiPQCQfE9cptI"+
            "BpykteSCQxMvzTjEpGpZINObz1A9y/h3LtMidSsaxvMRxJSEapl50GzcLj0fhbSh"+
    "oCNO9WsRgdZH2qf4iZrHFefSN90eKifkzcyTyKLmIw==").getBytes());
    static byte[] pixscep = Base64.decode(("MIAGCSqGSIb3DQEHAqCAMIACAQExDjAMBggqhkiG9w0CBQUAMIAGCSqGSIb3DQEH" +
            "AaCAJIAEggOZMIAGCSqGSIb3DQEHA6CAMIACAQAxgDCCAYMCAQAwazBfMSYwJAYJ" +
            "KoZIhvcNAQkBFhdwb3N0bWFzdGVyQHRkY29ubGluZS5kazEPMA0GA1UEAxMGdGRj" +
            "b2NhMRYwFAYDVQQLEw1PbmxpbmUgUHJpdmF0MQwwCgYDVQQKEwNUREMCCD7fK8fm" +
            "K2DpMA0GCSqGSIb3DQEBAQUABIIBABlqDG3Jx7NJ4VLTb38JxUB3hhpRx+TUMmjZ" +
            "PG64gFDcK8aNSW5O8dIG09GcfD1dyaW1lwVRUpcFlraEWWCV3xjpM2wPARZ169dL" +
            "j1K/Y+s4mZsqppm45d0KT7jQ/e0oBJUukJq67rtc90Qyst4W9eGYERulxiQTOILD" +
            "x43IpHOGlr9ta1oTsxVKvB6mxdGSSdlkem6eozEkKe2cUbDPGVvc4/O5F/zK7jrb" +
            "L6woflqhwOc+faEOnuCETlr9MUvyN0XdMUbp6Rc3YQkfZj0otgPQ4GjCKfwtui2R" +
            "LT4eD4m0TOuwFlsV+E0YJJFMLxrhjowIeZap2HKSpZ6Qmhmv0EQAADCABgkqhkiG" +
            "9w0BBwEwEQYFKw4DAgcECB3fKGT54qD/oIAEggHAA1e6sQ+qC5YZ0BsYz2tKpWHk" +
            "+dTCsKvRByxTDTjz5xm21pVvyd5iM/k08S674uuxW+V91Rt4OJ13YOUuZ27dyfz8" +
            "rf/1kRFI0Y8He8Ye5mwJ5beAHiv4gb2hlci8doPp8FkeerB/HM1JxBV0/GQWugyo" +
            "b6Z3clqXa3WkTI1Pa8dIKql4a1QBi+iXiz+Tg8BR+yUIKHdmfc6HISOqGGmthB5+" +
            "x7uOjqK4unI3LILauAfRbeQQalFn/PUxQuxNJWf2A0lOwxxtIEVBX0XwxKkejuX6" +
            "CVxDKaTkt90g3zeZLYvsEdLieGPnw4NhC91/+NycQdjoOpEQCGHjgUGRwX2v0CKg" +
            "hMSpFLTrsWB/o5X6G/Z5mdAKGKVIoBIj15BxesJAAx8KI3Rni8opie/EWjiXOEwb" +
            "d6+Ie80jxxyccsXgpBLNnx8EUmQzU1RwWOq3jmzJCtDzKHljaqCxTi6uyFAbsCF9" +
            "Okl2Qj1qc+rX9ah+F53BDHfXuV3WpCFBSCxi7/G48LXc7Lna6vcEY9eYR3alpUDW" +
            "ciV7k92bQgBwwHuaXh4brb0MytCcgVUXEwHL6+GI9CHsMT6JlMezIsCTlqZlIwQI" +
            "57+qPArzctYAAAAAAAAAAAAAAAAAAAAAoIAwggI0MIIBnQIgNzBiNDg2ZmZmMmYy" +
            "ZWIxYzAzZmRiYjljOWFjNmE2MmEwDQYJKoZIhvcNAQEEBQAwUzFRMA8GA1UEBRMI" +
            "MzAxYjJkODkwGwYDVQQDExRodWwudGVrbmV0Lm9wYXNpYS5kazAhBgkqhkiG9w0B" +
            "CQIWFGh1bC50ZWtuZXQub3Bhc2lhLmRrMB4XDTA0MDMxMTA5MTQ1NFoXDTE0MDMw" +
            "OTA5MTQ1NFowUzFRMA8GA1UEBRMIMzAxYjJkODkwGwYDVQQDExRodWwudGVrbmV0" +
            "Lm9wYXNpYS5kazAhBgkqhkiG9w0BCQIWFGh1bC50ZWtuZXQub3Bhc2lhLmRrMIGf" +
            "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/AtkNDP14TWSkJqDCtPu3T3JeqvyY" +
            "3Jqww+3ZNfUbs9njCycuiajHbbDVKEyffXCOtzE7GtkcSXJZKntbTICT7N4M+eot" +
            "EHOtri3l9DkvXWqdvHw21d4i83q+NKPkaXmo6h5yIwmtDQEVIccLDwQydMb0XDgK" +
            "PjCOm9MC33Pm2wIDAQABMA0GCSqGSIb3DQEBBAUAA4GBAAzXcoUUTmNV4UyxZ/01" +
            "FHafeqQJmmq66+TrIXUAcwfWyvtgIRGDb/kif2NsjDtvFvnlXUiM57K/I+/qVqQm" +
            "HF1Thx1L/sbvNwWqYZxyWJPm1TQaw2zvAu0Hpc53/T49dH8LgYYrwEOXRTyW5YE1" +
            "9fMRCmp78VeN/nJyoOGcJKigAAAxgDCCAcICAQEwdzBTMVEwDwYDVQQFEwgzMDFi" +
            "MmQ4OTAbBgNVBAMTFGh1bC50ZWtuZXQub3Bhc2lhLmRrMCEGCSqGSIb3DQEJAhYU" +
            "aHVsLnRla25ldC5vcGFzaWEuZGsCIDcwYjQ4NmZmZjJmMmViMWMwM2ZkYmI5Yzlh" +
            "YzZhNjJhMAwGCCqGSIb3DQIFBQCggaMwEgYKYIZIAYb4RQEJAjEEEwIxOTAYBgkq" +
            "hkiG9w0BCQMxCwYJKoZIhvcNAQcBMB8GCSqGSIb3DQEJBDESBBCQVbLp6teJEWNq" +
            "nBD/Kr1GMCAGCmCGSAGG+EUBCQUxEgQQbpDDbO95LE1U7ZbbEe2p8TAwBgpghkgB" +
            "hvhFAQkHMSITIDcwYjQ4NmZmZjJmMmViMWMwM2ZkYmI5YzlhYzZhNjJhMA0GCSqG" +
            "SIb3DQEBAQUABIGAfiGzBNxJiy4XI3DG13Osso4qV+7rvwg+CVbe0gqt01s1kd5A" +
            "LxwTYVhXXKG1spaBnebu+T9xZDZqvF9eY1ANJVNSIpNygKmJdhjsJivKFkD9Jz2y" +
            "F/BYZzv618HlvZQj9Sbv7PaODRU4xqGVifa6LllK/572uQdUQj3FTkssqFQAAAAA" +
    "AAAAAA==").getBytes());
    
    static byte[] altnamep10 = Base64.decode(("MIIBwjCCASsCAQAwNjELMAkGA1UEBhMCQVUxDDAKBgNVBAMTA2FzZDEZMBcGCSqG"+
    		"SIb3DQEJARYKYXNkQHNkZi5zZTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA"+
    		"ymEA1OVfAznYHDoYmKZ1TkNuIqfujryGN3ROrarCA6OdWteWG8IPxZBu1q70CNYz"+
    		"H7AEasvCncL3PajeltBET4jJ/0vLx/JTttoNRXjyxqIxbcWJ7b9g0IkvF8z2fsfn"+
    		"CLH5MgFzy8GPj40qxIFRgROafgdgvjhGTPJsxqbRG1cCAwEAAaBMMBUGCSqGSIb3"+
    		"DQEJBzEIEwZkc2ZzZGYwMwYJKoZIhvcNAQkOMSYwJDAVBgNVHREEDjAMgQpmb29A"+
    		"YmFyLnNlMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0BAQUFAAOBgQAk+ue+2+KsjZlZ"+
    		"9b/vtRHp3db/MQVB2qR4LTWbRE5HyexMtI29DCyveDTHmBS6DZej+4XdkkSSihft"+
    		"zeGs+DWneGZu8YaxLXeyeNEkfCaUmQp6n8CprExxfCZKsGEERrzLcGN4QiaD9RIg"+
    "INAmCWYYOtX6k4uJLY6gsOO4FD9sAA==").getBytes());
    
    static byte[] p12 = Base64.decode(("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCCvIwgDCABgkqhkiG9w0BBwGggCSABIIK" +
            "2jCCCtYwggVmBgsqhkiG9w0BDAoBAqCCBPkwggT1MCcGCiqGSIb3DQEMAQMwGQQU" +
            "M9v7H78lfcE5imiW09/BzSilz+0CAWQEggTIq8j9XRSKczoqkW8oBbYpLUM2F3ic" +
            "alq86KdAsJPhiKlxYmf56ylUg8c1DBJIIw9/kj84rZ3YMzTenWCvroa7KIZdGoIy" +
            "lWMUcKgYD/0dzR+tApz7WQMs7MA7eaEx6w1O/ppdEI5ISDb38uR8xDAuPxsRYavV" +
            "tFDJs6f9GBdyfhSJsX+FJv7NcoEPRw6As8+SJzFMRHj8+VvtUgE8BFAXsZ8C5DkF" +
            "e0fO0nISJEHOPRDoWH3o0MXKSm3HBPIDZjvlb3Wg9Rv08gOf1kcRpu6OI89dloo5" +
            "wX4NRq/j+aA6Q+AWCH148DfGK1a455d847N36gMwsTRFnyOx1rSTIoSXI/2kPCN5" +
            "dvylCbLxQuo+qEY+SHvBFP9t3GvE/dIYHz1hq3Ze8/Buf4HOL7HUW6WwcabYjZx/" +
            "xGpSHUSwGnhYRyyVpWEQySIa0/QKijJsNBK7Y/GCus4w0pNeTYwP1HCrEDupRgFF" +
            "IG3bSUFCH7kjr3IfAGP45PJXlFkqQna92NEFHOfT3LupE/gkwdPr2iGlOps9v9Jw" +
            "aKWF+dNgoTSGV39cxVNJ8nn4qpetfTOLNxvTC7cK1mMaGPLytB7GV4rkp34PY5JR" +
            "HDg5svKFRgp184wZgD/9MoRLU0JT9RfnY6DFJOUoA6R1L3SkoY4cvJQDgK5YaXyY" +
            "uyYKfJGcX6I/g2eZuYvooWk+jM2XFuWEQxpF3GgwenvWh0sQfOBE91Afh17z7lHx" +
            "1/4zJE6YUjHYyed0mUQQs/imoLgxzvHZ29vGU1qj6gtxyYdQaXnUpHrnvJeR7Q8g" +
            "XgF7YzTbitx6y12pP+zIXkIiigTTxYrF3+adkacAqLM7mNk7IMFLjv/N7AcUrAkK" +
            "+EUeH27cQB27yfjEX0wqxUSrV9DS1uwTwqvS6UFWVZP1G/VkBpc/A+MAwekUGGH9" +
            "ByQimhHeg3tIeQ4bSAXr9pM/xzi8dk8MYJw1+l8az5LaYsgbO9iFUwUVDZfwuOD7" +
            "8FRQKmEx9Q7+jeCd7j6o/B/AnDL9dmpc/n1nnC0zKkROEI8ZU2ErkCcnOFnvAMW+" +
            "Gzjz769KGMO59iZRXC8YjL2T8iB5SH9wgrGH+pZ4HRGtnoHsrwhXMmPshsR+USNs" +
            "V3/HH+5XgU9HQukHxVd6lwI3jvJbtO4jvzPpH2Uj6poNAL3+pNrRshNRc54gNOuz" +
            "pwtTAS9e6SKBU3D44KZ//RYpKMYm+Or5gfNTYJN8lSCRtD0/iD32V5LOwnPK2PZi" +
            "G0DAZ6ne37IUWS4p5yjeCqZDzhjh37z+D7sbyqVPSR5TzdN7Tjyv7BSe73XWbVME" +
            "qxyVmiXYaTYMdQ2KpfPfTSQTKJhyAhBbwEYE3E0me9UVz3syJc/UBkodxKJPiTJo" +
            "VIWEfZ6AxxhqMhJGy2gDZgR/nn518EI21Pca99ehwfBakJc2qDAUYYFkT3laL1ks" +
            "YP/OT0vAqqiqT/J08owUcxO4cRCZVk2zz94bq/SggQ1T5DuliZaMJ43TcBeW2hzr" +
            "DH9Qra3MoBdJu+F+Dw9YXMpZv+97fOnpTwBWBgz/LkDf4/OMDy0CAgN8V9lzwg0w" +
            "vNw/PemztRpGnLI9xR77iZ4LB+iyeDtALyaznqnnKf4oZP1Uhds2mgsNxNAa1Om0" +
            "EWkuMVowIwYJKoZIhvcNAQkVMRYEFGdq7yBdfjk4/bYULRgeEaIt3crGMDMGCSqG" +
            "SIb3DQEJFDEmHiQAcAByAGkAdgBhAHQAZQBkAGUAYwBrAGUAeQBhAGwAaQBhAHMw" +
            "ggVoBgsqhkiG9w0BDAoBAqCCBPkwggT1MCcGCiqGSIb3DQEMAQMwGQQU897tECd+" +
            "HTblVRmacnpGAAanf6YCAWQEggTIyiJzXF0VFCH9y94VtbDlHhA74rJ3GY2HG6js" +
            "dgTuPrs6WL1qGzVqyBh0K/No5WHGggxXtr0tNirGAY+OxWzCPeROqCDudsCHp9vP" +
            "aZPBojPTdXH/ZBj0JNUYCnmIg3Z29u2l7HR/d92qH02Su4PnwyyrjMUHuFys6ltF" +
            "IsvXfv87oWlfE777jDh3qQcfBSF6C/aZH/kuVmvPIEVl0MbBdOFrScK3gJOTapeS" +
            "bb/JwGXzV63tJD+s5LqkEPkLTEFK8jMikVvmhVlbUL8Wcd4bve3coFSZ01QwxJBG" +
            "6i9R4C7SOU05IcKCWlOrqefkv/gVZOfWAWvlCwizXIusYi0vOAcTK/1FBfMXtkDj" +
            "LP2xMRrSlNUVFhj22ZTo2/xxwWu6gxFO72bP00CLIFB2GIW7tT18v7FNll5Kd9mB" +
            "naHFikeE+JsXeywxsUVSTwSDeR8+kT1ObPFR6oIDGz9JKkJ/l5cAWlkSmz4PCiU4" +
            "my4jEoZZMO/mGSL5RWMjQKPNd0evijHul0KA5Q3E1lQDWPFb4j5VSne88C6vDdt3" +
            "4FQPe/+d0VPMKZKeWkVRiOm61V/RB+7EEskNbAUEASeiSPvLb/1abUCiTVZhExra" +
            "be0T3KY+yqeXRIvraSED/+8wKZfmpL6aV0VXjtfs+zfE23anAv6FZMG/Br+zP+AN" +
            "WjIgCy0WqG4r6OsCAWQGz0kv5m43fP/PouCyMwolqwlO48YGARTp0dN7/0ZIymft" +
            "HslyOTm2nIAWJL3F2Um+ij5jr7zFZU5Y0VW327iIkN9Z7jQezULu2nRpY2HKNvB5" +
            "WNNTf+k0H3L6bsjeQ0xCru4o1fTw+jyYs0oTThmrzdg4zMCZo73ZvvLGUwPrVeGm" +
            "Dc7hX2Ladf/e0fAJGZWEhyxQDwWAYgxaJQJ3HxnHc5dlAFgendwxvc2DbWVQGxCo" +
            "IOngMB5oCabMurHeKrqSlNeKq3NqzirDnrMzAe+6eigXd3X8YCCcgSeV8mf2n+lN" +
            "VluUepojm6CZpauWEJsffLG2I+sglxNYv4YeiIcvpRj9+2Y9ngJ30aZm+YUZ7dBl" +
            "Dnsh85bhLeApG65h9j8Gv4Hg8pdCSF4qdYOx/5ewfHXctAEBZNUi9ON0UB0mKSw4" +
            "ISQYyBTtrUvTPqJwTsiq3k7Y52j4rBrIJyIIn3ffYGZPDpXFmrI4a73heNbT2kTD" +
            "+NJVRSwZfX+4qykP0PIrxAupW28MQR7N67NmpgTeNmQyP2k2GbqhwMUkRxjaZk0e" +
            "zM2ErY6PMIOgxUDMYakCC0STfoA5svp1bPhKINqhQHp63EWMbEVAVBUX2IGZ1nfY" +
            "YS3W3lXbKowdnGfuhFkNg8NnMD8CEsmVCULj2LuxEFH+KWVzNnCJ1e1X07ygSUKL" +
            "z3RJqMDL8DOA6kxSYRICL8WaNuJIAIDrVq4jNG/2QXvLqfgySNmiEka+A/wGqBFm" +
            "GmzaptwyXbgwY9LnHpl90FFuCM/FIB83l1MFWflf+iTpfK3cZ6AlNyPN9xZ+ANRg" +
            "gUz626jNa+nUgWcNMRaVCYHcjJAAsVdqYjO7Cn6iHrE5jzAKYSTn8d7Twm1e9a8+" +
            "LeiG7UfPILknNwqbdarj5tS+/44f/t5iYqxMfknPYriBvj3b2QSyPp8RWEy/MVww" +
            "IwYJKoZIhvcNAQkVMRYEFAf9ikWDTmcUQ5CeaAoYzXl4MLQnMDUGCSqGSIb3DQEJ" +
            "FDEoHiYAcAByAGkAdgBhAHQAZQBzAGkAZwBuAGsAZQB5AGEAbABpAGEAcwAEAQAE" +
            "AQAEAQAEAQAEggeKADCABgkqhkiG9w0BBwaggDCAAgEAMIAGCSqGSIb3DQEHATAn" +
            "BgoqhkiG9w0BDAEGMBkEFL9IGozYO+/gw0lMa/ZD7qticoAzAgFkoIAEggc4A2bR" +
            "LXs1Gqb9nvqgnA3xlL0hek4U2lYUIFMywrKnIUiWQJLmfHf87u23Ij0KKH3VjXgA" +
            "ZPaBEzGoksSJVZaJXeO6QrvtwBSoQ+2aEjIXKMz3x9RxojzQl/BUO8iA/INIPjY4" +
            "N4EmdrEGaKZH8WrBVXjgGI+Wjrl7zikvj7rrmE82EomrcUneO9eLj1lCRbSr2jCN" +
            "k7dGSj9q9fpqsONSJZFsf2OUwlINQWdwTB1O+7c00f38tPP3VXqhADjxZlTTlDzV" +
            "RsC8Jp7JOcHgyCADreRSvt/8fZ7ix6qrr9exvjNc811onCJ0bF1nxHuPa7QIXSNL" +
            "zy8QalL71YFNeiGic7zEXUpF+ZssOl7nTHNSel3jqMrOsh7KKw+/JSZNciZOxrxa" +
            "WeeiJXd3F5zQHUTMZ60GNlLUb5MlHM5QBrO5txsmdw8qM7cnj4l1e0Uv0pUfWSNb" +
            "E3BR3UE064jXbyH3n4DQD9CZ6n/jEDTbRTgtbgQJYq8kfZtJG0qmoxzs6c40GKUI" +
            "ZmWCGTFC4oEInnJ1vV6cltNxlftCuDNwA12y5S4z+nOftLe5FRaiECY4CuvdGJrS" +
            "5wJF/DrkJydzXSYw7zr3bvzc0uLNVoN9E3Ul1QH7tTFCgMg+mgTNXqGRP86HjTdk" +
            "92so0e5Fd3UnVAdg9CHVmhKRa30fv7DENtNaAKC8uKaJjAy3iXRVD9pSrvGoRLko" +
            "zigz6AGrEgYMZGS8Oyt9r6b7V5DsqNvbg9dZIxm+JpavhnnlRxx0vOjvoS9OO0+A" +
            "039NUbB4/60f9DaUZem286vgBV2NaV072hmyzob0PxMeIAP//bG9GQloQvJdDaxy" +
            "hQLXSaFk0e0zH5QvCv42VvHxB+gqKH3mjEdPtbDiRyVIsrSDR5uM83oHwBfa/Z3C" +
            "LMenxrLojndEaDW0wwyqFucnTaamOhF0h7aqzmO/Y4QIF7gryNao0N7nYgNiLR/p" +
            "UWY2kzJ617xj99rwssffOOYx88tSzXPJSjtktHTRD2uEDbpvlRXUsDJbbLcG5CFp" +
            "Gv9inKiEiKarihLqQfXjhN2/Y4vi5eE1/PjBMIZ+2jeKg2DLrwjZfhs6AT9JN+48" +
            "RUncJGlJHf0wR+ofDBVf/WIhjzWEjFkTJgyK9PqSoMB5DmY5kzUyUwN2ChXWaNf/" +
            "cIPmsdVgcrCr058OoYIoevLgCwem3qpr67vgGJFBsm+qsEzGogiZ8Y4R1J/H5Xcx" +
            "DiIdxnu4HyL/e/Nunt83ulmdf6MtVaQqGV5fm96LGIyrFXlWsHgwssSg6u52ysLf" +
            "Gt883UTnBgsKzYrZVbUyBT+MTJrbvex5zwVX9myf3DwW5AgNDZ3UTrhqdRw+izMC" +
            "VBdd2thRLSi35mzHrwD9O49K9LCQ0e4w7c5H0+33Q3jO7TS5r65LmqFeXJ2tzP3i" +
            "RS5eyEFVr4GyrI0L9+Zvt6TLBLsYsi1V8du6SRngCvEVYx7+ysfVwWEpbQXVbGq/" +
            "EVJph+GqvxsiN6ohtS6j0XRnbtFLr5Cmw/GjgbgBX2dGP7KB9BTy8/ccmCrJX3Xw" +
            "jxuBUBHOpsQcUV9G/s5ZSCWAi5cgifwfgLcPAaF8qNXENFNz0Vz+LMNgEi7WZXs+" +
            "siFkww6XFH4dRTSWxRq2H96ch8FmYeZubiyqzyQIW7yDtxpQkvO2QDQMto6kT/aB" +
            "L00KX6DnJ+XXVjk9vvCVAG64JWBkJ4VX+TD3FkcbTZnTXZq+epehRm0FRDSarncC" +
            "OfCU3vCjyya/1sLpkBR4H+KArvcCimKnJvHkBjQkcfK/Uq7gl1YuG3Yuh1Mt4XHp" +
            "+N9RqF2l6UT+D7aLcfTzd1/+M6g+DJw6B/8dglYrF8VnaI8b3FXFSToRLgQFILBW" +
            "4DaaUSj7MjRpQgxBQzHrV2FrF0MwhKyEJhv7H22DSspyPOcRddGq/kpf1ZuKyG8M" +
            "wkfgPZMQ7M97ha13aQt6PAXJhZKVddP3U+i46UjzpaTOrB2XTMjoPBjKTdqc3/tt" +
            "VrGF6a+YQqQf7/lMPAT3AhKuBveH1+IGbYKLZwSKIAWV3i3RX3kCCflYJNJOiR0v" +
            "+AERvsR7zqCPX5k9OdFva3PUHTnhpCIezSeIcmJG/rY3Omfw8dAkzT0F0dq/wYdv" +
            "7nfhSbQg8UbUAI6EZsk9tYwpNVeEAur5IOFyR9tlaNHXb5D4uXeGRZqH5F1uxZt3" +
            "J383Y8qvC4vmTboTRfJ6VYuc/2BckW5REXpKGH6nLbsZf3rTwjj+4pd1wI40dVS7" +
            "K22WVfkGy2BDo/5kR93yFEuZvEWmG8s9JvACiKjkefvq9qQk3PG4ljdHjR8UYzHA" +
            "S3Dniak/FFnVhvHPwMs9qs2OYaIF+BKG7k4Qr34SCRmR0tvfVdvV+5ZyRVDbruLi" +
            "ATW8ahl9i725+n/EknOyupv1RfDI8mX3WJFU+Nink45aVe0lB6sZNcGOGNLrwNup" +
            "UxxOH7kAlxTAOK+lW94r0saD5ZY6AAQBAAQBAAQBAAQBAAQBAAQBAAQBAAQBAAQB" +
            "AAQBAAQBAAAAAAAAADA8MCEwCQYFKw4DAhoFAAQURCoC9aMwMaUQwabHmxqHNPDm" +
    "Jb4EFAtXS2+0nByy9M2RLJ2xjB38iCBOAgFkAAA=").getBytes());
    
}
