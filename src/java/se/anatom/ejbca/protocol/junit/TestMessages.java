package se.anatom.ejbca.protocol.junit;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.*;
import java.security.Provider;
import java.security.Security;

import se.anatom.ejbca.protocol.ScepRequestMessage;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.KeyTools;

import org.apache.log4j.*;
import junit.framework.*;

/** Tests signing session.
 *
 * @version $Id: TestSignSession.java,v 1.13 2002/10/17 15:24:47 anatom Exp $
 */
public class TestMessages extends TestCase {

    static byte[] keytoolp10 = Base64.decode(
    ("MIIBbDCB1gIBADAtMQ0wCwYDVQQDEwRUZXN0MQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNF"
    +"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDY+ATE4ZB0oKfmXStu8J+do0GhTag6rOGtoydI"
    +"eNX9DdytlsmXDyONKl8746478/3HXdx9rA0RevUizKSataMpDsb3TjprRjzBTvYPZSIfzko6s8g6"
    +"AZLO07xCFOoDmyRzb9k/KEZsMls0ujx79CQ9p5K4rg2ksjmDeW7DaPMphQIDAQABoAAwDQYJKoZI"
    +"hvcNAQEFBQADgYEAyJVobqn6wGRoEsdHxjoqPXw8fLrQyBGEwXccnVpI4kv9iIZ45Xres0LrOwtS"
    +"kFLbpn0guEzhxPBbL6mhhmDDE4hbbHJp1Kh6gZ4Bmbb5FrwpvUyrSjTIwwRC7GAT00A1kOjl9jCC"
    +"XCfJkJH2QleCy7eKANq+DDTXzpEOvL/UqN0=").getBytes());

    static byte[] oldbcp10 = Base64.decode(
    ("MIIBbDCB1gIBADAtMQswCQYDVQQGEwJTRTEPMA0GA1UEChMGQW5hVG9tMQ0wCwYDVQQDEwRUZXN0"
    +"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCzN9nDdwmq23/RLGisvR3CRO9JSem2QZ7JC7nr"
    +"NlbxQBLVqlkypT/lxMMur+lTX1S+jBaqXjtirhZTVaV5C/+HObWZ5vrj30lmsCdgzFybSzVxBz0l"
    +"XC0UEDbgBml/hO70cSDdmyw3YE9g5eH3wdYs2FCTzexRF3kNAVHNUa8svwIDAQABoAAwDQYJKoZI"
    +"hvcNAQEFBQADgYEAm6uRSyEmyCcs652Ttg2npm6JZPFT2qwSl4dviyIKJbn6j+meCzvn2TMP10d8"
    +"7Ak5sv5NJew1XGkM4mGpF9cfcVshxLVlW+cgq0749fWbyS8KlgQP/ANh3DkLl8k5E+3Wnbi0JjCV"
    +"Xe1s44+K2solX8jOtryoR4TMJ6p9HpsuO68=").getBytes());

    static byte[] iep10 = Base64.decode(
    ("MIICnTCCAgYCAQAwGzEZMBcGA1UEAxMQNkFFSzM0N2Z3OHZXRTQyNDCBnzANBgkq"
    +"hkiG9w0BAQEFAAOBjQAwgYkCgYEAukW70HN9bt5x2AiSZm7y8GXQuyp1jN2OIvqU"
    +"sr0dzLIOFt1H8GPJkL80wx3tLDj3xJfWJdww3TqExsxMSP+qScoYKIOeNBb/2OMW"
    +"p/k3DThCOewPebmt+M08AClq5WofXTG+YxyJgXWbMTNfXKIUyR0Ju4Spmg6Y4eJm"
    +"GXTG7ZUCAwEAAaCCAUAwGgYKKwYBBAGCNw0CAzEMFgo1LjAuMjE5NS4yMCAGCisG"
    +"AQQBgjcCAQ4xEjAQMA4GA1UdDwEB/wQEAwIE8DCB/wYKKwYBBAGCNw0CAjGB8DCB"
    +"7QIBAR5cAE0AaQBjAHIAbwBzAG8AZgB0ACAARQBuAGgAYQBuAGMAZQBkACAAQwBy"
    +"AHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgAgAHYAMQAu"
    +"ADADgYkAjuYPzZPpbLgCWYnXoNeX2gS6nuI4osrWHlQQKcS67VJclhELlnT3hBb9"
    +"Blr7I0BsJ/lguZvZFTZnC1bMeNULRg17bhExTg+nUovzPcJhMvG7G3DR17PrJ7V+"
    +"egHAsQV4dQC2hOGGhOnv88JhP9Pwpso3t2tqJROa5ZNRRSJSkw8AAAAAAAAAADAN"
    +"BgkqhkiG9w0BAQQFAAOBgQCL5k4bJt265j63qB/9GoQb1XFOPSar1BDFi+veCPA2"
    +"GJ/vRXt77Vcr4inx9M51iy87FNcGGsmyesBoDg73p06UxpIDhkL/WpPwZAfQhWGe"
    +"o/gWydmP/hl3uEfE0E4WG02UXtNwn3ziIiJM2pBCGQQIN2rFggyD+aTxwAwOU7Z2"
    +"fw==").getBytes());

    static byte[] openscep = Base64.decode(
    ("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").getBytes());

    static byte[] p12 = Base64.decode(
    ("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"
    +"AA==").getBytes());

    private PrivateKey privateKey = null;
    private X509Certificate caCert = null;
    
    static Category cat = Category.getInstance( TestMessages.class.getName() );

    public TestMessages(String name) {
        super(name);
    }
    protected void setUp() throws Exception {
        cat.debug(">setUp()");
        // Install BouncyCastle provider
        Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        int result = Security.addProvider(BCJce);

        KeyStore keyStore=KeyStore.getInstance("PKCS12", "BC");
        InputStream is = new ByteArrayInputStream(p12);
        String keyStorePass = "foo123";
        keyStore.load(is, keyStorePass.toCharArray());
        String privateKeyAlias= "privateKey";
        char[] pkPass = null;
        privateKey = (PrivateKey)keyStore.getKey(privateKeyAlias, pkPass);
        if (privateKey == null) {
            cat.error("Cannot load key with alias '"+privateKeyAlias+"' from keystore.");
            throw new Exception("Cannot load key with alias '"+privateKeyAlias+"' from keystore.");
        }
        Certificate[] certchain = KeyTools.getCertChain(keyStore, privateKeyAlias);
        caCert = (X509Certificate)certchain[0];
        cat.debug("<setUp()");
    }
    protected void tearDown() throws Exception {
    }

    public void test01TestOpenScep() throws Exception {
        cat.debug(">test01TestOpenScep()");
        ScepRequestMessage msg = new ScepRequestMessage(openscep);
        if (msg.requireKeyInfo()) {
            msg.setKeyInfo(caCert, privateKey);
        }
        boolean ret = msg.verify();
        assertTrue("Failed to verify SCEP message.", ret);
        cat.debug("<test01TestOpenScep()");
    }
}

