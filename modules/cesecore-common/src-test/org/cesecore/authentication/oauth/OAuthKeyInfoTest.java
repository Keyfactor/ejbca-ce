package org.cesecore.authentication.oauth;

import org.cesecore.authentication.oauth.OAuthKeyInfo.OAuthProviderType;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.KeyTools;

public class OAuthKeyInfoTest {
    private static final String OAUTH_KEY = "OauthSystemTestKey";
    private static final String PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyiRvfMhXb1nLE+bQ8Dtg\n" +
            "P/YFPm6nesE+hNeSlxXQbdRI/Vd6djyynnptBVxZIvRmuax/zQRNqdK+FsoZKQGJ\n" +
            "978PuBhFoLsgCyccrqCEfO2kZp9atXFYoctgXW339Kj2bF5zRhYlSqCD/vBKcjCd\n" +
            "d6q0myEseplcPUzZXWbKHsdP4irjNRS3SwjKjetDBZ6FquAb5jXlSFH9JUx8iRYF\n" +
            "Bv4F3TDWC1NHFp3fpLovUjcZama6nrY7VQfnsLFY2YKPahQqikd4NSny2wmnonnw\n" +
            "Vyos88Ylt//DlzVgijMOvDE4TKF81g4qbd7x8B/JpPxdBk3gXdgJk8+S+scOqfPX\n" +
            "swIDAQAB\n" +
            "-----END PUBLIC KEY-----\n";

    @Test
    public void canLogOathKeyInfo() throws Exception {
        byte[] pubKeyBytes = KeyTools.getBytesFromPEM(PUBLIC_KEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY);

        OAuthKeyInfo oAuthKeyInfo = new OAuthKeyInfo(OAUTH_KEY, 6000, OAuthProviderType.TYPE_AZURE);
        oAuthKeyInfo.setUrl("https://login.microsoftonline.com/");
        oAuthKeyInfo.setAudience("api://f4b51ae1-77e0-4367-be11-5a43b6b20358");
        oAuthKeyInfo.setScope("api://f4b51ae1-77e0-4367-be11-5a43b6b20358/ejbca");
        oAuthKeyInfo.addPublicKey(OAUTH_KEY, pubKeyBytes);
        oAuthKeyInfo.createLogString();
    }

}
