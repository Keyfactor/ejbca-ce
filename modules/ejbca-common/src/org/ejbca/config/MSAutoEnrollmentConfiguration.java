package org.ejbca.config;

import org.cesecore.configuration.ConfigurationBase;

/**
 * Configuration for the Microsoft Auto Enrollment
 */
public class MSAutoEnrollmentConfiguration extends ConfigurationBase {
    private static final long serialVersionUID = 1L;
    public static final String CONFIGURATION_ID = "MS_AUTO_ENROLLMENT";

    // Configuration elements here.

    // MSAE Kerberos
    private static final String MSAE_DOMAIN = "msaeDomain";

    // MSAE Settings
    private static final String IS_USE_SSL = "isUseSSL";
    private static final String AD_CONNECTION_PORT = "adConnectionPort";
    private static final String AD_LOGIN_DN = "adLoginDN";
    private static final String AD_LOGIN_PASSWORD = "adLoginPassword";

    // MS Enrollment Servlet Settings
    private static final String KEY_STORE_PATH = "keyStorePath";
    private static final String KEY_STORE_PASSWORD = "keyStorePassword";
    private static final String TRUSTED_KEY_STORE_PATH = "trustedKeyStorePath";
    private static final String TRUSTED_KEY_STORE_PASSWORD = "trustedKeyStorePassword";
    private static final String CA_NAME = "caName";


    private static int DEFAULT_AD_CONNECTION_PORT = 389;

    public MSAutoEnrollmentConfiguration() {
        initWithDefaults();
    }

    private void initWithDefaults() {
        // TODO: Set default values.

        // MSAE Kerberos
        setMsaeDomain("");

        // MSAE
        setIsUseSsl(false);
        setAdConnectionPort(DEFAULT_AD_CONNECTION_PORT);
        setAdLoginDN("");
        setAdLoginPassword("");

        // MS Servlet Settings
        setKeyStorePath("");
        setKeyStorePassword("");
        setTrustedKeyStorePath("");
        setTrustedKeyStorePassword("");
        setCaName("");
    }

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            data.put(VERSION, Float.valueOf(LATEST_VERSION));
        }
    }

    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }

    // MSAE Kerberos Settings
    public String getMsaeDomain() {
        return (String) data.get(MSAE_DOMAIN);
    }

    public void setMsaeDomain(final String msaeDomain) {
        data.put(MSAE_DOMAIN, msaeDomain);
    }

    // MSAE Settings
    public boolean isUseSSL() {
        return Boolean.TRUE.equals(data.get(IS_USE_SSL));
    }

    public void setIsUseSsl(final boolean isUseSsl) {
        data.put(IS_USE_SSL, Boolean.valueOf(isUseSsl));
    }

    public int getADConnectionPort() {
        return (Integer) data.get(AD_CONNECTION_PORT);
    }

    public void setAdConnectionPort(final int port) {
        data.put(AD_CONNECTION_PORT, port);
    }

    public String getAdLoginDN() {
        return (String) data.get(AD_LOGIN_DN);
    }

    public void setAdLoginDN(final String adLoginDN) {
        data.put(AD_LOGIN_DN, adLoginDN);
    }

    public String getAdLoginPassword() {
        return (String) data.get(AD_LOGIN_PASSWORD);
    }

    public void setAdLoginPassword(final String adLoginPassword) {
        data.put(AD_LOGIN_PASSWORD, adLoginPassword);
    }

    // MS Enrollment Servlet Settings
    public String getKeyStorePath() {
        return (String) data.get(KEY_STORE_PATH);
    }
    public void setKeyStorePath(final String keyStorePath) {
        data.put(KEY_STORE_PATH, keyStorePath);
    }

    public String getKeyStorePassword() {
        return (String) data.get(KEY_STORE_PASSWORD);
    }
    public void setKeyStorePassword(final String keyStorePassword) {
        data.put(KEY_STORE_PASSWORD, keyStorePassword);
    }

    public String getTrustedKeyStorePath() {
        return (String) data.get(TRUSTED_KEY_STORE_PATH);
    }
    public void setTrustedKeyStorePath(final String trustedKeyStorePath) {
        data.put(TRUSTED_KEY_STORE_PATH, trustedKeyStorePath);
    }

    public String getTrustedKeyStorePassword() {
        return (String) data.get(TRUSTED_KEY_STORE_PASSWORD);
    }
    public void setTrustedKeyStorePassword(final String trustedKeyStorePassword) {
        data.put(TRUSTED_KEY_STORE_PASSWORD, trustedKeyStorePassword);
    }

    public String getCaName() {
        return (String) data.get(CA_NAME);
    }
    public void setCaName(final String caName) {
        data.put(CA_NAME, caName);
    }
}
