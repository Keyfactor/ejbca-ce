package se.anatom.ejbca.ra;

import se.anatom.ejbca.util.UpgradeableDataHashMap;


/**
 * This is a  class containing global configuration parameters.
 *
 * @version $Id: GlobalConfiguration.java,v 1.16 2003-07-23 09:40:16 anatom Exp $
 */
public class GlobalConfiguration extends UpgradeableDataHashMap implements java.io.Serializable {
    // Default Values
    public static final float LATEST_VERSION = 1;

    // Entries to choose from in userpreference part, defines the size of data to be displayed on one page.
    private final String[] DEFAULTPOSSIBLEENTRIESPERPAGE = { "10", "25", "50", "100" };

    // Entries to choose from in view log part, defines the size of data to be displayed on one page.
    private final String[] DEFAULTPOSSIBLELOGENTRIESPERPAGE = { "10", "25", "50", "100", "200", "400" };

    // Rules available by default i authorization module.
    private final String[] DEFAULT_AVAILABLE_RULES = {
        "/", "/ca_functionallity", "/ca_functionallity/basic_functions",
        "/ca_functionallity/view_certificate", "/ca_functionallity/create_crl",
        "/ca_functionallity/edit_certificate_profiles",
        "/ra_functionallity/edit_end_entity_profiles", "/ra_functionallity",
        "/ra_functionallity/edit_end_entity_profiles", "/ra_functionallity/view_end_entity",
        "/ra_functionallity/create_end_entity", "/ra_functionallity/edit_end_entity",
        "/ra_functionallity/delete_end_entity", "/ra_functionallity/revoke_end_entity",
        "/ra_functionallity/view_end_entity_history", "/log_functionallity",
        "/log_functionallity/view_log", "/log_functionallity/view_log/log_entries",
        "/log_functionallity/view_log/ca_entries", "/log_functionallity/view_log/ra_entries",
        "/log_functionallity/edit_log_configuration",
        "/log_functionallity/view_log/adminweb_entries",
        "/log_functionallity/view_log/publicweb_entries", "/system_functionallity",
        "/system_functionallity/edit_system_configuration",
        "/system_functionallity/edit_administrator_privileges",
        "/system_functionallity/edit_administrator_privileges/edit_available_accessrules"
    };
    public static final String[] LOGMODULERESOURCES = {
        "/log_functionallity/view_log/ca_entries", "/log_functionallity/view_log/ra_entries",
        "/log_functionallity/view_log/log_entries", "/log_functionallity/view_log/publicweb_entries",
        "/log_functionallity/view_log/adminweb_entries",
        "/log_functionallity/view_log/hardtoken_entries",
        "/log_functionallity/view_log/keyrecovery_entries"
    };

    // Available end entity profile authorization rules.
    public static final String VIEW_RIGHTS = "/view_end_entity";
    public static final String EDIT_RIGHTS = "/edit_end_entity";
    public static final String CREATE_RIGHTS = "/create_end_entity";
    public static final String DELETE_RIGHTS = "/delete_end_entity";
    public static final String REVOKE_RIGHTS = "/revoke_end_entity";
    public static final String HISTORY_RIGHTS = "/view_end_entity_history";

    // Endings to add to profile authorizxation.
    public static final String[] ENDENTITYPROFILE_ENDINGS = {
        VIEW_RIGHTS, EDIT_RIGHTS, CREATE_RIGHTS, DELETE_RIGHTS, REVOKE_RIGHTS, HISTORY_RIGHTS
    };

    // Name of end entity profile prefix directory in authorization module.
    public static final String ENDENTITYPROFILEPREFIX = "/endentityprofilesrules/";

    // Hard Token specific resources used in authorization module.
    public static final String[] HARDTOKENRESOURCES = {
        "/hardtoken_functionallity/edit_hardtoken_issuers",
        "/hardtoken_functionallity/issue_hardtokens",
        "/hardtoken_functionallity/issue_hardtoken_administrator"
    };
    public static final String HARDTOKEN_RA_ENDING = "/view_hardtoken";

    // Hard Token specific resource used in authorization module.
    public static final String KEYRECOVERYRESOURCE = "/keyrecovery";

    // Path added to baseurl used as default vaule in CRLDistributionPointURI field in Certificate Type definitions.
    private static final String DEFAULTCRLDISTURIPATH = "ejbca/webdist/certdist?cmd=crl";

    // Default name of headbanner in web interface.
    private static final String DEFAULTHEADBANNER = "head_banner.jsp";

    // Default name of footbanner page in web interface.
    private static final String DEFAULTFOOTBANNER = "foot_banner.jsp";

    // Title of ra admin web interface.
    private static final String DEFAULTEJBCATITLE = "Enterprise Java Bean Certificate Authority";

    // Language codes. Observe the order is important
    public static final int EN = 0;
    public static final int SE = 1;

    // Public constants.
    public static final String HEADERFRAME = "topFrame"; // Name of header browser frame
    public static final String MENUFRAME = "leftFrame"; // Name of menu browser frame
    public static final String MAINFRAME = "mainFrame"; // Name of main browser frame

    /**
     * Creates a new instance of Globaldatauration
     */
    public GlobalConfiguration() {
        super();

        setEjbcaTitle(DEFAULTEJBCATITLE);
        setEnableEndEntityProfileLimitations(false);
        setEnableAuthenticatedUsersOnly(false);
        setEnableKeyRecovery(false);
        setIssueHardwareTokens(false);
    }

    /**
     * Initializes a new global datauration with data used in ra web interface.
     *
     * @param baseurl DOCUMENT ME!
     * @param adminpath DOCUMENT ME!
     * @param availablelanguages DOCUMENT ME!
     * @param availablethemes DOCUMENT ME!
     * @param publicport DOCUMENT ME!
     * @param privateport DOCUMENT ME!
     * @param publicprotocol DOCUMENT ME!
     * @param privateprotocol DOCUMENT ME!
     */
    public void initialize(String baseurl, String adminpath, String availablelanguages,
        String availablethemes, String publicport, String privateport, String publicprotocol,
        String privateprotocol) {
        String tempbaseurl = baseurl;
        String tempadminpath = adminpath.trim();

        if (!tempbaseurl.endsWith("/")) {
            tempbaseurl = tempbaseurl + "/";
        }

        if (tempadminpath == null) {
            tempadminpath = "";
        }

        if (!tempadminpath.endsWith("/") && !tempadminpath.equals("")) {
            tempadminpath = tempadminpath + "/"; // Add ending '/'
        }

        if (tempadminpath.startsWith("/")) {
            tempadminpath = tempadminpath.substring(1); // Remove starting '/'
        }

        String[] tempdefaultdirs = new String[DEFAULT_AVAILABLE_RULES.length + 2];
        tempdefaultdirs[0] = "/";
        tempdefaultdirs[1] = "/" + tempadminpath;

        for (int i = 2; i < tempdefaultdirs.length; i++) {
            tempdefaultdirs[i] = "/" + tempadminpath + DEFAULT_AVAILABLE_RULES[i - 2];
        }

        setBaseUrl(tempbaseurl);
        data.put(ADMINPATH, tempadminpath);
        data.put(AVAILABLELANGUAGES, availablelanguages.trim());
        data.put(AVAILABLETHEMES, availablethemes.trim());
        data.put(PUBLICPORT, publicport.trim());
        data.put(PRIVATEPORT, privateport.trim());
        data.put(PUBLICPROTOCOL, publicprotocol.trim());
        data.put(PRIVATEPROTOCOL, privateprotocol.trim());

        data.put(AUTHORIZATION_PATH, tempadminpath + "administratorprivileges");
        data.put(BANNERS_PATH, "banners");
        data.put(CA_PATH, tempadminpath + "ca");
        data.put(CONFIG_PATH, tempadminpath + "sysconfig");
        data.put(HELP_PATH, "help");
        data.put(IMAGES_PATH, "images");
        data.put(LANGUAGE_PATH, "languages");
        data.put(LOG_PATH, tempadminpath + "log");
        data.put(RA_PATH, tempadminpath + "ra");
        data.put(THEME_PATH, "themes");
        data.put(HARDTOKEN_PATH, tempadminpath + "hardtoken");

        data.put(LANGUAGEFILENAME, "languagefile");
        data.put(MAINFILENAME, "main.jsp");
        data.put(INDEXFILENAME, "index.jsp");
        data.put(MENUFILENAME, "adminmenu.jsp");
        data.put(ERRORPAGE, "errorpage.jsp");

        setHeadBanner(DEFAULTHEADBANNER);
        setFootBanner(DEFAULTFOOTBANNER);
    }

    /**
     * Checks if global datauration have been initialized.
     *
     * @return DOCUMENT ME!
     */
    public boolean isInitialized() {
        return data.get(BASEURL) != null;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getBaseUrl() {
        return (String) data.get(BASEURL);
    }

    /**
     * DOCUMENT ME!
     *
     * @param burl DOCUMENT ME!
     */
    public void setBaseUrl(String burl) {
        // Add trailing '/' if it doesn't exists.
        if (!burl.endsWith("/")) {
            data.put(BASEURL, burl + "/");
        } else {
            data.put(BASEURL, burl);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAdminWebPath() {
        return (String) data.get(ADMINPATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getStandardCRLDistributionPointURI() {
        String retval = (String) data.get(BASEURL);
        retval = retval.replaceFirst((String) data.get(PRIVATEPROTOCOL),
                (String) data.get(PUBLICPROTOCOL));
        retval = retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
        retval += DEFAULTCRLDISTURIPATH;

        return retval;
    }

    /**
     * Returns the default available resources in the authorization module.
     *
     * @return DOCUMENT ME!
     */
    public String[] getDefaultAvailableResources() {
        return DEFAULT_AVAILABLE_RULES;
    }

    /**
     * Checks the themes paht for css files and returns an array of filenames without the ".css"
     * ending.
     *
     * @return DOCUMENT ME!
     */
    public String[] getAvailableThemes() {
        String[] availablethemes;
        availablethemes = getAvailableThenesAsString().split(",");

        if (availablethemes != null) {
            for (int i = 0; i < availablethemes.length; i++) {
                availablethemes[i] = availablethemes[i].trim();

                if (availablethemes[i].endsWith(".css")) {
                    availablethemes[i] = availablethemes[i].substring(0,
                            availablethemes[i].length() - 4);
                }
            }
        }

        return availablethemes;
    }

    /**
     * Returns the default avaiable theme used by administrator preferences.
     *
     * @return DOCUMENT ME!
     */
    public String getDefaultAvailableTheme() {
        return getAvailableThemes()[0];
    }

    // Methods for manipulating the headbanner filename.
    public String getHeadBanner() {
        return (String) data.get(HEADBANNER);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getHeadBannerFilename() {
        String returnval = (String) data.get(HEADBANNER);

        return returnval.substring(returnval.lastIndexOf('/') + 1);
    }

    /**
     * DOCUMENT ME!
     *
     * @param head DOCUMENT ME!
     */
    public void setHeadBanner(String head) {
        data.put(HEADBANNER,
            ((String) data.get(ADMINPATH)) + ((String) data.get(BANNERS_PATH)) + "/" + head);
    }

    // Methods for manipulating the headbanner filename.
    public String getFootBanner() {
        return (String) data.get(FOOTBANNER);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getFootBannerFilename() {
        String returnval = (String) data.get(FOOTBANNER);

        return returnval.substring(returnval.lastIndexOf('/') + 1);
    }

    /**
     * DOCUMENT ME!
     *
     * @param foot DOCUMENT ME!
     */
    public void setFootBanner(String foot) {
        data.put(FOOTBANNER, "/" + ((String) data.get(BANNERS_PATH)) + "/" + foot);
    }

    // Methods for manipulating the title.
    public String getEjbcaTitle() {
        return (String) data.get(TITLE);
    }

    /**
     * DOCUMENT ME!
     *
     * @param ejbcatitle DOCUMENT ME!
     */
    public void setEjbcaTitle(String ejbcatitle) {
        data.put(TITLE, ejbcatitle);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAuthorizationPath() {
        return (String) data.get(AUTHORIZATION_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getBannersPath() {
        return (String) data.get(BANNERS_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getCaPath() {
        return (String) data.get(CA_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getConfigPath() {
        return (String) data.get(CONFIG_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getHelpPath() {
        return (String) data.get(HELP_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getImagesPath() {
        return (String) data.get(IMAGES_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getLanguagePath() {
        return (String) data.get(LANGUAGE_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getLogPath() {
        return (String) data.get(LOG_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getRaPath() {
        return (String) data.get(RA_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getThemePath() {
        return (String) data.get(THEME_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getHardTokenPath() {
        return (String) data.get(HARDTOKEN_PATH);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getLanguageFilename() {
        return (String) data.get(LANGUAGEFILENAME);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getMainFilename() {
        return (String) data.get(MAINFILENAME);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getIndexFilename() {
        return (String) data.get(INDEXFILENAME);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getMenuFilename() {
        return (String) data.get(MENUFILENAME);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getErrorPage() {
        return (String) data.get(ERRORPAGE);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String[] getPossibleEntiresPerPage() {
        return DEFAULTPOSSIBLEENTRIESPERPAGE;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String[] getPossibleLogEntiresPerPage() {
        return DEFAULTPOSSIBLELOGENTRIESPERPAGE;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAvailableLanguagesAsString() {
        return (String) data.get(AVAILABLELANGUAGES);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getAvailableThenesAsString() {
        return (String) data.get(AVAILABLETHEMES);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getEnableEndEntityProfileLimitations() {
        return ((Boolean) data.get(ENABLEEEPROFILELIMITATIONS)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param value DOCUMENT ME!
     */
    public void setEnableEndEntityProfileLimitations(boolean value) {
        data.put(ENABLEEEPROFILELIMITATIONS, Boolean.valueOf(value));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getEnableAuthenticatedUsersOnly() {
        return ((Boolean) data.get(ENABLEAUTHENTICATEDUSERSONLY)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param value DOCUMENT ME!
     */
    public void setEnableAuthenticatedUsersOnly(boolean value) {
        data.put(ENABLEAUTHENTICATEDUSERSONLY, Boolean.valueOf(value));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getEnableKeyRecovery() {
        return ((Boolean) data.get(ENABLEKEYRECOVERY)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param value DOCUMENT ME!
     */
    public void setEnableKeyRecovery(boolean value) {
        data.put(ENABLEKEYRECOVERY, Boolean.valueOf(value));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getIssueHardwareTokens() {
        return ((Boolean) data.get(ISSUEHARDWARETOKENS)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param value DOCUMENT ME!
     */
    public void setIssueHardwareTokens(boolean value) {
        data.put(ISSUEHARDWARETOKENS, Boolean.valueOf(value));
    }

    /**
     * Implemtation of UpgradableDataHashMap function getLatestVersion
     *
     * @return DOCUMENT ME!
     */
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Implemtation of UpgradableDataHashMap function upgrade.
     */
    public void upgrade() {
        if (LATEST_VERSION != getVersion()) {
            // New version of the class, upgrade
            if (data.get(HARDTOKEN_PATH) == null) {
                data.put(HARDTOKEN_PATH, ((String) data.get(ADMINPATH) + "hardtoken"));
            }

            data.put(VERSION, new Float(LATEST_VERSION));
        }
    }

    // Private fields.
    // Private constants
    private static final String BASEURL = "baseurl";
    private static final String ADMINPATH = "raadminpath";
    private static final String AVAILABLELANGUAGES = "availablelanguages";
    private static final String AVAILABLETHEMES = "availablethemes";
    private static final String PUBLICPORT = "publicport";
    private static final String PRIVATEPORT = "privateport";
    private static final String PUBLICPROTOCOL = "publicprotocol";
    private static final String PRIVATEPROTOCOL = "privateprotocol";

    // Title
    private static final String TITLE = "title";

    // Banner files.
    private static final String HEADBANNER = "headbanner";
    private static final String FOOTBANNER = "footbanner";

    // Other configuration.
    private static final String ENABLEEEPROFILELIMITATIONS = "endentityprofilelimitations";
    private static final String ENABLEAUTHENTICATEDUSERSONLY = "authenticatedusersonly";
    private static final String ENABLEKEYRECOVERY = "enablekeyrecovery";
    private static final String ISSUEHARDWARETOKENS = "issuehardwaretokens";

    // Paths
    private static final String AUTHORIZATION_PATH = "authorization_path";
    private static final String BANNERS_PATH = "banners_path";
    private static final String CA_PATH = "ca_path";
    private static final String CONFIG_PATH = "data_path";
    private static final String HELP_PATH = "help_path";
    private static final String IMAGES_PATH = "images_path";
    private static final String LANGUAGE_PATH = "language_path";
    private static final String LOG_PATH = "log_path";
    private static final String RA_PATH = "ra_path";
    private static final String THEME_PATH = "theme_path";
    private static final String HARDTOKEN_PATH = "hardtoken_path";
    private static final String LANGUAGEFILENAME = "languagefilename";
    private static final String MAINFILENAME = "mainfilename";
    private static final String INDEXFILENAME = "indexfilename";
    private static final String MENUFILENAME = "menufilename";
    private static final String ERRORPAGE = "errorpage";
}
