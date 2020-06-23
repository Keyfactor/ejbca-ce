package org.ejbca.ui.web.jsf.configuration;

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

import javax.servlet.http.HttpServletRequest;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.EstConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.configuration.WebLanguage;
import org.ejbca.ui.web.configuration.exception.AdminDoesntExistException;
import org.ejbca.ui.web.configuration.exception.AdminExistsException;
import org.ejbca.ui.web.configuration.exception.CacheClearException;

public interface EjbcaWebBean extends Serializable {

    X509Certificate getClientX509Certificate(final HttpServletRequest httpServletRequest);

    /* Sets the current user and returns the global configuration */
    GlobalConfiguration initialize(final HttpServletRequest httpServletRequest, final String... resources) throws Exception;

    GlobalConfiguration initialize_errorpage(final HttpServletRequest request) throws Exception;

    /** Returns the current users common name */
    String getUsersCommonName();

    /** Returns the users certificate serialnumber, user to id the adminpreference. */
    String getCertificateFingerprint();

    /** Return the admins selected theme including its trailing '.css' */
    String getCssFile();

    /** Return the IE fixes CSS of the admins selected theme including it's trailing '.css' */
    String getIeFixesCssFile();

    /** Returns the admins prefered language */
    int getPreferedLanguage();

    /** Returns the admins secondary language. */
    int getSecondaryLanguage();

    int getEntriesPerPage();

    int getLogEntriesPerPage();

    void setLogEntriesPerPage(final int logentriesperpage) throws AdminDoesntExistException, AdminExistsException;

    int getLastFilterMode();

    void setLastFilterMode(final int lastfiltermode) throws AdminDoesntExistException, AdminExistsException;

    int getLastEndEntityProfile();

    void setLastEndEntityProfile(final int lastprofile) throws AdminDoesntExistException, AdminExistsException;

    boolean existsAdminPreference();

    void addAdminPreference(final AdminPreference adminPreference) throws AdminExistsException;

    void changeAdminPreference(final AdminPreference adminPreference) throws AdminDoesntExistException;

    /** @return the current admin's preference */
    AdminPreference getAdminPreference();

    AdminPreference getDefaultAdminPreference();

    void saveDefaultAdminPreference(final AdminPreference adminPreference) throws AuthorizationDeniedException;

    // TODO ECA-7823 Refactor EjbcaWebBean's deprecated methods
    /**
     * Checks if the admin have authorization to view the resource without performing any logging. Used by menu page Does not return false if not
     * authorized, instead throws an AuthorizationDeniedException.
     *
     * @deprecated Don't use as is in a new admin GUI. Use {@link #isAuthorizedNoLogSilent(String...)} instead.
     *
     * @return true if is authorized to resource, throws AuthorizationDeniedException if not authorized, never returns false.
     * @throws AuthorizationDeniedException is not authorized to resource
     */
    @Deprecated
    boolean isAuthorizedNoLog(final String... resources) throws AuthorizationDeniedException;

    /**
     * Checks if the admin have authorization to view the resource without performing any logging. Will simply return a boolean,
     * does not throw exception.
     *
     * @return true if is authorized to resource, false if not
     */
    boolean isAuthorizedNoLogSilent(final String... resources);

    String getBaseUrl();

    String getReportsPath();

    /* Returns the global configuration */
    GlobalConfiguration getGlobalConfiguration();

    /**
     * @return Public application base URL (e.g. 'http://localhost:8080/ejbca')
     */
    String getBaseUrlPublic();

    String getCurrentRemoteIp();

    /**
     * A functions that returns wanted imagefile in preferred language and theme. If none of the language specific images are found the original
     * imagefilename will be returned.
     *
     * The priority of filenames are in the following order 1. imagename.theme.preferedlanguage.png/jpg/gif 2. imagename.theme.secondarylanguage.png/jpg/gif
     * 3. imagename.theme.png/jpg/gif 4. imagename.preferedlanguage.png/jpg/gif 5. imagename.secondarylanguage.png/jpg/gif 6. imagename.png/jpg/gif
     *
     * The parameter imagefilename should the wanted filename without language infix. For example: given imagefilename 'caimg.png' would return
     * 'caimg.en.png' if English was the users preferred language. It's important that all letters in imagefilename is lowercase.
     */
    String getImagefileInfix(final String imagefilename);

    String[] getAvailableLanguages();

    String getText(final String template);

    List<WebLanguage> getWebLanguagesList();

    WebLanguages getWebLanguages();

    /**
     * @param template the entry in the language file to get
     * @param unescape true if html entities should be unescaped (&auml; converted to the real char)
     * @param params values of {0}, {1}, {2}... parameters
     * @return text string, possibly unescaped, or "template" if the template does not match any entry in the language files
     */
    String getText(final String template, final boolean unescape, final Object... params);

    /** @return a more user friendly representation of a Date. */
    String formatAsISO8601(final Date date);

    /** Parse a Date and reformat it as vailidation. */
    // TODO seems to be unused. Remove this and implementation?
    String validateDateFormat(final String value) throws ParseException;

    /** Check if the argument is a relative date/time in the form days:min:seconds. */
    boolean isRelativeDateTime(final String dateString);

    /** To be used when giving format example. */
    String getDateExample();

    /** Convert a the format "yyyy-MM-dd HH:mm:ssZZ" to "yyyy-MM-dd HH:mm" with implied TimeZone UTC used when storing. */
    String getImpliedUTCFromISO8601(final String dateString) throws ParseException;

    /**
     * Convert a the format "yyyy-MM-dd HH:mm:ssZZ" to "yyyy-MM-dd HH:mm" with implied TimeZone UTC used when storing. If it is a relative date we
     * return it as it was. Otherwise we try to parse it as a ISO8601 date time.
     */
    String getImpliedUTCFromISO8601OrRelative(final String dateString) throws ParseException;

    /** Convert a the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC to a more user friendly "yyyy-MM-dd HH:mm:ssZZ". */
    String getISO8601FromImpliedUTC(final String dateString) throws ParseException;

    /**
     * Convert a the format "yyyy-MM-dd HH:mm" with implied TimeZone UTC to a more user friendly "yyyy-MM-dd HH:mm:ssZZ". If it is a relative date we
     * return it as it was. If we fail to parse the stored date we return an error-string followed by the stored value.
     * If the passed in value is empty, we return an empty string
     */
    String getISO8601FromImpliedUTCOrRelative(final String dateString);

    void reloadGlobalConfiguration();

    void saveGlobalConfiguration(final GlobalConfiguration gc) throws AuthorizationDeniedException;

    void saveGlobalConfiguration() throws Exception;

    /**
     * Save the given CMP configuration.
     *
     * @param cmpconfiguration A CMPConfiguration
     * @throws AuthorizationDeniedException if the current admin doesn't have access to global configurations
     */
    void saveCmpConfiguration(final CmpConfiguration cmpconfiguration) throws AuthorizationDeniedException;

    /**
     * Save the given EST configuration.
     *
     * @param estconfiguration A EstConfiguration
     * @throws AuthorizationDeniedException if the current admin doesn't have access to global configurations
     */
    void saveEstConfiguration(final EstConfiguration estconfiguration) throws AuthorizationDeniedException;

    /**
     * Reload the current configuration from the database.
     */
    void reloadCmpConfiguration();

    void reloadEstConfiguration();
    
    // TODO ECA-7823 Refactor EjbcaWebBean's deprecated methods
    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getCAIdToNameMap instead. */
    @Deprecated
    Map<Integer,String> getCAIdToNameMap();

    // TODO ECA-7823 Refactor EjbcaWebBean's deprecated methods
    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getAuthorizedCaIds instead. */
    @Deprecated
    List<Integer> getAuthorizedCAIds();

    // TODO ECA-7823 Refactor EjbcaWebBean's deprecated methods
    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getAuthorizedCaNamesToIds instead. */
    @Deprecated
    TreeMap<String,Integer> getCANames();

    TreeMap<String,Integer> getExternalCANames();

    TreeMap<String,Integer> getActiveCANames();

    /**
     * Returns authorized end entity  profile names as a treemap of name (String) -> id (Integer)
     */
    TreeMap<String, Integer> getAuthorizedEndEntityCertificateProfileNames();

    /**
     * Returns authorized sub CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    TreeMap<String, Integer> getAuthorizedSubCACertificateProfileNames();

    /**
     * Returns authorized root CA certificate profile names as a treemap of name (String) -> id (Integer)
     */
    TreeMap<String, Integer> getAuthorizedRootCACertificateProfileNames();

    /**
     * 
     * @return authorized SSH certificate profile names as a treemap of name (String) -> id (Integer)
     */
    TreeMap<String, Integer>  getAuthorizedSshCertificateProfileNames();
    
    /**
     * Method returning the all available approval profiles id to name.
     *
     * @return the approvalprofiles-id-to-name-map (HashMap)
     */
    Map<Integer, String> getApprovalProfileIdToNameMap();

    List<Integer> getSortedApprovalProfileIds();

    /**
     * @return all authorized publishers names as a list
     */
    List<String> getAuthorizedPublisherNames();

    /**
     * @return all authorized publishers names as a treemap of name (String) -> id (Integer).
     */
    TreeMap<String,Integer> getAuthorizedPublisherNamesAndIds();

    /**
     * Method returning the all available publishers id to name.
     *
     * @return the publisheridtonamemap (HashMap) sorted by value
     */
    Map<Integer, String> getPublisherIdToNameMapByValue();

    /**
     * Returns authorized end entity profile names as a treemap of name (String) -> id (String)
     */
    TreeMap<String, String> getAuthorizedEndEntityProfileNames(final String endentityAccessRule);

    AuthenticationToken getAdminObject();

    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     *
     * @return true if key strength is limited
     */
    boolean isUsingExportableCryptography();

    boolean isPostUpgradeRequired();

    /**
     * @return The host's name or "unknown" if it could not be determined.
     */
    String getHostName();

    /** @return The current time on the server */
    String getServerTime();

    /**
     * Uses the language in the Administration GUI to determine which locale is preferred.
     *
     * @return the locale of the Admin GUI
     */
    Locale getLocale();

    boolean isSessionTimeoutEnabled();

    int getSessionTimeoutTime();

    boolean isHelpEnabled();

    String getHelpBaseURI();

    String getHelpReference(final String lastPart);

    String getExternalHelpReference(final String linkPart);

    String[] getCertSernoAndIssuerdn(final String certdata);

    String getCleanOption(final String parameter, final String[] validOptions);

    void clearClusterCache(final boolean excludeActiveCryptoTokens) throws CacheClearException;

    EjbLocalHelper getEjb();

    Object getEnterpriseEjb();

    //**********************
    //     CMP
    //**********************

    CmpConfiguration getCmpConfiguration();

    /**
     * Returns a clone of the current CMPConfiguration containing only the given alias. Also caches the clone locally.
     *
     * @param alias a CMP config alias
     * @return a clone of the current CMPConfiguration containing only the given alias. Will return an alias with only default values if the CmpConfiguration doesn't
     *          contain that alias.
     */
    CmpConfiguration getCmpConfigForEdit(final String alias);

    /**
     * Merges together an alias from the editing clone into the proper configuration cache and saves it to the database.
     *
     * @param alias a CMP config alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void updateCmpConfigFromClone(final String alias) throws AuthorizationDeniedException;

    /**
     * Adds an alias to the database.
     *
     * @param alias the name of a CMP alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void addCmpAlias(final String alias) throws AuthorizationDeniedException;

    /**
     * Makes a copy of a given alias
     *
     * @param oldName the name of the alias to copy
     * @param newName the name of the new alias
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void cloneCmpAlias(final String oldName, final String newName) throws AuthorizationDeniedException;

    /**
     * Deletes a CMP alias from the database.
     *
     * @param alias the name of the alias to delete.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void removeCmpAlias(final String alias) throws AuthorizationDeniedException;

    /**
     * Renames a CMP alias
     *
     * @param oldName the old alias name
     * @param newName the new alias name
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void renameCmpAlias(final String oldName, final String newName) throws AuthorizationDeniedException;

    void clearCmpConfigClone();

    void clearCmpCache();

    /**
     * Retrieve a mapping between authorized end entity profile names and their ids which can be displayed in the GUI.
     * The returned map will contain an additional "KeyID" entry which allows the end user to specify the end entity
     * in the CMP request.
     * @param endEntityAccessRule the access rule used for authorization
     * @return a map {end entity profile name} => {end entity profile id} with authorized end entituy profiles
     */
    Map<String, String> getAuthorizedEEProfileNamesAndIds(final String endEntityAccessRule);

    Map<String, String> getAuthorizedEEProfilesAndIdsNoKeyId(final String endEntityAccessRule);

    /**
     * Retrieve a collection of available certificate authority ids based on end entity profile id. The returned list may
     * contain an additional "KeyID" option which allows the end user to specify the CA in the CMP request.
     * @param endEntityProfileId the id of an end entity profile
     * @return a sorted list of certificate authorities for the specified end entity profile
     * @throws NumberFormatException if the end entity profile id is not a number
     * @throws CADoesntExistsException if the certificate authority pointed to by an end entity profile does not exist
     * @throws AuthorizationDeniedException if we were denied access control
     */
    Collection<String> getAvailableCAsOfEEProfile(final String endEntityProfileId) throws NumberFormatException, CADoesntExistsException, AuthorizationDeniedException;

    /**
     * Retrieve a list of certificate profile ids based on an end entity profile id. The returned list may contain
     * an additional "KeyID" option which allows the end user to specify the certificate profile in the CMP request.
     * @param endEntityProfileId the end entity profile id for which we want to fetch certificate profiles
     * @return a sorted list of certificate profile names
     */
    Collection<String> getAvailableCertProfilesOfEEProfile(final String endEntityProfileId);

    /**
     * Retrieve a mapping between certificate profiles names and IDs available in the end entity profile. To be displayed in the GUI.
     * @param endEntityProfileId the the end entity profile in which we want to find certificate profiles
     * @return a map (TreeMap so it's sorted by key) {certificate profile name, certificate profile id} with authorized certificate profiles
     */
    Map<String, Integer> getCertificateProfilesNoKeyId(final String endEntityProfileId);

    Collection<String> getCertificateProfileIDsNoKeyId(final String endEntityProfileId);

    // TODO ECA-7823 Refactor EjbcaWebBean's deprecated methods
    /** @deprecated Since EJBCA 7.0.0. Use CaSession.getAuthorizedCaNamesToIds instead. */
    @Deprecated
    TreeMap<String, Integer> getCAOptions();

    /**
     * Gets the list of CA names by the list of CA IDs.
     * @param idString the semicolon separated list of CA IDs.
     * @return the list of CA names as semicolon separated String.
     * @throws NumberFormatException if a CA ID could not be parsed.
     * @throws AuthorizationDeniedException if authorization was denied.
     */
    String getCaNamesString(final String idString) throws NumberFormatException, AuthorizationDeniedException;

    /** @return true if we are running in the enterprise mode otherwise false. */
    boolean isRunningEnterprise();

    /** @return true if we are running EJBCA build that has CA functionality enabled. */
    boolean isRunningBuildWithCA();
    
    /** @return true if we are running EJBCA build that has RA functionality enabled. 
     * RA functionality can be disabled by composing a VA-only ziprelease (with variant=va)
     * */
    boolean isRunningBuildWithRA();

    /** @return true if we are running EJBCA build that has RA Web functionality enabled.
     * RA functionality can be disabled by composing a VA-only ziprelease (with variant=va)
     * */
    boolean isRunningBuildWithRAWeb();
    
    EstConfiguration getEstConfiguration();

    /**
     * Returns a clone of the current EstConfiguration containing only the given alias. Also caches the clone locally.
     *
     * @param alias a EST config alias
     * @return a clone of the current EstConfiguration containing only the given alias. Will return an alias with only default values if the EstConfiguration doesn't
     *          contain that alias.
     */
    EstConfiguration getEstConfigForEdit(final String alias);

    /**
     * Merges together an alias from the editing clone into the proper configuration cache and saves it to the database.
     *
     * @param alias a EST config alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void updateEstConfigFromClone(final String alias) throws AuthorizationDeniedException;

    /**
     * Adds an alias to the database.
     *
     * @param alias the name of a EST alias.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void addEstAlias(final String alias) throws AuthorizationDeniedException;

    /**
     * Makes a copy of a given alias
     *
     * @param oldName the name of the alias to copy
     * @param newName the name of the new alias
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void cloneEstAlias(final String oldName, final String newName) throws AuthorizationDeniedException;

    /**
     * Deletes a EST alias from the database.
     *
     * @param alias the name of the alias to delete.
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void removeEstAlias(final String alias) throws AuthorizationDeniedException;

    /**
     * Renames a EST alias
     *
     * @param oldName the old alias name
     * @param newName the new alias name
     * @throws AuthorizationDeniedException if the current admin isn't authorized to edit configurations
     */
    void renameEstAlias(final String oldName, final String newName) throws AuthorizationDeniedException;

    void clearEstConfigClone();

    void clearEstCache();

    //*************************************************
    //      AvailableExtendedKeyUsagesConfigration
    //*************************************************

    AvailableExtendedKeyUsagesConfiguration getAvailableExtendedKeyUsagesConfiguration();

    void reloadAvailableExtendedKeyUsagesConfiguration();

    void saveAvailableExtendedKeyUsagesConfiguration(final AvailableExtendedKeyUsagesConfiguration ekuConfig) throws AuthorizationDeniedException;

    //*****************************************************************
    //       AvailableCustomCertificateExtensionsConfiguration
    //*****************************************************************

    AvailableCustomCertificateExtensionsConfiguration getAvailableCustomCertExtensionsConfiguration();

    void reloadAvailableCustomCertExtensionsConfiguration();

    void saveAvailableCustomCertExtensionsConfiguration(final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws AuthorizationDeniedException;

    //*******************************
    //         Peer Connector
    //*******************************

    /** @return true if the PeerConnectors GUI implementation is present. */
    boolean isPeerConnectorPresent();

}
