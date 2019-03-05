/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.model.validation;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.validation.DnsNameValidator;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.profiles.Profile;
import org.cesecore.util.CertTools;
import org.cesecore.util.MapTools;
import org.cesecore.util.NameTranslatable;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.core.model.validation.domainblacklist.DomainBlacklistChecker;
import org.ejbca.core.model.validation.domainblacklist.DomainBlacklistExactMatchChecker;
import org.ejbca.core.model.validation.domainblacklist.DomainBlacklistNormalizer;

/**
 * A Domain Blacklist Validator checks DNSName fields against a set of blacklists.
 * It works by first normalizing domain names (so that for example.com and examp1e.c0m compare equal),
 * and second by performing checks against a blacklist. The most basic blacklist is simply a
 * set of domains, with exact matching, but more powerful checks can be created (such as similarity matching).
 * <p>
 * Both domain components and full domains can be matched. A backlisted string with dots will be matched
 * against full domains and subdomains, while a string without dots will be matched against domain components also.
 * 
 * @version $Id$
 */
public class DomainBlacklistValidator extends ValidatorBase implements DnsNameValidator {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(DomainBlacklistValidator.class);

    private static final Pattern allowedDomainCharacters = Pattern.compile("^[a-zA-Z0-9._-]+$");

    /** The domain blacklist validator type. */
    private static final String TYPE_IDENTIFIER = "DOMAIN_BLACKLIST_VALIDATOR";

    /** Normalizations to perform (e.g. ASCII looklike). List of Java class names */
    private static final String NORMALIZATIONS_KEY = "normalizations";
    /** Checks to perform (e.g. exact match, domain component). List of Java class names */
    private static final String CHECKS_KEY = "checks";
    /** Current blacklist. Set of strings (blacklisted domains and/or domain components) */
    private static final String BLACKLISTS_KEY = "blacklists";
    /** Information about the existing blacklist: Filename, date, SHA-256 */
    private static final String BLACKLIST_INFO_KEY = "blacklist_info"; // Used in GUI only
    private static final String BLACKLIST_DATE_KEY = "blacklist_date";     // Persisted
    private static final String BLACKLIST_SHA256_KEY = "blacklist_sha256"; // Persisted
    /** File upload of new existing blacklist. Not persisted */
    private static final String BLACKLIST_UPLOAD_KEY = "blacklist_upload";

    private static final int MAX_LOG_DOMAINS = 100;

    /** Dynamic UI model extension. */
    protected DynamicUiModel uiModel;

    private transient Cache cache = null;
    private class Cache {
        final boolean initializationFailure;
        final List<DomainBlacklistNormalizer> normalizers;
        final List<DomainBlacklistChecker> checkers;
        public Cache(final boolean initializationFailure, final List<DomainBlacklistNormalizer> normalizers, final List<DomainBlacklistChecker> checkers) {
            this.initializationFailure = initializationFailure;
            this.normalizers = normalizers;
            this.checkers = checkers;
        }
    }

    @Override
    public List<Integer> getApplicablePhases() {
        return new ArrayList<>(Arrays.asList(IssuancePhase.DATA_VALIDATION.getIndex(), IssuancePhase.APPROVAL_VALIDATION.getIndex()));
    }

    @Override
    public void init() {
        super.init();
        // Add fields that have been upgraded and need default values here
    }

    private void loadBlacklistData() {
        if (cache == null) {
            synchronized (this) { // wait
                // Don't load if loaded while we waited for the synchronized block
                if (cache == null) {
                    reloadBlacklistData();
                }
            }
        }
    }

    /** Replaces the existing domain blacklist with the uploaded one. Takes a File object. */
    private void changeBlacklist(final File file) {
        try {
            final byte[] bytes = FileUtils.readFileToByteArray(file);
            changeBlacklist(bytes);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to parse domain black list.", e);
        }
    }

    /** Replaces the existing domain blacklist with the uploaded one. Takes a byte array. */
    public void changeBlacklist(final byte[] bytes) {
        final Set<String> domainSet = new TreeSet<>(); // store entries sorted in database
        try {
            try (final InputStream domainBlacklistInputStream = new ByteArrayInputStream(bytes);
                 final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(domainBlacklistInputStream, StandardCharsets.UTF_8))) {
                String line;
                int lineNumber = 0;
                while ((line = bufferedReader.readLine()) != null) {
                    lineNumber++;
                    final int comment = line.indexOf('#');
                    if (comment != -1) {
                        line = line.substring(0, comment);
                    }
                    line = line.trim();
                    if (line.isEmpty()) {
                        continue;
                    }
                    validateDomain(line, lineNumber);
                    domainSet.add(line.toLowerCase(Locale.ROOT));
                }
                if (log.isDebugEnabled()) {
                    log.debug("Parsed domain blacklist with " + domainSet.size() + " entries (" + lineNumber + " lines)");
                }
                setBlacklist(domainSet);
                setBlacklistDate(new Date());
                final String sha256 = new String(Hex.encode(CertTools.generateSHA256Fingerprint(bytes)), StandardCharsets.US_ASCII);
                setBlacklistSha256(sha256);
                // The Validator cache is reloaded after saving, so that will trigger a reload of the cache here in DomainBlacklistValidator 
            }
        } catch (IOException e) {
            throw new IllegalStateException("Unable to parse domain black list.", e);
        }
    }

    /**
     * Performs a basic validation of a domain, just to prevent mistakes.
     * Given that we may want to block fraud domains, we should not be too strict with standards compliance here.
     * Otherwise, we could have used StringTools.isValidSanDnsName
     */
    private void validateDomain(final String domain, final int lineNumber) {
        if (!allowedDomainCharacters.matcher(domain).matches()) {
            final String message = "Invalid syntax of domain at line " + lineNumber + (lineNumber < 5 ? ". The file must be a plain text file in ASCII format, or UTF-8 format (without Byte Order Mark). Please put one domain per line. IDN domains must be in Punycode format." : "");
            log.info(message);
            throw new IllegalArgumentException(message);
        }
    }

    private synchronized void reloadBlacklistData() {
        log.trace(">reloadBlacklistData");
        boolean newInitializationFailure = false;
        // Instantiate classes
        final List<DomainBlacklistNormalizer> newNormalizers = new ArrayList<>();
        for (final String normalizerName : getNormalizations())  {
            try {
                final Class<?> normalizerClass = Class.forName(normalizerName);
                final DomainBlacklistNormalizer normalizer = (DomainBlacklistNormalizer) normalizerClass.newInstance();
                normalizer.initialize(data);
                newNormalizers.add(normalizer);
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                log.error("Failed to load Domain Blacklist Normalizer '" + normalizerName + "'.");
                newInitializationFailure = true;
            }
        }
        final List<DomainBlacklistChecker> newCheckers = new ArrayList<>();
        for (final String checkerName : getChecks())  {
            try {
                final Class<?> checkerClass = Class.forName(checkerName);
                final DomainBlacklistChecker checker = (DomainBlacklistChecker) checkerClass.newInstance();
                newCheckers.add(checker);
            } catch (ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                log.error("Failed to load Domain Blacklist Checker '" + checkerName + "'.");
                newInitializationFailure = true;
            }
        }
        // Create combined blacklist
        final Collection<String> domainSetNotNormalized = getBlacklist(); 
        final HashMap<String,String> domainMap = new HashMap<>((int)(domainSetNotNormalized.size()/0.75)+1); // keys: normalized domains. values: unmodified blacklisted domains
        if (log.isDebugEnabled()) {
            log.debug("Normalizing " + domainSetNotNormalized.size() + " domains for Validator '" + getProfileName() + "'");
        }
        for (final String domain : domainSetNotNormalized) {
            // Normalize before adding to combined list
            final String normalizedDomain = normalizeDomain(newNormalizers, domain);
            domainMap.put(normalizedDomain, domain);
            if (log.isTraceEnabled()) {
                log.trace("Normalized domain '" + domain + "' to '" + normalizedDomain + "'");
            }
        }
        // Initialize checkers
        for (final DomainBlacklistChecker checker : newCheckers) {
            checker.initialize(data, domainMap);
        }
        if (log.isDebugEnabled()) {
            log.debug("Initialized cache for Validator '" + getProfileName() + "' with " + domainMap.size() + " domains, " + newCheckers.size() + " checkers, " + newNormalizers.size() + " normalizers.");
        }
        cache = new Cache(newInitializationFailure, newNormalizers, newCheckers); 
        log.trace("<reloadBlacklistData");
    }

    /**
     *  Clears caches. This will trigger a re-build of the combined in-memory blacklist.
     */
    private void clearCache() {
        if (log.isDebugEnabled()) {
            log.debug("Clearing domain blacklist cache for validator '" + getProfileName() + "'");
        }
        cache = null;
    }

    @Override
    public void initDynamicUiModel() {
        uiModel = new DynamicUiModel(data, getFilteredDataMapForLogging()) {
            @Override
            public Map<String, Object> getRawData() {
                final Map<String, Object> rawData = super.getRawData();
                // Parse file data
                final DynamicUiProperty<?> uploadUiProperty = getProperties().get(BLACKLIST_UPLOAD_KEY);
                final File uploadedFile = (File) uploadUiProperty.getValue();
                if (uploadedFile != null) {
                    try {
                        if (log.isDebugEnabled()) {
                            log.debug("Parsing uploaded file: " + uploadedFile.getName());
                        }
                        changeBlacklist(uploadedFile);
                    } finally {
                        uploadedFile.delete();
                    }
                } else {
                    log.debug("No new blacklist file was uploaded.");
                }
                return rawData;
            }
        };
        uiModel.add(new DynamicUiProperty<String>("settings"));
        addClassSelection(DomainBlacklistNormalizer.class, NORMALIZATIONS_KEY,  false, getNormalizations(), null);
        addClassSelection(DomainBlacklistChecker.class, CHECKS_KEY, true, getChecks(), DomainBlacklistExactMatchChecker.class.getName());
        addBlacklistInfo();
        uploadBlacklistFile();
    }

    private <T extends NameTranslatable> void addClassSelection(final Class<T> clazz, final String dataMapKey, final boolean required, final List<String> currentValues, final String defaultValue) {
        final LinkedHashMap<String,String> labels = new LinkedHashMap<>();
        final ServiceLoader<T> serviceLoader = ServiceLoader.load(clazz);
        for (final T implementation : serviceLoader) {
            final String displayName = implementation.getNameKey();
            final String name = implementation.getClass().getName();
            if (log.isDebugEnabled()) {
                log.debug("Found implementation: " + name);
            }
            labels.put(name, displayName);
        }
        MapTools.sortLinkedHashMap(labels, String.CASE_INSENSITIVE_ORDER);
        final DynamicUiProperty<String> uiProperty = new DynamicUiProperty<>(String.class, dataMapKey, defaultValue, labels.keySet());
        uiProperty.setRenderingHint(DynamicUiProperty.RENDER_SELECT_MANY);
        uiProperty.setLabels(labels);
        uiProperty.setHasMultipleValues(true);
        uiProperty.setRequired(required);
        try {
            uiProperty.setValues(currentValues);
        } catch (PropertyValidationException e) {
            throw new IllegalStateException(e);
        }
        uiModel.add(uiProperty);
    }

    private void addBlacklistInfo() {
        final Date blacklistDate = getBlacklistDate();
        if (blacklistDate == null) {
            log.debug("No file has been uploaded previously");
            return;
        }
        final DynamicUiProperty<String> uiProperty = new DynamicUiProperty<>(String.class, BLACKLIST_INFO_KEY, null);
        uiProperty.setRenderingHint(DynamicUiProperty.RENDER_LABEL);
        uiProperty.setEscape(false);
        uiProperty.setTransientValue(true);
        try {
            final String text = intres.getLocalizedMessage("validator.domainblacklist.info_text",
                    CollectionUtils.size(getBlacklist()), ValidityDate.formatAsUTC(blacklistDate), getBlacklistSha256());
            final String html = StringEscapeUtils.escapeHtml(text).replace("|", "<br />");
            uiProperty.setValue(html);
        } catch (PropertyValidationException e) {
            throw new IllegalStateException(e);
        }
        uiModel.add(uiProperty);
    }

    private void uploadBlacklistFile() {
        final DynamicUiProperty<File> uiProperty = new DynamicUiProperty<>(File.class, BLACKLIST_UPLOAD_KEY, null);
        uiProperty.setRenderingHint(DynamicUiProperty.RENDER_FILE_CHOOSER);
        uiProperty.setTransientValue(true);
        uiModel.add(uiProperty);
    }

    @Override
    public DynamicUiModel getDynamicUiModel() {
        return uiModel;
    }

    @Override
    public String getValidatorTypeIdentifier() {
        return TYPE_IDENTIFIER;
    }

    @Override
    public String getLabel() {
        return intres.getLocalizedMessage("validator.implementation.dnsname.domainblacklist");
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return DomainBlacklistValidator.class;
    }

    @Override
    public Class<? extends Validator> getValidatorSubType() {
        return DnsNameValidator.class;
    }

    private String normalizeDomain(final List<DomainBlacklistNormalizer> normalizersToUse, final String domainName) {
        String normalizedDomain = domainName;
        for (final DomainBlacklistNormalizer normalizer : normalizersToUse) {
            normalizedDomain = normalizer.normalize(normalizedDomain);
        }
        return normalizedDomain;
    }

    @Override
    public Entry<Boolean, List<String>> validate(final ExecutorService executorService, final String... domainNames) {
        loadBlacklistData();
        if (cache.initializationFailure) {
            final String message = "Validation cannot be performed due to a configuration problem with '" + getProfileName() + "'."; // getProfileName returns the validator name
            log.debug(message);
            return new AbstractMap.SimpleEntry<>(Boolean.FALSE, new ArrayList<>(Arrays.asList(message)));
        }
        boolean result = true;
        final List<String> messages = new ArrayList<>();
        for (final String domainName : domainNames) {
            final String normalizedDomain = normalizeDomain(cache.normalizers, domainName);
            if (log.isDebugEnabled()) {
                log.debug("Normalized domain '" + domainName + "' to '" + normalizedDomain + "'. Checking with " + cache.checkers.size() + " checkers.");
            }
            for (final DomainBlacklistChecker checker : cache.checkers) {
                final String matchingBlacklistedDomain = checker.check(normalizedDomain);
                if (matchingBlacklistedDomain != null) {
                    messages.add("Domain '" + domainName + "' is blacklisted. Matching domain on blacklist: '" + matchingBlacklistedDomain +"'");
                    result = false;
                }
            }
        }
        return new AbstractMap.SimpleEntry<>(result, messages);
    }

    public List<String> getNormalizations() {
        return getData(NORMALIZATIONS_KEY, Collections.emptyList());
    }

    // The GUI sets NORMALIZATIONS_KEY directly in the data map
    public void setNormalizations(final List<String> normalizationClasses) {
        putData(NORMALIZATIONS_KEY, normalizationClasses);
        clearCache();
    }

    public List<String> getChecks() {
        return getData(CHECKS_KEY, Collections.emptyList());
    }

    // The GUI sets CHECKS_KEY directly in the data map
    public void setChecks(final List<String> checks) {
        putData(CHECKS_KEY, checks);
        clearCache();
    }


    public Collection<String> getBlacklist() {
        return getData(BLACKLISTS_KEY, Collections.emptyList());
    }

    public void setBlacklist(final Collection<String> domainMap) {
        putData(BLACKLISTS_KEY, new ArrayList<>(domainMap));
        clearCache();
    }

    public Date getBlacklistDate() {
        return getData(BLACKLIST_DATE_KEY, null);
    }

    public void setBlacklistDate(final Date date) {
        putData(BLACKLIST_DATE_KEY, date);
    }

    public String getBlacklistSha256() {
        return getData(BLACKLIST_SHA256_KEY, "");
    }

    public void setBlacklistSha256(final String sha256) {
        putData(BLACKLIST_SHA256_KEY, sha256);
    }

    @Override
    public LinkedHashMap<Object,Object> getFilteredDataMapForLogging() {
        LinkedHashMap<Object,Object> map = getDataMap();
        final Collection<?> blacklists = (Collection<?>) map.get(BLACKLISTS_KEY);
        if (blacklists == null || blacklists.size() <= MAX_LOG_DOMAINS) {
            return map; // Just log as is
        } else {
            map = new LinkedHashMap<>(map);
            map.put(BLACKLISTS_KEY, "(" + blacklists.size() + " entries, not shown in the log)");
            return map;
        }
    }

    @Override
    public String getLogMessage(final boolean successful, final List<String> messages) {
        final String validatorName = getProfileName();
        final String languageKey = successful ? "validator.domainblacklist.validation_successful" : "validator.domainblacklist.validation_failed";
        return intres.getLocalizedMessage(languageKey, validatorName, messages);
    }

    @Override
    public DomainBlacklistValidator clone() {
        final DomainBlacklistValidator clone = (DomainBlacklistValidator) super.clone();
        clone.cache = cache; // cache is not modified, so it can be referenced.
        return clone;
    }
}
