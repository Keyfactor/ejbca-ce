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

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;
import java.util.ServiceLoader;
import java.util.Set;
import java.util.concurrent.ExecutorService;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.keys.validation.DnsNameValidator;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.profiles.Profile;
import org.cesecore.util.MapTools;
import org.cesecore.util.NameTranslatable;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.PropertyValidationException;
import org.ejbca.core.ejb.ca.validation.BlacklistSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;
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

    /** The domain blacklist validator type. */
    private static final String TYPE_IDENTIFIER = "DOMAIN_BLACKLIST_VALIDATOR";

    private static final String NORMALIZATIONS_KEY = "normalizations";
    private static final String CHECKS_KEY = "checks";
    private static final String BLACKLISTS_KEY = "blacklists";
    
    private static final char SEPARATOR_CHAR = ';';

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
        return new ArrayList<>(Arrays.asList(IssuancePhase.DATA_VALIDATION.getIndex()));
    }

    @Override
    public void init() {
        super.init();
        // Add fields that have been upgraded and need default values here
        // Load blacklist data
        loadBlacklistData();
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
        final BlacklistSessionLocal blacklistSession = new EjbLocalHelper().getBlacklistSession();
        final Set<String> combinedBlacklist = new HashSet<>();
        for (final int blacklistId : getEnabledBlacklists()) {
            final BlacklistEntry blacklistEntry = blacklistSession.getBlacklistEntry(blacklistId);
            for (final String domainName : parseBlacklist(blacklistEntry.getData())) {
                // Normalize before adding to combined list
                final String normalizedDomain = normalizeDomain(newNormalizers, domainName);
                combinedBlacklist.add(normalizedDomain);
                if (log.isTraceEnabled()) {
                    log.trace("Normalized domain '" + domainName + "' to '" + normalizedDomain + "'");
                }
            }
        }
        // Initialize checkers
        for (final DomainBlacklistChecker checker : newCheckers) {
            checker.initialize(data, combinedBlacklist);
        }
        cache = new Cache(newInitializationFailure, newNormalizers, newCheckers); 
        log.trace("<reloadBlacklistData");
    }

    private String[] parseBlacklist(final String blacklistEntryData) {
        return StringUtils.split(blacklistEntryData, SEPARATOR_CHAR); 
    }

    /**
     *  Clears caches. This will trigger a re-build of the combined in-memory blacklist.
     */
    private void clearCache() {
        log.debug("Clearing domain blacklist cache for validator '" + getProfileName() + "'");
        cache = null;
    }

    @Override
    public void initDynamicUiModel() {
        uiModel = new DynamicUiModel(data);
        uiModel.add(new DynamicUiProperty<String>("settings"));
        addClassSelection(DomainBlacklistNormalizer.class, NORMALIZATIONS_KEY,  false, getNormalizations(), null);
        addClassSelection(DomainBlacklistChecker.class, CHECKS_KEY, true, getChecks(), DomainBlacklistExactMatchChecker.class.getName());
        addBlacklistSelection();
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
        // TODO this should if possible be replaced with checkboxes / radio buttons. Can we add two new rendering hints for this? Investigate in ECA-6052.
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

    private void addBlacklistSelection() {
        final LinkedHashMap<Integer,String> blacklists = new LinkedHashMap<>();
        // TODO Get available blacklists here (ECA-6052)
        MapTools.sortLinkedHashMap(blacklists, String.CASE_INSENSITIVE_ORDER);
        final DynamicUiProperty<Integer> uiProperty = new DynamicUiProperty<>(Integer.class, BLACKLISTS_KEY, null, blacklists.keySet());
        uiProperty.setRenderingHint(DynamicUiProperty.RENDER_SELECT_MANY);
        uiProperty.setLabels(blacklists);
        uiProperty.setHasMultipleValues(true);
        uiProperty.setRequired(true);
        try {
            uiProperty.setValues(getEnabledBlacklists());
        } catch (PropertyValidationException e) {
            throw new IllegalStateException(e);
        }
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
                log.debug("Normalized domain '" + domainName + "' to '" + normalizedDomain + "'");
            }
            for (final DomainBlacklistChecker checker : cache.checkers) {
                if (!checker.check(normalizedDomain)) {
                    messages.add("Domain '" + domainName + "' is blacklisted.");
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

    public List<Integer> getEnabledBlacklists() {
        return getData(BLACKLISTS_KEY, Collections.emptyList());
    }

    // The GUI sets BLACKLISTS_KEY directly in the data map
    public void setEnabledBlacklists(final List<Integer> blacklistId) {
        putData(BLACKLISTS_KEY, blacklistId);
        clearCache();
    }

    @Override
    public String getLogMessage(final boolean successful, final List<String> messages) {
        final String validatorName = getProfileName();
        final String languageKey = successful ? "validator.domainblacklist.validation_successful" : "validator.domainblacklist.validation_failed";
        return intres.getLocalizedMessage(languageKey, validatorName, messages);
    }
}
