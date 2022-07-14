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
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.regex.Pattern;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CesecoreException;
import org.cesecore.keys.validation.DnsNameValidator;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.profiles.Profile;
import org.cesecore.util.CertTools;
import org.cesecore.util.ValidityDate;
import org.cesecore.util.ui.DynamicUiActionCallback;
import org.cesecore.util.ui.DynamicUiCallbackException;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;
import org.cesecore.util.ui.PropertyValidationException;


public class DomainAllowlistValidator extends ValidatorBase implements DnsNameValidator {
    
    private static final long serialVersionUID = 5317012621081331592L;
    private static final Pattern allowedDomainCharacters = Pattern.compile("^[a-zA-Z0-9._\\-\\*]+$");
    private static final String WILDCARD = "*";

    private static final Logger log = Logger.getLogger(DomainAllowlistValidator.class);

    /** The domain allowed list validator type. */
    private static final String TYPE_IDENTIFIER = "DOMAIN_ALLOWLIST_VALIDATOR";
    /** Current whitelist. Set of strings or regex */
    private static final String WHITELISTS_KEY = "whitelists";
    /** Information about the existing whitelist: Filename, date, SHA-256 */
    private static final String WHITELIST_INFO_KEY = "whitelist_info"; // Used in GUI only
    private static final String WHITELIST_DATE_KEY = "whitelist_date";     // Persisted
    private static final String WHITELIST_SHA256_KEY = "whitelist_sha256"; // Persisted
    /** File upload of new existing whitelist. Not persisted */
    private static final String WHITELIST_UPLOAD_KEY = "whitelist_upload";
    /** Text field that allow for testing of domains. Not persisted. */
    private static final String TEST_DOMAINENTRY_KEY = "test_domainentry";
    private static final String TEST_BUTTON_KEY = "test_button";
    private static final String TEST_BUTTON_TEXT = "test_button_text";
    private static final String TEST_RESULT_KEY = "test_result";
    
    /** Dynamic UI model extension. */
    protected DynamicUiModel uiModel;
    
    @Override
    public String getValidatorTypeIdentifier() {
        return TYPE_IDENTIFIER;
    }

    @Override
    public String getLabel() {
        return intres.getLocalizedMessage("validator.implementation.dnsname.domainallowlist");
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

    @Override
    public Class<? extends Validator> getValidatorSubType() {
        return DnsNameValidator.class;
    }

    @Override
    public void initDynamicUiModel() {
        uiModel = new DynamicUiModel(data, getFilteredDataMapForLogging()) {
            @Override
            public Map<String, Object> getRawData() throws CesecoreException {
                final Map<String, Object> rawData = super.getRawData();
                // Parse file data
                final DynamicUiProperty<?> uploadUiProperty = getProperties().get(WHITELIST_UPLOAD_KEY);
                final byte[] uploadedFile = (byte[]) uploadUiProperty.getValue();
                if (uploadedFile != null) {
                    if (log.isDebugEnabled()) {
                        log.debug("Parsing uploaded file: " + uploadedFile);
                    }
                    changeWhitelist(uploadedFile);
                } else {
                    log.debug("No new block list file was uploaded.");
                }
                return rawData;
            }
        };
        uiModel.add(new DynamicUiProperty<String>("settings"));
        addWhitelistInfo();
        uploadWhitelistFile();
        if (getWhitelistDate() != null) {
            addTestControls();
        }
        
    }
    
    public void changeWhitelist(final byte[] bytes) throws DomainListFileException {
        final Set<String> domainSet = new HashSet<>(); // store entries sorted in database
        try {
            try (final InputStream domainWhitelistInputStream = new ByteArrayInputStream(bytes);
                 final BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(domainWhitelistInputStream, StandardCharsets.UTF_8))) {
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
                    line = line.toLowerCase(Locale.ROOT);
                    line = formatRegexDomainIfNecessary(line);
                    domainSet.add(line);
                }
                if (log.isDebugEnabled()) {
                    log.debug("Parsed domain allow list with " + domainSet.size() + " entries (" + lineNumber + " lines)");
                }
                setWhitelist(domainSet);
                setWhitelistDate(new Date());
                final String sha256 = new String(Hex.encode(CertTools.generateSHA256Fingerprint(bytes)), StandardCharsets.US_ASCII);
                setWhitelistSha256(sha256);
            }
        } catch (IOException e) {
            throw new DomainListFileException("Unable to parse domain allow list. " + e.getMessage());
        }
    }
    
    private String formatRegexDomainIfNecessary(String str) {
        if(str.contains(WILDCARD)) {
            str = str.replace(".", "\\.");
            str = str.replace("*", ".*");
        }
        return str;
    }
    
    /**
     * Performs a basic validation of a domain, just to prevent mistakes.
     * Given that we may want to block fraud domains, we should not be too strict with standards compliance here.
     * Otherwise, we could have used StringTools.isValidSanDnsName
     * @throws DomainListFileException 
     */
    private void validateDomain(final String domain, final int lineNumber) throws DomainListFileException {
        if (!allowedDomainCharacters.matcher(domain).matches()) {
            final String message = "Invalid syntax of domain at line " + lineNumber + (lineNumber < 5 ? ". The file must be a plain text file in ASCII format, or UTF-8 format (without Byte Order Mark). Please put one domain per line. IDN domains must be in Punycode format." : "");
            log.info(message);
            throw new DomainListFileException(message);
        }
    }
    
    private void addWhitelistInfo() {
        final Date blacklistDate = getWhitelistDate();
        if (blacklistDate == null) {
            log.debug("No file has been uploaded previously");
            return;
        }
        final DynamicUiProperty<String> uiProperty = new DynamicUiProperty<>(String.class, WHITELIST_INFO_KEY, null);
        uiProperty.setRenderingHint(DynamicUiProperty.RENDER_LABEL);
        uiProperty.setEscape(false);
        uiProperty.setTransientValue(true);
        try {
            final String text = intres.getLocalizedMessage("validator.domainallowlist.info_text",
                    CollectionUtils.size(getWhitelist()), ValidityDate.formatAsUTC(blacklistDate), getWhitelistSha256());
            final String html = StringEscapeUtils.escapeHtml(text).replace("|", "<br />");
            uiProperty.setValue(html);
        } catch (PropertyValidationException e) {
            throw new IllegalStateException(e);
        }
        uiModel.add(uiProperty);
    }

    private void uploadWhitelistFile() {
        final DynamicUiProperty<File> uiProperty = new DynamicUiProperty<>(File.class, WHITELIST_UPLOAD_KEY, null);
        uiProperty.setRenderingHint(DynamicUiProperty.RENDER_FILE_CHOOSER);
        uiProperty.setTransientValue(true);
        uiModel.add(uiProperty);
    }

    private void addTestControls() {
        final DynamicUiProperty<String> testEntry = new DynamicUiProperty<>(String.class, TEST_DOMAINENTRY_KEY, "");
        testEntry.setRenderingHint(DynamicUiProperty.RENDER_TEXTFIELD);
        testEntry.setTransientValue(true);
        testEntry.setRequired(false);
        try {
            testEntry.setValue("");
        } catch (PropertyValidationException e) {
            throw new IllegalStateException(e);
        }
        uiModel.add(testEntry);
        final DynamicUiProperty<String> testButton = new DynamicUiProperty<>(String.class, TEST_BUTTON_KEY, TEST_BUTTON_TEXT);
        testButton.setRenderingHint(DynamicUiProperty.RENDER_BUTTON);
        testButton.setTransientValue(true);
        testButton.setActionCallback(new DynamicUiActionCallback() {
            @Override
            public void action(final Object parameter) throws DynamicUiCallbackException, CesecoreException {
                final DynamicUiProperty<?> domainEntryProperty = uiModel.getProperties().get(TEST_DOMAINENTRY_KEY);
                uiModel.writeProperties(getRawData());
                final String resultText = testDomain((String) domainEntryProperty.getValue());
                uiModel.firePropertyChange(TEST_RESULT_KEY, "x", resultText);
            }
            @Override
            public List<String> getRender() {
                return new ArrayList<>(Collections.singleton(TEST_RESULT_KEY));
            }
        });
        uiModel.add(testButton);
        final DynamicUiProperty<String> resultLabel = new DynamicUiProperty<>(String.class, TEST_RESULT_KEY, "");
        resultLabel.setRenderingHint(DynamicUiProperty.RENDER_LABEL);
        resultLabel.setEscape(false);
        resultLabel.setTransientValue(true);
        uiModel.add(resultLabel);
    }

    @Override
    public DynamicUiModel getDynamicUiModel() {
        return uiModel;
    }

    @Override
    public Entry<Boolean, List<String>> validate(ExecutorService executorService, String... domainNames) {        
        final Set<String> whiteList = getWhitelist();
        if(whiteList==null || whiteList.isEmpty()) {
            return new AbstractMap.SimpleEntry<>(false, Arrays.asList("Allowed domain list is not initialized."));
        }
        
        boolean result=true;
        final List<String> messages = new ArrayList<>();
        
        outer: 
        for (final String domainName : domainNames) {

            String formattedDomainName = formatRegexDomainIfNecessary(domainName);
            if(whiteList.contains(formattedDomainName))
                continue;
            
            for(String allowedDomain: whiteList) {
                // validate regex only when necessary
                if(allowedDomain.contains(WILDCARD) && domainName.matches(allowedDomain)) {
                        continue outer;
                }
            }
            
            messages.add("Domain '" + domainName + "' is not allowed.");
            result = false;
            
        }
        return new AbstractMap.SimpleEntry<>(result, messages);
    }
    
    /**
     * Performs a test validation of a domain
     * @param domain Domain to test
     * @return HTML message.
     */
    private String testDomain(final String domain) {
        if (log.isDebugEnabled()) {
            log.debug("Testing domain: " + domain);
        }
        if (StringUtils.isBlank(domain)) {
            return "";
        }
        final Entry<Boolean,List<String>> result = validate(null, domain.trim());
        if (result.getKey()) {
            return StringEscapeUtils.escapeHtml(intres.getLocalizedMessage("validator.domainallowlist.validation_successful", getProfileName()));
        } else if (CollectionUtils.isEmpty(result.getValue())) {
            return "Failed to check domain"; // Bug. Should never happen
        } else {
            final StringBuilder sb = new StringBuilder();
            for (final String message : result.getValue()) {
                if (sb.length() != 0) {
                    sb.append("<br />");
                }
                sb.append(StringEscapeUtils.escapeHtml(message));
            }
            return sb.toString();
        }
    }

    @Override
    public String getLogMessage(boolean successful, List<String> messages) {
        final String validatorName = getProfileName();
        final String languageKey = successful ? "validator.domainallowlist.validation_successful" : "validator.domainallowlist.validation_failed";
        return intres.getLocalizedMessage(languageKey, validatorName, messages);
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return DomainAllowlistValidator.class;
    }
    
    public Set<String> getWhitelist() {
        return getData(WHITELISTS_KEY, Collections.emptySet());
    }

    public void setWhitelist(final Collection<String> domainSet) {
        putData(WHITELISTS_KEY, new HashSet<>(domainSet));
    }

    public Date getWhitelistDate() {
        return getData(WHITELIST_DATE_KEY, null);
    }

    public void setWhitelistDate(final Date date) {
        putData(WHITELIST_DATE_KEY, date);
    }

    public String getWhitelistSha256() {
        return getData(WHITELIST_SHA256_KEY, "");
    }

    public void setWhitelistSha256(final String sha256) {
        putData(WHITELIST_SHA256_KEY, sha256);
    }

}
