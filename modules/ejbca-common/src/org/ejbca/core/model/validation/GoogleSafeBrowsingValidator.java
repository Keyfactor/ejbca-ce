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

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.log4j.Logger;
import org.cesecore.keys.validation.DnsNameValidator;
import org.cesecore.keys.validation.IssuancePhase;
import org.cesecore.keys.validation.Validator;
import org.cesecore.keys.validation.ValidatorBase;
import org.cesecore.profiles.Profile;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.config.InternalConfiguration;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.IOException;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;

import static java.util.stream.Collectors.toList;

/**
 * Validates domain names against the <a href="https://developers.google.com/safe-browsing">Google Safe Browsing API</a>.
 *
 * @version $Id$
 */
public class GoogleSafeBrowsingValidator extends ValidatorBase implements DnsNameValidator, Serializable {
    private static final long serialVersionUID = -1L;
    public static final String TYPE_IDENTIFIER = "SAFE_BROWSING_VALIDATOR";
    private static final String API_KEY_KEY = "API_KEY";
    private static final Logger log = Logger.getLogger(GoogleSafeBrowsingValidator.class);
    protected DynamicUiModel uiModel;
    private transient final Supplier<CloseableHttpClient> supplyHttpClient;

    public GoogleSafeBrowsingValidator(final Supplier<CloseableHttpClient> supplyHttpClient) {
        this.supplyHttpClient = supplyHttpClient;
    }

    public GoogleSafeBrowsingValidator() {
        this(() -> HttpClients.createDefault());
    }

    @Override
    public Map.Entry<Boolean, List<String>> validate(final ExecutorService executorService, final String... domainNames) {
        try (final CloseableHttpClient httpClient = supplyHttpClient.get()) {
            final HttpPost request = new HttpPost(String.format("https://safebrowsing.googleapis.com/v4/threatMatches:find?key=%s", getApiKey()));
            final StringEntity entity = new StringEntity(createJsonPayload(domainNames), StandardCharsets.UTF_8);
            request.addHeader(HttpHeaders.USER_AGENT, InternalConfiguration.getAppNameCapital());
            request.addHeader(HttpHeaders.CONTENT_TYPE, "application/json");
            request.setEntity(entity);
            if (log.isDebugEnabled()) {
                log.debug("Sending request: " + EntityUtils.toString(request.getEntity()));
            }
            try (final CloseableHttpResponse response = httpClient.execute(request)) {
                final String json = response.getEntity() == null
                        ? "null"
                        : EntityUtils.toString(response.getEntity());
                if (log.isDebugEnabled()) {
                    log.debug("Response received: " + json);
                }
                if (response.getStatusLine().getStatusCode() != 200) {
                    return new AbstractMap.SimpleEntry<>(false, Arrays.asList("HTTP error code " + response.getStatusLine().getStatusCode()
                            + " received from the Google Safe Browsing API."));
                }
                return parseJsonResponse(json, domainNames);
            }
        } catch (final IOException e) {
            log.error("Could not contact the Google Safe Browsing API.", e);
            return new AbstractMap.SimpleImmutableEntry<>(false, Arrays.asList("Could not contact the Google Safe Browsing API."));
        }
    }

    @Override
    public String getLogMessage(final boolean successful, final List<String> messages) {
        return successful
                ? intres.getLocalizedMessage("validator.safebrowsing.validation_successful")
                : intres.getLocalizedMessage("validator.safebrowsing.validation_failed") + " " + messages;
    }

    @Override
    public String getValidatorTypeIdentifier() {
        return GoogleSafeBrowsingValidator.TYPE_IDENTIFIER;
    }

    @Override
    public String getLabel() {
        return intres.getLocalizedMessage("validator.implementation.dnsname.safebrowsing");
    }

    @Override
    public Class<? extends Validator> getValidatorSubType() {
        return DnsNameValidator.class;
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return GoogleSafeBrowsingValidator.class;
    }

    @Override
    public void initDynamicUiModel() {
        uiModel = new DynamicUiModel(data);
        uiModel.add(new DynamicUiProperty<>(String.class, API_KEY_KEY, getApiKey()));
    }

    @Override
    public DynamicUiModel getDynamicUiModel() {
        return uiModel;
    }

    @Override
    public List<Integer> getApplicablePhases() {
        return new ArrayList<>(Arrays.asList(IssuancePhase.DATA_VALIDATION.getIndex()));
    }

    private String getApiKey() {
        return data.get(API_KEY_KEY) == null
                ? StringUtils.EMPTY
                : StringUtils.trim((String) data.get(API_KEY_KEY));
    }
    
    public String getApiKeyForConfigdump() {
        return "placeholder";
    }
    
    public void setApiKeyForConfigdump(String apiKey) {
        data.put(API_KEY_KEY, apiKey);
    }

    /**
     * Creates a JSON payload to send to the Google Safe Browsing Lookup API v4.
     *
     * Example payload:
     * <pre>
     * {
     *     "client": {
     *         "clientId": "EJBCA",
     *         "clientVersion": "version of EJBCA"
     *     },
     *     "threatInfo": {
     *     "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
     *     "platformTypes": ["ANY_PLATFORM"],
     *     "threatEntryTypes": ["URL"],
     *     "threatEntries": [
     *         {"url": "domain1.com"},
     *         {"url": "domain2.com"}
     *       ]
     *     }
     * }
     * </pre>
     *
     * The lists MALWARE/ANY_PLATFORM/URL and SOCIAL_ENGINEERING/ANY_PLATFORM/URL are used.
     * You can list <a href="https://safebrowsing.googleapis.com/v4/threatLists?key=API_KEY">
     * all available lists through the API</a>.
     *
     * @param domainNames the domain names from the certificate.
     * @return a JSON payload to send to the Google Safe Browsing Lookup API.
     */
    @SuppressWarnings("unchecked")
    private String createJsonPayload(final String[] domainNames) {
        final JSONObject client = new JSONObject();
        final JSONObject threatInfo = new JSONObject();
        final JSONObject jsonPayload = new JSONObject();
        final JSONArray threatTypes = new JSONArray();
        final JSONArray platformTypes = new JSONArray();
        final JSONArray threatEntryTypes = new JSONArray();
        final JSONArray threatEntries = new JSONArray();
        client.put("clientId", InternalConfiguration.getAppNameCapital());
        client.put("clientVersion", InternalConfiguration.getAppVersionNumber());
        threatTypes.addAll(Arrays.asList("MALWARE", "SOCIAL_ENGINEERING"));
        platformTypes.addAll(Arrays.asList("ANY_PLATFORM"));
        threatEntryTypes.addAll(Arrays.asList("URL"));
        for (final String domainName : domainNames) {
            final JSONObject threatEntry = new JSONObject();
            threatEntry.put("url", domainName);
            threatEntries.add(threatEntry);
        }
        threatInfo.put("threatTypes", threatTypes);
        threatInfo.put("platformTypes", platformTypes);
        threatInfo.put("threatEntryTypes", threatEntryTypes);
        threatInfo.put("threatEntries", threatEntries);
        jsonPayload.put("client", client);
        jsonPayload.put("threatInfo", threatInfo);
        return jsonPayload.toJSONString();
    }

    /**
     * Parses a JSON payload received from the Google Safe Browsing Lookup API v4.
     *
     * Example payload (with threat entries):
     * <pre>
     * {
     *   "matches": [{
     *     "threatType":      "MALWARE",
     *     "platformType":    "WINDOWS",
     *     "threatEntryType": "URL",
     *     "threat":          {"url": "domain2.com"},
     *     "threatEntryMetadata": {
     *       "entries": [{
     *         "key": "malware_threat_type",
     *         "value": "landing"
     *      }]
     *     },
     *     "cacheDuration": "300.000s"
     *   }, {
     *     "threatType":      "MALWARE",
     *     "platformType":    "WINDOWS",
     *     "threatEntryType": "URL",
     *     "threat":          {"url": "domain1.com"},
     *     "threatEntryMetadata": {
     *       "entries": [{
     *         "key":   "malware_threat_type",
     *         "value": "landing"
     *      }]
     *     },
     *     "cacheDuration": "300.000s"
     *   }]
     * }
     * </pre>
     */
    private Map.Entry<Boolean, List<String>> parseJsonResponse(final String json, final String[] domainNames) {
        try {
            final JSONObject jsonPayload = (JSONObject) new JSONParser().parse(json);
            if (!jsonPayload.containsKey("matches")) {
                return new AbstractMap.SimpleImmutableEntry<>(true, Arrays.asList("Domain names passed Google Safe Browsing validation."));
            }
            return new AbstractMap.SimpleImmutableEntry<>(false, Arrays.asList(domainNames)
                    .stream()
                    .map(domainName -> getValidationResult((JSONArray) jsonPayload.get("matches"), domainName))
                    .collect(toList()));
        } catch (final ParseException e) {
            log.error("Could not parse JSON response.", e);
            return new AbstractMap.SimpleImmutableEntry<>(false, Arrays.asList("Could not parse JSON response."));
        }
    }

    private String getValidationResult(final JSONArray matches, final String domainName) {
        final Iterator<?> iterator = matches.iterator();
        while (iterator.hasNext()) {
            final JSONObject nextMatch = (JSONObject) iterator.next();
            final JSONObject threat = (JSONObject) nextMatch.get("threat");
            if (StringUtils.equals((String) threat.get("url"), domainName)) {
                return domainName + " is a threat.";
            }
        }
        return domainName + " is not a threat.";
    }
}
