/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.stream.Stream;

import org.cesecore.profiles.Profile;
import org.cesecore.util.ui.DynamicUiModel;

/**
 * @version $Id$
 *
 */
public class DnsNameValidatorMock extends ValidatorBase implements DnsNameValidator {

    private static final long serialVersionUID = 1L;

    private static final String DOMAIN_NAMES_KEY = "domainNames";
    private static final String VALIDATE_EMAIL_DOMAINS_KEY = "validateEmailDomains";
    private static final String FAIL_ON_FORBIDDEN_DOMAINS_KEY = "failOnForbiddenDomains";

    private transient Set<String> domainNames;
    private transient boolean validateEmailDomains = true;
    private transient boolean failOnForbiddenDomains = false;

    public DnsNameValidatorMock() {
        super();
        setDomainNames(new HashSet<String>());
    }

    public DnsNameValidatorMock(String name, String... domainNames) {
        super(name);
        setDomainNames(new HashSet<>(Arrays.asList(domainNames)));
    }

    public DnsNameValidatorMock(String name, boolean failOnForbiddenDomains, String... domainNames) {
        super(name);
        setDomainNames(new HashSet<>(Arrays.asList(domainNames)));
        this.failOnForbiddenDomains = failOnForbiddenDomains;
        saveTransientObjects();
    }

    @Override
    public void initDynamicUiModel() {
        // NOOP
    }

    @Override
    public DynamicUiModel getDynamicUiModel() {
        return null;
    }

    @Override
    public String getValidatorTypeIdentifier() {
        return null;
    }

    @Override
    public String getLabel() {
        return null;
    }

    @Override
    public Class<? extends Validator> getValidatorSubType() {
        return DnsNameValidator.class;
    }

    @Override
    public Entry<Boolean, List<String>> validate(final ExecutorService executorService, ValidationRequestParameters validationRequestParameters,
            final String... domainNames) {
        Set<String> domains = new HashSet<>();
        Stream.of(domainNames).filter(getDomainNames()::contains).forEach(domains::add);
        if (failOnForbiddenDomains) {
            if(domains.size() != domainNames.length) {
                return new AbstractMap.SimpleImmutableEntry<Boolean, List<String>>(Boolean.FALSE, new ArrayList<String>());
            }
        }
        if(domains.size() != getDomainNames().size()) {
            throw new IllegalStateException("Test failed, wrong set of domain names was sent in.");
        }
        return new AbstractMap.SimpleImmutableEntry<Boolean, List<String>>(Boolean.TRUE, new ArrayList<String>());
    }

    @Override
    protected Class<? extends Profile> getImplementationClass() {
        return DnsNameValidatorMock.class;
    }

    public Set<String> getDomainNames() {
        return domainNames;
    }

    public void setDomainNames(Set<String> domainNames) {
        this.domainNames = domainNames;
        saveTransientObjects();
    }

    @SuppressWarnings("unchecked")
    @Override
    protected void loadTransientObjects() {
        super.loadTransientObjects();
        this.domainNames =  (Set<String>) data.get(DOMAIN_NAMES_KEY);
        this.validateEmailDomains = (boolean) data.getOrDefault(VALIDATE_EMAIL_DOMAINS_KEY, true);
        this.failOnForbiddenDomains = (boolean) data.getOrDefault(FAIL_ON_FORBIDDEN_DOMAINS_KEY, false);
    }

    @Override
    protected void saveTransientObjects() {
        super.saveTransientObjects();
        //Here we return all sequences to be persisted.
        Map<Object, Object> transientObjects = new HashMap<>();
        if (getDomainNames() != null) {
            transientObjects.put(DOMAIN_NAMES_KEY, getDomainNames());
        }
        transientObjects.put(VALIDATE_EMAIL_DOMAINS_KEY, validateEmailDomains);
        transientObjects.put(FAIL_ON_FORBIDDEN_DOMAINS_KEY, failOnForbiddenDomains);
        data.putAll(transientObjects);
    }

    @Override
    public String getLogMessage(final boolean successful, final List<String> messages) {
        return "";
    }

    @Override
    public boolean isValidatorAlwaysApplicable() {
        return true;
    }
    
    @Override
    public boolean validateEmailDomains() {
        return validateEmailDomains;
    }
    
    public void setValidateEmailDomains(boolean validateEmailDomains) {
        this.validateEmailDomains = validateEmailDomains;
        saveTransientObjects();
    }

}
