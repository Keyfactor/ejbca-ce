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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.cesecore.profiles.Profile;

/**
 * @version $Id$
 *
 */
public class DnsNameValidatorMock extends ValidatorBase implements DnsNameValidator {

    private static final long serialVersionUID = 1L;

    private static final String DOMAIN_NAMES_KEY = "domainNames";
    
    private transient Set<String> domainNames;
    
    
    public DnsNameValidatorMock() {
        super();
        setDomainNames(new HashSet<String>());
    }
    
    public DnsNameValidatorMock(String name, String... domainNames) {
        super(name);
        setDomainNames(new HashSet<>(Arrays.asList(domainNames)));
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
    public List<String> validate(String... domainNames) {
        //Return all domain names that overlap with those preset in this validator.
        List<String> result = new ArrayList<>();
        for(String domainName : domainNames) {
            if(getDomainNames().contains(domainName)) {
                result.add(domainName);
            }
        }
        if(result.size() != getDomainNames().size()) {
            throw new IllegalStateException("Test failed, wrong set of domain names was sent in.");
        }
        return new ArrayList<String>();
    }

    @Override
    public String getIssuer() {
        return null;
    }

    @Override
    public String getTemplateFile() {
        return null;
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

    }

    @Override
    protected void saveTransientObjects() {
        super.saveTransientObjects();
        //Here we return all sequences to be persisted. 
        Map<Object, Object> transientObjects = new HashMap<>();
        if (getDomainNames() != null) {
            transientObjects.put(DOMAIN_NAMES_KEY, getDomainNames());
        }
   
         data.putAll(transientObjects);
    }

    
}
