package org.ejbca.core.protocol.acme.eab;

import java.io.Serializable;
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
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map.Entry;

import org.apache.log4j.Logger;
import org.cesecore.accounts.AccountBinding;
import org.cesecore.accounts.AccountBindingBase;
import org.cesecore.util.ui.DynamicUiModel;
import org.cesecore.util.ui.DynamicUiModelAware;
import org.cesecore.util.ui.IndexedDynamicUiModel;
import org.ejbca.configdump.ConfigdumpProperty;

/**
 * Base class for all ACME external account bindings (EAB) strategy objects.
 */
public abstract class AcmeExternalAccountBindingBase extends AccountBindingBase implements AcmeExternalAccountBinding, DynamicUiModelAware, IndexedDynamicUiModel {

    private static final long serialVersionUID = 3018936825885684493L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(AcmeExternalAccountBindingBase.class);

    /** Dynamic UI model extension. */
    protected DynamicUiModel uiModel;
    
    /** Config dump extension. */
    protected List<ConfigdumpProperty<?>> configdumpProperties;
    
    @Override
    public boolean isDefault() {
        return false;
    }

    @Override
    public String getProfileType() {
        return AcmeExternalAccountBinding.TYPE_NAME;
    }

    @Override
    public Class<? extends AccountBinding> getAccountBindingSubType() {
        return AcmeExternalAccountBinding.class;
    }

    @Override
    public AcmeExternalAccountBinding clone() {
        AcmeExternalAccountBinding clone;
        try {
            clone = (AcmeExternalAccountBinding) getClass().getConstructor().newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Could not instantiate class of type " + getClass().getCanonicalName());
        }
        clone.setProfileName(getProfileName());
        clone.setProfileId(getProfileId());

        // We need to make a deep copy of the hash map here.
        LinkedHashMap<Object, Object> dataMap = new LinkedHashMap<>(data.size());
        for (final Entry<Object, Object> entry : data.entrySet()) {
            Object value = entry.getValue();
            if (value instanceof ArrayList<?>) {
                // We need to make a clone of this object, but the stored immutable values can still be referenced.
                value = ((ArrayList<?>) value).clone();
            }
            dataMap.put(entry.getKey(), value);
        }
        clone.setDataMap(dataMap);
        return clone;
    }

    // Configdump
    
    @Override
    public List<ConfigdumpProperty<? extends Serializable>> getConfigDumpProperties() {
        if (configdumpProperties == null) {
            initConfigdumpProperties();
            log.debug("Initialized config dump properties: " + configdumpProperties);
        }
        return new ArrayList<ConfigdumpProperty<?>>(configdumpProperties);
    }
    
    public abstract String getKeyIdentifier();
}
