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
package org.ejbca.test;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import javax.ejb.EJB;

import org.apache.log4j.Logger;

/**
 * Creates a session bean with mocked &amp;EJB injections
 */
public class EjbMocker<T> {
    
    private static final Logger log = Logger.getLogger(EjbMocker.class);

    private final Class<T> sessionBeanClass;
    private final Map<Class<?>, Object> mockedInjections = new HashMap<>();
    
    public EjbMocker(final Class<T> sessionBeanClass) {
        this.sessionBeanClass = sessionBeanClass;
    }
    
    /** Adds objects that should be injected in &amp;EJB annotated fields */
    public void addMockedInjections(final Object... toInject) {
        for (final Object obj : toInject) {
            for (final Class<?> iface : obj.getClass().getInterfaces()) {
                addInjection(iface, obj);
            }
        }
    }
    
    private void addInjection(Class<? extends Object> theClass, Object obj) {
        if (log.isDebugEnabled()) {
            log.debug("For interface " + theClass + ", " + obj.getClass().getName() + " will be injected.");
        }
        if (mockedInjections.put(theClass, obj) != null) {
            throw new IllegalStateException("Duplicate entry for mocked injection: " + theClass);
        }
    }

    /** Constructs the EJB to test and injects mock fields */
    public T construct() {
        final T ssb;
        try {
            ssb = sessionBeanClass.getConstructor().newInstance();
        } catch (NoSuchMethodException e) {
            throw new IllegalStateException("Missing default constructor in EJB to mock", e);
        } catch (ReflectiveOperationException | IllegalArgumentException | SecurityException e) {
            throw new IllegalStateException("Failed to construct EJB to mock: " + e.getMessage(), e);
        }
        injectAll(ssb);
        return ssb;
    }

    private void injectAll(final T ssb) {
        for (final Field field : sessionBeanClass.getDeclaredFields()) {
            if (field.getAnnotationsByType(EJB.class).length != 0) {
                if (log.isDebugEnabled()) {
                    log.debug("Found field annotated with @EJB: " + field.getName());
                }
                final Object obj = mockedInjections.get(field.getType());
                if (obj != null) {
                    injectMockedEjb(ssb, field, obj);
                }
            }
        }
    }

    private void injectMockedEjb(final T ssb, final Field field, final Object obj) {
        field.setAccessible(true);
        try {
            log.info("Injecting mock class to field: " + field.getName());
            field.set(ssb, obj);
        } catch (IllegalArgumentException | IllegalAccessException e) {
            throw new IllegalStateException("Failed to inject mock EJB", e);
        }
    }
    
}
