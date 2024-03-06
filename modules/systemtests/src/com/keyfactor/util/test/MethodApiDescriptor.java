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
package com.keyfactor.util.test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

import org.bouncycastle.util.encoders.Hex;

/**
 * Describes a method that is part of an API and should NOT change across versions.
 * It contains the name, the parameters and return type of the method.
 *
 * It does not check the exceptions, because the peers protocol can handle exception
 * changes in the happy path.
 */
public class MethodApiDescriptor {

    private static final byte[] HASH_SEPARATOR = new byte[] { 0 };
    private static final String DUMMY_PARAM_TYPE = "com.example.ParamObject123";
    private static final String DUMMY_RETURN_TYPE = "com.example.ReturnObject123";

    private ApiVersion apiVersion;
    private final String name;
    private final String returnType;
    private final List<String> parameterTypes;
    private final String expectedHash;

    public MethodApiDescriptor(final String name, final String returnType, final List<String> parameterTypes, final String expectedHash) {
        this(ApiVersion.INITIAL_VERSION, name, returnType, parameterTypes, expectedHash);
    }

    public MethodApiDescriptor(final ApiVersion apiVersion, final String name, final String returnType, final List<String> parameterTypes, final String expectedHash) {
        this.apiVersion = apiVersion;
        this.name = Objects.requireNonNull(name);
        this.returnType = Objects.requireNonNull(returnType);
        this.parameterTypes = Objects.requireNonNull(parameterTypes);
        this.expectedHash = Objects.requireNonNull(expectedHash);
    }

    // This constructor should NOT be made public (it would be too easy to shoot oneself in the foot and not notice)
    private MethodApiDescriptor(final Method method) {
        this.name = method.getName();
        this.returnType = method.getReturnType().getName();
        this.parameterTypes = Arrays.stream(method.getParameterTypes()).<String>map(param -> param.getName()).collect(Collectors.toList());
        this.expectedHash = null;
    }

    public void checkUnchanged(final Method method) {
        checkHashValue();
        assertEquals("Method name has changed, which is an incompatible API change.", name, method.getName());
        assertEquals("Method '" + name + "' has a different return type, which is an incompatible API change.", returnType, method.getReturnType().getName());
        final Class<?>[] actualParameters = method.getParameterTypes();
        if (actualParameters.length != parameterTypes.size()) {
            assertEquals("Method '" + name + "' has a different number of parameters, which is an incompatible API change.", name, method.getName());
        }
        final Iterator<String> expectedParamsIter = parameterTypes.iterator();
        for (final Class<?> actualParam : actualParameters) {
            final String expectedParam = expectedParamsIter.next();
            assertEquals("Method '" + name + "' has an incompatible parameter type.", expectedParam, actualParam.getName());
        }
    }

    private void checkHashValue() {
        assertNotNull(expectedHash);
        // Not using assertEquals here, because it would show the actual value of the hash,
        // and it should NOT be copied.
        assertTrue("Test data has been corrupted. Please revert the changes!", getActualHashValue().equals(expectedHash));
}

    public String getName() {
        return name;
    }

    public ApiVersion getApiVersion() {
        return apiVersion;
    }

    public String getReturnType() {
        return returnType;
    }

    public List<String> getParameterTypes() {
        return parameterTypes;
    }

    public static String formatAsJavaCode(final Method method) {
        final MethodApiDescriptor desc = new MethodApiDescriptor(method);
        return desc.formatAsJavaCode();
    }

    private String formatAsJavaCode() {
        String code = "new MethodApiDescriptor(\"" + name + "\", \"" + returnType + "\", ";
        if (parameterTypes.isEmpty()) {
            code += "Collections.emptyList()";
        } else {
            code += "Arrays.asList(\"" + String.join("\", \"", parameterTypes) + "\")";
        }
        code += ", \"" + getHashString() + "\")";
        return code;
    }

    /** Returns a hash of the method declaration. The purpose is to detect changes */
    private String getHashString() {
        if (expectedHash != null) {
            // Expected value
            return expectedHash;
        } else {
            // Actual value
            return getActualHashValue();
        }
    }

    private String getActualHashValue() {
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(name.getBytes(StandardCharsets.US_ASCII));
            md.update(HASH_SEPARATOR);
            md.update(returnType.getBytes(StandardCharsets.US_ASCII));
            md.update(HASH_SEPARATOR);
            for (final String paramType : parameterTypes) {
                md.update(paramType.getBytes(StandardCharsets.US_ASCII));
                md.update(HASH_SEPARATOR);
            }
            final byte[] hashBytes = md.digest();
            return new String(Hex.encode(hashBytes), StandardCharsets.US_ASCII).substring(0, 12);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not supported", e);
        }
    }

    public static MethodApiDescriptor makeDummyMethod(final String methodName) {
        final MethodApiDescriptor desc = new MethodApiDescriptor(methodName, DUMMY_RETURN_TYPE, Arrays.asList(DUMMY_PARAM_TYPE), "dummy");
        return new MethodApiDescriptor(methodName, DUMMY_RETURN_TYPE, Arrays.asList(DUMMY_PARAM_TYPE), desc.getActualHashValue());
    }
}
