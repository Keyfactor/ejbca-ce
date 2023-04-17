/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons                                                    *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.keys.token.pkcs11;

import java.io.File;
import java.lang.invoke.MethodHandle;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;

import org.apache.log4j.Logger;

/**
 *
 * This class wraps sun.security.pkcs11.wrapper.PKCS11, so that we can access the native C_GetSlotList PKCS11 
 * call directly to get information about slots/tokens and their labels.
 * 
 * A slot list and token labels for each slot is cached so that C_GetSlotList() only has to be called once and
 * so that C_GetTokenInfo() only has to be called once for each slot. This means that is additional/new slots are created on a token
 * EJBCA has to be restarted.
 * 
 * The {@link #getInstance(File)} method must be called before any SunPKCS#11 provider is created.
 */
public class SunP11SlotListWrapper implements PKCS11SlotListWrapper {
    private static final Logger log = Logger.getLogger(SunP11SlotListWrapper.class);

    private final HashMap<Long, char[]> labelMap;
    private final Method getSlotListMethod;
    private final Method getTokenInfoMethod;
    private final Field labelField;
    private final Object p11;
    private final long slotList[];

    public SunP11SlotListWrapper(final String fileName) {
        final Class<? extends Object> p11Class;
        try {
            p11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");
        } catch (ClassNotFoundException e) {
            String msg = "Class sun.security.pkcs11.wrapper.PKCS11 was not found locally, could not wrap.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }

        try {
            getSlotListMethod = p11Class.getDeclaredMethod("C_GetSlotList", boolean.class);
        } catch (NoSuchMethodException e) {
            String msg = "Method C_GetSlotList was not found in class sun.security.pkcs11.wrapper.PKCS11, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (SecurityException e) {
            String msg = "Access was denied to method sun.security.pkcs11.wrapper.PKCS11.C_GetSlotList";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }
        try {
            getTokenInfoMethod = p11Class.getDeclaredMethod("C_GetTokenInfo", long.class);
        } catch (NoSuchMethodException e) {
            String msg = "Method C_GetTokenInfo was not found in class sun.security.pkcs11.wrapper.PKCS11, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (SecurityException e) {
            String msg = "Access was denied to method sun.security.pkcs11.wrapper.PKCS11.C_GetTokenInfo";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }
        try {
            labelField = Class.forName("sun.security.pkcs11.wrapper.CK_TOKEN_INFO").getField("label");
        } catch (NoSuchFieldException e) {
            String msg = "Field 'label' was not found in class sun.security.pkcs11.wrapper.CK_TOKEN_INFO, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (SecurityException e) {
            String msg = "Access was denied to field sun.security.pkcs11.wrapper.CK_TOKEN_INFO.label";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (ClassNotFoundException e) {
            String msg = "Class sun.security.pkcs11.wrapper.CK_TOKEN_INFO was not found locally, could not wrap.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }

        // sun.security.pkcs11.wrapper.PKCS11.getInstance comes in a few different variantions. 
        // RedHat/Fedora has created one with five arguments instead of four
        Method getInstanceMethod1 = null;
        try {
            // "standard" OpenJDK getnstance (as of May 2022)
            getInstanceMethod1 = p11Class.getDeclaredMethod("getInstance",
                    new Class[] { String.class, String.class, Class.forName("sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS"), boolean.class });
        } catch (NoSuchMethodException e) {
            if (log.isDebugEnabled()) {
                String msg = "Method getInstance was not found in class sun.security.pkcs11.wrapper.PKCS11.CK_C_INITIALIZE_ARGS, this may be due to"
                        + " a change in the underlying library, will try second alternative getInstance signature.";
                log.debug(msg, e);
            }
        } catch (SecurityException e) {
            String msg = "Access was denied to method sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS.getInstance";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (ClassNotFoundException e) {
            String msg = "Class sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS was not found locally, could not wrap.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }
        
        Method getInstanceMethod2 = null;
        if (getInstanceMethod1 == null) {
            try {
                // RedHat/Fedora OpenJDK getnstance (as of May 2022), not the extra MethodHandle argument
                getInstanceMethod2 = p11Class.getDeclaredMethod("getInstance",
                        new Class[] { String.class, String.class, Class.forName("sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS"), boolean.class, MethodHandle.class });
            } catch (NoSuchMethodException e) {
                String msg = "Method getInstance was not found in class sun.security.pkcs11.wrapper.PKCS11.CK_C_INITIALIZE_ARGS, this may be due to"
                        + " a change in the underlying library. Neither first nor second alternative was found.";
                log.error(msg, e);
                throw new IllegalStateException(msg, e);
            } catch (SecurityException e) {
                String msg = "Access was denied to method sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS.getInstance";
                log.error(msg, e);
                throw new IllegalStateException(msg, e);
            } catch (ClassNotFoundException e) {
                String msg = "Class sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS was not found locally, could not wrap.";
                log.error(msg, e);
                throw new IllegalStateException(msg, e);
            }
        }
        
        
        try {
            if (getInstanceMethod1 != null) {
                this.p11 = getInstanceMethod1.invoke(null, new Object[] { fileName, "C_GetFunctionList", null, Boolean.FALSE });
            } else if (getInstanceMethod2 != null) {
                this.p11 = getInstanceMethod2.invoke(null, new Object[] { fileName, "C_GetFunctionList", null, Boolean.FALSE, null });
            } else {
                throw new IllegalStateException("No sun.security.pkcs11.wrapper.PKCS11.getInstance method found");
            }
        } catch (IllegalAccessException e) {
            String msg = "Method sun.security.pkcs11.wrapper.PKCS11.CK_C_INITIALIZE_ARGS.getInstance was not accessible, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (IllegalArgumentException e) {
            String msg = "Wrong arguments were passed to sun.security.pkcs11.wrapper.PKCS11.CK_C_INITIALIZE_ARGS.getInstance. This may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (InvocationTargetException e) {
            String msg = "Wrong arguments were passed to sun.security.pkcs11.wrapper.PKCS11.CK_C_INITIALIZE_ARGS.getInstance threw an exception "
                    + "for log.error(msg, e)";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }
        labelMap = new HashMap<>();
        slotList = C_GetSlotList();
        for (long id : slotList) {
            labelMap.put(id, getTokenLabelLocal(id));
        }
    }
    
//    public SunP11SlotListWrapper(final String fileName) {
//        this.fileName = fileName;
//        labelMap = new HashMap<>();
//        slotList = C_GetSlotList();
//        for (long id : slotList) {
//            labelMap.put(id, getTokenLabelLocal(id));
//        }
//    }

    @Override
    public long[] getSlotList() {
        return slotList;
    }

    @Override
    public char[] getTokenLabel(long slotID) {
        if (log.isTraceEnabled()) {
            log.trace(">getTokenLabel: " + slotID);
        }
        return labelMap.get(slotID);
    }

    private long[] C_GetSlotList() {
        try {
            return (long[]) getSlotListMethod.invoke(p11, Boolean.TRUE);
        } catch (IllegalAccessException e) {
            String msg = "Access was denied to method sun.security.pkcs11.wrapper.PKCS11C.GetSlotList, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (IllegalArgumentException e) {
            String msg = "Incorrect parameters sent to sun.security.pkcs11.wrapper.PKCS11C.GetSlotList, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (InvocationTargetException e) {
            String msg = "Method sun.security.pkcs11.wrapper.PKCS11C.GetSlotList threw an unknown exception.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }
    }

    private char[] getTokenLabelLocal(long slotID)  {
        final Object tokenInfo;
        try {
            tokenInfo = getTokenInfoMethod.invoke(p11, slotID);
        } catch (IllegalAccessException e) {
            String msg = "Access was denied to method sun.security.pkcs11.wrapper.PKCS11.C_GetTokenInfo, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (IllegalArgumentException e) {
            String msg = "Incorrect parameters sent to sun.security.pkcs11.wrapper.PKCS11.C_GetTokenInfo, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (InvocationTargetException e) {
            String msg = "Method sun.security.pkcs11.wrapper.PKCS11.C_GetTokenInfo threw an unknown exception.";
            log.error(msg, e);
            return null;
        }
        if (tokenInfo == null) {
            return null;
        }
        try {
            String result = String.copyValueOf((char[]) labelField.get(tokenInfo));
            return result.trim().toCharArray();
        } catch (IllegalArgumentException e) {
            String msg = "Field sun.security.pkcs11.wrapper.PKCS11.C_GetTokenInfo was not of type sun.security.pkcs11.wrapper.CK_TOKEN_INFO"
                    + ", this may be due to a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        } catch (IllegalAccessException e) {
            String msg = "Access was denied to field sun.security.pkcs11.wrapper.CK_TOKEN_INFO.label, this may be due to"
                    + " a change in the underlying library.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }
    }
}
