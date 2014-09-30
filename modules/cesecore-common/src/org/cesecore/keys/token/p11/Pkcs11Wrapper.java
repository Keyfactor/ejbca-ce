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
package org.cesecore.keys.token.p11;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.log4j.Logger;

/**
 *
 * This class wraps sun.security.pkcs11.wrapper.PKCS11, so that we can access the native PKCS11 calls
 * directly.
 * A slot list and token labels for each slot is cached so that C_GetSlotList() only has to be called once and
 * so that C_GetTokenInfo() only has to be called once for each slot.
 * 
 * The {@link #getInstance(File)} method must be called before any PKCS#11 provider is created.
 *
 *  @version $Id$
 *
 */
public class Pkcs11Wrapper {
    private static final Logger log = Logger.getLogger(Pkcs11Wrapper.class);

    private static volatile Map<String, Pkcs11Wrapper> instances = new HashMap<String, Pkcs11Wrapper>();
    private static final Lock lock = new ReentrantLock();
    private final Method getSlotListMethod;
    private final Method getTokenInfoMethod;
    private final Field labelField;
    private final Object p11;
    private final HashMap<Long, char[]> labelMap;
    private final long slotList[];

    private Pkcs11Wrapper(final String fileName) {
        Class<? extends Object> p11Class;
        try {
            p11Class = Class.forName("sun.security.pkcs11.wrapper.PKCS11");
        } catch (ClassNotFoundException e) {
            String msg = "Class sun.security.pkcs11.wrapper.PKCS11 was not found locally, could not wrap.";
            log.error(msg, e);
            throw new IllegalStateException(msg, e);
        }

        try {
            this.getSlotListMethod = p11Class.getDeclaredMethod("C_GetSlotList", new Class[] { boolean.class });
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
            this.getTokenInfoMethod = p11Class.getDeclaredMethod("C_GetTokenInfo", new Class[] { long.class });
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
            this.labelField = Class.forName("sun.security.pkcs11.wrapper.CK_TOKEN_INFO").getField("label");
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
        Method getInstanceMethod;
        try {
            getInstanceMethod = p11Class.getDeclaredMethod("getInstance",
                    new Class[] { String.class, String.class, Class.forName("sun.security.pkcs11.wrapper.CK_C_INITIALIZE_ARGS"), boolean.class });
        } catch (NoSuchMethodException e) {
            String msg = "Method getInstance was not found in class sun.security.pkcs11.wrapper.PKCS11.CK_C_INITIALIZE_ARGS, this may be due to"
                    + " a change in the underlying library.";
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
        try {
            this.p11 = getInstanceMethod.invoke(null, new Object[] { fileName, "C_GetFunctionList", null, Boolean.FALSE });
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
        this.labelMap = new HashMap<Long, char[]>();
        this.slotList = C_GetSlotList();
        for( long id : this.slotList) {
            this.labelMap.put(Long.valueOf(id), getTokenLabelLocal(id));
        }
    }

    /**
     * Get an instance of the class. 
     * @param the p11 .so file.
     * @return the instance.
     * @throws IllegalArgumentException
     */
    public static Pkcs11Wrapper getInstance(final File file) throws IllegalArgumentException {
        final String canonicalFileName;
        try {
            canonicalFileName = file.getCanonicalPath();
        } catch (IOException e) {
            throw new IllegalArgumentException(file+" is not a valid filename.",e );
        }
        {
            final Pkcs11Wrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// if instance exist we don't have to wait for lock just grab it.
            }
        }
        try {
            lock.lock();// wait for lock; some other tread might be creating the instance right now.
            final Pkcs11Wrapper storedP11 = instances.get(canonicalFileName);
            if (storedP11 != null) {
                return storedP11;// some other thread had already created the instance
            }
            // no other thread has created the instance and no other will since this thread is locking.
            Pkcs11SlotLabel.doC_Initialize(file);// C_Initialize with multithreading args.
            final Pkcs11Wrapper newP11 = new Pkcs11Wrapper(canonicalFileName);
            instances.put(canonicalFileName, newP11);
            return newP11;
        } finally {
            lock.unlock();// now other threads might get the instance.
        }
    }

    /**
     * Get a list of p11 slot IDs to slots that has a token.
     * @return the list.
     */
    public long[] getSlotList() {
        return this.slotList;
    }

    /**
     * Get the token label of a specific slot ID.
     * @param slotID the ID of the slot
     * @return the token label, or null if no matching token was found.
     */
    public char[] getTokenLabel(long slotID) {
        return this.labelMap.get(Long.valueOf(slotID));
    }

    private long[] C_GetSlotList() {
        try {
            return (long[]) this.getSlotListMethod.invoke(this.p11, new Object[] { Boolean.TRUE });
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
            tokenInfo = this.getTokenInfoMethod.invoke(this.p11, new Object[] { Long.valueOf(slotID) });
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
            throw new IllegalStateException(msg, e);
        }
        if (tokenInfo == null) {
            return null;
        }
        try {
            String result = String.copyValueOf((char[]) this.labelField.get(tokenInfo));
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
