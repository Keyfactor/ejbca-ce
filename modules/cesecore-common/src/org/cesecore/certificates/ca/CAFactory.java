package org.cesecore.certificates.ca;

import java.lang.reflect.InvocationTargetException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import org.apache.log4j.Logger;


/**
 * Constructs instances of CA implementations. Depending on which implementations are available
 * in the current build, the appropriate implementation of the CA interface is returned. 
 * @version $Id$
 *
 */
public enum CAFactory {
    INSTANCE;
    
    private static final String CA_TYPE_X509 = "X509CA";
    private static final String CA_TYPE_X509_EXT = "X509CA_EXTERNAL";
    private static final String CA_TYPE_CVC_EAC = "CVC_EAC";

    private static final Logger log = Logger.getLogger(CAFactory.class);
    
    private Map<String, CACommon> caImplMap = new HashMap<>();
    
    private CAFactory() {
        try {
            ServiceLoader<CACommon> cALoader = ServiceLoader.load(CACommon.class);
            for (CACommon ca : cALoader) {
                caImplMap.put(ca.getCaImplType(), ca);
            }
            if (caImplMap.isEmpty()) {
                Logger.getLogger(CAFactory.class).error("No CA implementations found by ServieLoader");
            } 
        } catch (Exception e) {
            Logger.getLogger(CAFactory.class).error("Could not construct CA implementations", e);
            throw e;
        }
    }
    
    public CACommon getX509CAImpl(final X509CAInfo caInfo)  {
        if (caImplMap.containsKey(CA_TYPE_X509)) {
            return createCaByImpl(CA_TYPE_X509, X509CAInfo.class, caInfo);
        } else if (caImplMap.containsKey(CA_TYPE_X509_EXT)) {
            return createCaByImpl(CA_TYPE_X509_EXT, X509CAInfo.class, caInfo);
        }
        log.error("X509CA implementation not found");
        return null;
    }
    
    public CACommon getX509CAImpl(final HashMap<Object, Object> data, final int caId, final String subjectDn, final String name, final int status,
            final Date updateTime, final Date expireTime)  {
        if (caImplMap.containsKey(CA_TYPE_X509)) {
            return createCaByImpl(CA_TYPE_X509, data, caId, subjectDn, name, status, updateTime, expireTime);
        } else if (caImplMap.containsKey(CA_TYPE_X509_EXT)) {
            return createCaByImpl(CA_TYPE_X509_EXT, data, caId, subjectDn, name, status, updateTime, expireTime);
        }
        log.error("X509CA implementation not found");
        return null;
    }
    
    
    public CACommon getCvcCaImpl(final HashMap<Object, Object> data, final int caId, final String subjectDn, final String name, final int status,
            final Date updateTime, final Date expireTime) {
        if (caImplMap.containsKey(CA_TYPE_CVC_EAC)) {
            return CvcCABase.getInstance(data, caId, subjectDn, name, status, updateTime, expireTime);
        }
        log.error("CVC CA implementation not found");
        return null;
    }
    
    public CACommon getCvcCaImpl(CVCCAInfo cvccainfo) {
        if (caImplMap.containsKey(CA_TYPE_CVC_EAC)) {
            return CvcCABase.getInstance(cvccainfo);
        }
        log.error("CVC CA implementation not found");
        return null;
    }
    
    private <T extends CAInfo> CACommon createCaByImpl(final String impl, final Class<T> caClass, final T caInfo)  {
        try {
            return caImplMap.get(impl).getClass().getConstructor(caClass).newInstance(caInfo);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }
    
    private CACommon createCaByImpl(final String impl, final HashMap<Object, Object> data, final int caId, final String subjectDn, final String name, final int status,
            final Date updateTime, final Date expireTime)  {
        try {
            return caImplMap.get(impl).getClass().getConstructor(HashMap.class, Integer.TYPE, String.class, String.class, Integer.TYPE,
                    Date.class, Date.class).newInstance(data, caId, subjectDn, name, status, updateTime, expireTime);
        } catch (NoSuchMethodException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | SecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
