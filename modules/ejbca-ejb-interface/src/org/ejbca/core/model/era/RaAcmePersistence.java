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

package org.ejbca.core.model.era;

import org.apache.log4j.Logger;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 
 * @version $Id$
 *
 */

public class RaAcmePersistence {

    private static final ConcurrentHashMap nonceObjs = new ConcurrentHashMap();
    private static final ConcurrentHashMap authObjs = new ConcurrentHashMap();
    private static final ConcurrentHashMap regObjs = new ConcurrentHashMap();
    private static final ConcurrentHashMap certObjs = new ConcurrentHashMap();

    public static final String authObjName = "AuthObject";
    public static final String regObjName = "RegistrationObject";
    public static final String certObjName = "certificate";

    private static final Logger classlog = Logger.getLogger(RaAcmePersistence.class);

    /**
     * Sets ACME certification object on the the persistance layer
     * @param uuid
     * @param certObj
     * @return
     */

    //Certificate functionality
    public static Map setCertObj(String uuid, Map certObj) {
        try {
            HashMap obj = new HashMap();

            //Adding field and context info
            obj.put("uuid", uuid);
            obj.put(certObjName, certObj);
            obj.put("date", new Date());

            return obj;
        } catch (NullPointerException npe) {
            classlog.error("setCertObj :: Unable to insert the Certification object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("setCertObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    /**
     * Gets ACME certification object on the persistance layer
     * @param uuid
     * @return
     */
    public static Map getCertObj(String uuid) {
        try {
            HashMap result = (HashMap) certObjs.get(uuid);

            //Fields
            HashMap authObj = (HashMap) result.get(certObjName);

            return authObj;
        } catch (NullPointerException npe) {
            classlog.error("getCertObj :: Unable to retrieve the Certification object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("getCertObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    /**
     * Checks that the certification object is in the persistence layer
     * @param uuid
     * @return
     */
    public static boolean isCertObj(String uuid) {
        return !getCertObj(uuid).isEmpty();
    }

    /**
     * Sets ACME authorization object on the the persistance layer
     * @param uuid
     * @param authObj
     * @return
     */

    //Authorization functionality
    public static Map setAuthObj(String uuid, Map authObj) {
        try {
            HashMap obj = new HashMap();

            //Adding field and context info
            obj.put("uuid", uuid);
            obj.put(authObjName, authObj);
            obj.put("date", new Date());

            HashMap authObjsReturn = (HashMap) authObjs.put(uuid, obj);
            authObjsReturn = (HashMap) authObjs.get(uuid);

            return (authObjsReturn == null) ? new Hashtable() : authObjsReturn;
        } catch (NullPointerException npe) {
            classlog.error("setAuthObj :: Unable to insert the authorization object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("setAuthObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    /**
     * Gets ACME authorization object on the persistance layer
     * @param uuid
     * @return
     */
    public static Map getAuthObj(String uuid) {
        classlog.info(">>>>>>>>>>>>>>>>>>>>>>>>>RaAcmePersistence::getAuthObj::uuid[" + uuid + "]");
        Enumeration keys = authObjs.keys();
        while (keys.hasMoreElements())
            classlog.info(">>>>>>>>>>>>>>>>>>>>>>>>>RaAcmePersistence::getAuthObj:::keys:[" + keys.nextElement() + "]");
        classlog.info(">>>>>>>>>>>>>>>>>>>>>>>>>RaAcmePersistence::getAuthObj::authObjs:keys:elem(" + authObjs.size() + ")");

        try {
            HashMap data = (HashMap) authObjs.get(uuid);
            HashMap result = (HashMap) data.get(authObjName);

            return (result == null) ? new HashMap() : result;
        } catch (NullPointerException npe) {
            classlog.error("getAuthObj :: Unable to retrieve the authorization object(s):" + npe.getMessage());
            npe.getStackTrace();
        } catch (Exception ex) {
            classlog.error("getAuthObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    /**
     * Checks that the authorization object is in the persistence layer
     * @param uuid
     * @return
     */
    public static Map isAuthObj(String uuid) {
        return getAuthObj(uuid);
    }

    public static Map remAuthObj(String uuid) {
        try {
            //HashMap authObj = (HashMap) authObjs.get(uuid);
            HashMap authObjRem = (HashMap) authObjs.remove(uuid);

            return (authObjRem == null) ? new Hashtable() : authObjRem;
        } catch (NullPointerException npe) {
            classlog.error("isAuthObj :: Unable to remove:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("isAuthObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    //Registration functionality
    /**
     * Sets ACME registration object on the the persistance layer
     * @param uuid
     * @param regObj
     * @return
     */
    public static Map setRegObj(String uuid, Map regObj) {
        try {
            HashMap obj = new HashMap();

            //Adding field and context info
            obj.put("uuid", uuid);
            obj.put(regObjName, regObj);
            obj.put("date", new Date());

            HashMap regObjsReturn = (HashMap) regObjs.put(uuid, obj);
            regObjsReturn = (HashMap) regObjs.get(uuid);

            return (regObjsReturn == null) ? new Hashtable() : regObjsReturn;

        } catch (NullPointerException npe) {
            classlog.error("setRegObj :: Unable to insert the registration object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("setRegObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    /**
     * Gets ACME authorization object on the persistance layer
     * @param uuid
     * @return
     */
    public static Map getRegObj(String uuid) {
        classlog.info(">>>>>>>>>>>>>>>>>>>>>>>>>RaAcmePersistence::getRegObj::uuid[" + uuid + "]");
        Enumeration keys = regObjs.keys();
        while (keys.hasMoreElements())
            classlog.info(">>>>>>>>>>>>>>>>>>>>>>>>>RaAcmePersistence::getRegObj:::keys:[" + keys.nextElement() + "]");
        classlog.info(">>>>>>>>>>>>>>>>>>>>>>>>>RaAcmePersistence::getRegObj::regObjs:keys:elem(" + regObjs.size() + ")");
        try {
            HashMap data = (HashMap) regObjs.get(uuid);
            HashMap result = (HashMap) data.get(regObjName);

            return (result == null) ? new HashMap() : result;
        } catch (NullPointerException npe) {
            classlog.error("getRegObj :: Unable to retrieve the registration object(s):" + npe.getMessage());
            npe.printStackTrace();
        } catch (Exception ex) {
            classlog.error("getRegObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    /**
     * Checks that the registration object is in the persistance layer
     * @param uuid
     * @return
     */
    public static Map isRegObj(String uuid) {
        return getRegObj(uuid);
    }

    public static Map remRegObj(String uuid) {
        try {

            //HashMap regObj = (HashMap) regObjs.get(uuid);
            HashMap regObjRem = (HashMap) regObjs.remove(uuid);

            return (regObjRem == null) ? new Hashtable() : regObjRem;
        } catch (NullPointerException npe) {
            classlog.error("remRegObj :: Unable to remove:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("remRegObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    //Nonce functionality
    /**
     * Sets ACME Nonce on the the persistance layer
     * @param uuid
     * @return if the insertion failed returns an empty JSONObject, if not returns a JSONObject with an entry
     * \<uuid,empty JSONObject\>
     */
    private static Map setNonceObj(String uuid) {
        try {
            HashMap obj = new HashMap();
            obj.put(uuid, new HashMap());

            HashMap result = (HashMap) nonceObjs.put(uuid, new HashMap());

            return result == null ? new HashMap() : obj;
        } catch (NullPointerException npe) {
            classlog.error("setNonceObj :: Unable to insert the registration object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("setNonceObj :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }

    /**
     * Gets ACME Nonce on the persistance layer and dequeues on request
     * @return returns an empty Map if empty
     */
    public static Map<String, String> getNonce() {
        try {
            HashMap<String, String> result = new HashMap<>();
            result.put("nonce", java.util.UUID.randomUUID().toString());
            return result;
        } catch (NullPointerException npe) {
            classlog.error("getNonce :: Unable to retrieve the registration object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("getNonce :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap<String, String>();
    }

    /**
     * Checks that the Nonce is in the persistance layer
     * @param uuid
     * @return
     */
    public static Map<String, String> isNonce(String uuid) {
        try {
            if (nonceObjs.containsKey(uuid)) {
                HashMap<String, String> result = new HashMap<String, String>();
                result.put("nonce", uuid);

                remNonce(uuid);

                return result;
            } else {
                classlog.error("getNonce :: Unable to find requested nonce");
            }
        } catch (NullPointerException npe) {
            classlog.error("getNonce :: Unable to retrieve the registration object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("getNonce :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap<String, String>();
    }

    private static Map remNonce(String uuid) {
        try {
            HashMap result = (HashMap) nonceObjs.remove(uuid);
            if (result == null) {
                classlog.error("remNonce :: Unable to retrieve or delete nonce object");
            }
            return result;
        } catch (NullPointerException npe) {
            classlog.error("remNonce :: Unable to retrieve or delete nonce object:" + npe.getMessage());
        } catch (Exception ex) {
            classlog.error("remNonce :: Unexpected Internal error:" + ex.getMessage());
            ex.printStackTrace();
        }
        return new HashMap();
    }
}
