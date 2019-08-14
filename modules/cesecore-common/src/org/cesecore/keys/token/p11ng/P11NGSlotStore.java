/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11ng;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.apache.commons.lang.ArrayUtils;
import org.pkcs11.jacknji11.CKA;

/**
 * Holder for parameters to result mapping of HSM calls with respect to a slot for P11NG provider.
 * 
 * @version $Id$
 */
public class P11NGSlotStore {
    private final Map<FindObjectsCallParamsHolder, long[]> findObjectsCallParams2ResultMap = new HashMap<>();
    private final Map<GetAttributeValueCallParamsHolder, CKA> getAttributeValueCallParams2ResultMap = new HashMap<>();

    public synchronized boolean objectsExists(FindObjectsCallParamsHolder key) {
        return findObjectsCallParams2ResultMap.containsKey(key);
    }

    public synchronized boolean attributeValueExists(GetAttributeValueCallParamsHolder key) {
        return getAttributeValueCallParams2ResultMap.containsKey(key);
    }

    public synchronized long[] getObjects(FindObjectsCallParamsHolder key) {
        return findObjectsCallParams2ResultMap.get(key);
    }
    
    public synchronized CKA getAttributeValue(GetAttributeValueCallParamsHolder key) {
        return getAttributeValueCallParams2ResultMap.get(key);
    }

    public synchronized void addObjectsSearchResult(FindObjectsCallParamsHolder key, long[] objectRefs) {
        findObjectsCallParams2ResultMap.put(key, objectRefs);
    }

    public synchronized void addAttributeValueSearchResult(GetAttributeValueCallParamsHolder key, CKA attributeValue) {
        getAttributeValueCallParams2ResultMap.put(key, attributeValue);
    }

    public synchronized void removeAllEntriesByObject(long object) {
        removeObjectsSearchResultByObject(object);
        removeAttributeValueSearchResultByObject(object);
    }
    
    public synchronized void removeObjectsSearchResultByObject(long object) {
        Iterator<Map.Entry<FindObjectsCallParamsHolder, long[]>> itr = findObjectsCallParams2ResultMap.entrySet().iterator();
        while (itr.hasNext()) {
            Map.Entry<FindObjectsCallParamsHolder, long[]> entry = itr.next();
            Long[] objectsBoxed = ArrayUtils.toObject(entry.getValue());
            if (Arrays.asList(objectsBoxed).contains(object)) {
                itr.remove();
            }
        }
    }

    private void removeAttributeValueSearchResultByObject(long object) {
        Iterator<Map.Entry<GetAttributeValueCallParamsHolder, CKA>> itr = getAttributeValueCallParams2ResultMap.entrySet().iterator();
        while (itr.hasNext()) {
            Map.Entry<GetAttributeValueCallParamsHolder, CKA> entry = itr.next();
            GetAttributeValueCallParamsHolder key = entry.getKey();
            if (key.getObject() == object) {
                itr.remove();
            }
        }
    }
    
    public synchronized void removeObjectsSearchResultByLabel(String label) {
        Iterator<Map.Entry<FindObjectsCallParamsHolder, long[]>> itr = findObjectsCallParams2ResultMap.entrySet().iterator();
        while (itr.hasNext()) {
            Map.Entry<FindObjectsCallParamsHolder, long[]> entry = itr.next();
            FindObjectsCallParamsHolder key = entry.getKey();
            if (key.getCkaLabel() != null && key.getCkaLabel().equals(label)) {
                itr.remove();
            }
        }
    }

}
