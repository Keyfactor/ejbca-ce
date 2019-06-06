/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.certificatetransparency;


import org.bouncycastle.util.encoders.Hex;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @version $Id$
 */
public class SctDataCallbackImpl implements SctDataCallback {

    private final SctDataSessionLocal sctDataSession;

    public SctDataCallbackImpl(SctDataSessionLocal sctDataSession) {
        this.sctDataSession = sctDataSession;
    }

    @Override
    public void saveSctData(String fingerprint, int logId, long certificateExpirationDate, String data) {
        SctData sctData = new SctData(fingerprint, logId, certificateExpirationDate, data);
        sctDataSession.addSctData(sctData);
    }

    @Override
    public Map<Integer, byte[]> findSctData(String fingerprint) {
        List<SctData> sctDataList = sctDataSession.findSctData(fingerprint);
        Map<Integer, byte[]> result = new HashMap<>();
        for(SctData sctData : sctDataList){
            result.put(sctData.getLogId(), Hex.decode(sctData.getData()));
        }
        return result;
    }
}
