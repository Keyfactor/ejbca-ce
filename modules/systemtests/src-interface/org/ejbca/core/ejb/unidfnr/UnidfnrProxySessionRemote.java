package org.ejbca.core.ejb.unidfnr;

import javax.ejb.Remote;

@Remote
public interface UnidfnrProxySessionRemote {
    
    void removeUnidFnrDataIfPresent(final String unid);

    void stroreUnidFnrData(final String unid, final String fnr);
    
}
