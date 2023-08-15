package org.ejbca;

import org.apache.log4j.Logger;
import org.junit.Test;

public class ServerLogCheckUtilTest {
    
    private static final Logger log = Logger.getLogger(ServerLogCheckUtilTest.class);
    private static final String LOG_SNIPPET = 
              "[0m[0m08:36:12,174 INFO  [org.jboss.as.ejb3] (MSC service thread 1-5) WFLYEJB0493: Jakarta Enterprise Beans subsystem suspension complete\n"
            + "[0m[0m08:36:12,211 INFO  [org.jboss.as.patching] (MSC service thread 1-1) WFLYPAT0050: WildFly Full cumulative patch ID is: base, one-off patches include: none\n"
            + "[0m[0m08:39:13,947 ERROR  [org.cesecore.certificates.crl.CrlStoreSessionBean] (default task-2) [getLastCRL] [312] Retrieved CRL from issuer 'CN=CaRestResourceSystemTest11619651981-440507607', with CRL number 1.\n"
            + "[0m[0m08:39:14,070 WARN  [org.cesecore.certificates.crl.CrlStoreSessionBean] (default task-2) [getLastCRL] [322] Error retrieving CRL for issuer 'CN=CaRestResourceSystemTest11619651981-440507607' with CRL number 0.\n"
            + "[0m[0m08:39:14,137 DEBUG  [org.ejbca.core.ejb.crl.ImportCrlSessionBean] (default task-2) [verifyCrlIssuer] [173] CA: CN=CaRestResourceSystemTest11619651981-440507607\n"
            + "[0m[0m08:39:14,141 INFO  [org.cesecore.certificates.crl.CrlStoreSessionBean] (default task-2) [getLastCRL] [322] Error retrieving CRL for issuer 'CN=CaRestResourceSystemTest11619651981-440507607' with CRL number 0. CRL partition: 2\n"
            + "";
    
    @Test
    public void test() {
        for (String line: LOG_SNIPPET.split("\n")) {
            log.error(ServerLogCheckUtil.parseServerLogRecord(line));
        }
    }
    
    @Test
    public void testConfigLoad() {
        log.error("configs: " + ServerLogCheckUtil.whiteListedClasses);
        log.error("configs: " + ServerLogCheckUtil.whiteListedMethods);
        log.error("configs: " + ServerLogCheckUtil.whiteListedPackages);
    }

}
