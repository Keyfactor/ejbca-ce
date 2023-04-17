package org.ejbca.ui.cli.config;




import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;

import org.apache.cxf.common.util.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.CaTestUtils;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.configuration.GlobalConfigurationSession;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.core.protocol.cmp.CmpTestCase;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

/**
 *This class tests the CLI updatealias command for CMP
 */

public class CmpUpdateCommandTest extends CmpTestCase{
    
    private static final Logger log = Logger.getLogger(CmpUpdateCommandTest.class);
    private  CmpConfiguration cmpConfiguration;
    private final static String ALIAS = "DefaultProfileTestConfAlias";

    private final int caid1;
    private final X509CA ca1;
    
    private final int caid2;
    private final X509CA ca2;
    
    private String key = "defaultca";


    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final GlobalConfigurationSession globalConfigurationSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(GlobalConfigurationSessionRemote.class);

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        
    }
    
    public CmpUpdateCommandTest() throws Exception {
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);

        final int keyusage = X509KeyUsage.digitalSignature + X509KeyUsage.keyCertSign + X509KeyUsage.cRLSign;
        ca1 = CaTestUtils.createTestX509CA("CN=CmpTestCA1", null, false, keyusage);
        caid1 = ca1.getCAId();
        caSession.addCA(ADMIN, ca1);

        ca2 = CaTestUtils.createTestX509CA("CN=CmpTestCA2", null, false, keyusage);
        caid2 = ca2.getCAId();
        caSession.addCA(ADMIN, ca2);
    }

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();

        ArrayList<Integer> availablecas = new ArrayList<Integer>();
        availablecas.add(caid1);
        availablecas.add(caid2);

        cmpConfiguration.addAlias(ALIAS);        
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);

    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();

        cmpConfiguration.removeAlias(ALIAS);
        globalConfigurationSession.saveConfiguration(ADMIN, cmpConfiguration);
        
        CaTestUtils.removeCa(ADMIN, ca1.getCAInfo());
        CaTestUtils.removeCa(ADMIN, ca2.getCAInfo());
    }
    /**
    * Testing CMP updatealias for defaultCA.
    * 
    * Update defaultCA when defaultCA is disabled
    */
    @Test
    public void test01CmpUpdateDefaultCaIfDefaultCaDisabledInAlias() throws Exception {
        log.trace(">test01CmpUpdateDefaultCaWithCaDisabledInAlias()");
        assertTrue("DefaultCa in Alias is disabled",cmpConfiguration.getCMPDefaultCA(ALIAS).equals("") );
        final String[] updateDefaultCaArgs = new String[]{ ALIAS, key, "CmpTestCA1" };
        new org.ejbca.ui.cli.config.cmp.UpdateCommand().execute(updateDefaultCaArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertTrue("Disabled defaultCa is updated to Ca1", cmpConfiguration.getCMPDefaultCA(ALIAS).equals(ca1.getSubjectDN()) );
        assertEquals("DefaultCA is updated to CA1", cmpConfiguration.getCMPDefaultCA(ALIAS), ca1.getSubjectDN());
        log.trace(">test01CmpUpdateDefaultCaWithCaDisabledInAlias()");
    } 
    /**
    * Update defaultCA when there is an existing CA set. DefaultCA is updated
    * using the CA name.
    */
    @Test
    public void test02CmpUpdateDefaultCaWithAnotherCa() throws Exception {
        log.trace(">test02CmpUpdateDefaultCaWithAnotherCa()");
        cmpConfiguration.setCMPDefaultCA(ALIAS, ca1.getSubjectDN());
        final String ca2Name = "CmpTestCA2";
        final String[] updateDefaultCaArgs = new String[]{ ALIAS, key, ca2Name };
        new org.ejbca.ui.cli.config.cmp.UpdateCommand().execute(updateDefaultCaArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertTrue("Alias is updated from CA1 to CA", cmpConfiguration.getCMPDefaultCA(ALIAS).equals(ca2.getSubjectDN()));
        assertEquals("Alias is updated from Ca1 to Ca2",cmpConfiguration.getCMPDefaultCA(ALIAS), ca2.getSubjectDN());
        log.trace("<test02CmpUpdateDefaultCaWithAnotherCa()");
    }
    /**
    * Update defaultCA when there is an existing CA set. DefaultCA is updated using 
    * the SubjectDN.
    */
    @Test
    public void test03CmpUpdateDefaultCaWithAnotherCaUsingCN() throws Exception {
        log.trace(">test02CmpUpdateDefaultCaWithAnotherCa()");
        cmpConfiguration.setCMPDefaultCA(ALIAS, ca1.getSubjectDN());
        assertTrue ("DefaultCa in Alias is Ca1", cmpConfiguration.getCMPDefaultCA(ALIAS).equals(ca1.getSubjectDN()));
        final String[] updateDefaultCaArgs = new String[]{ ALIAS, key, "CN=CmpTestCA2"};
        new org.ejbca.ui.cli.config.cmp.UpdateCommand().execute(updateDefaultCaArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertTrue("Alias is updated with another Ca using CN",cmpConfiguration.getCMPDefaultCA(ALIAS).equals(ca2.getSubjectDN()));
        assertEquals("Alias is updated with another Ca using CN",cmpConfiguration.getCMPDefaultCA(ALIAS), "CN=CmpTestCA2");
        log.trace("<test03CmpUpdateDefaultCaWithAnotherCaUsingCN()");
    }
    /**
    * Updating defaultCA when there is an existing CA using an non-existing CA.
    * Result should be false.
    */
    @Test
    public void test04CmpUpdateDefaultCaWithNonExistingCa() throws Exception {
        log.trace(">test04CmpUpdateDefaultCaWithNonExistingCa()");
        cmpConfiguration.setCMPDefaultCA(ALIAS, ca1.getSubjectDN());
        assertTrue("DefaultCa in Alias is Ca1", cmpConfiguration.getCMPDefaultCA(ALIAS).equals(ca1.getSubjectDN()));
        final String[] updateDefaultCaArgs = new String[]{ ALIAS, key, "CN=NonExistingCa"};
        new org.ejbca.ui.cli.config.cmp.UpdateCommand().execute(updateDefaultCaArgs);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertFalse("Alias is not updated with new CA",cmpConfiguration.getCMPDefaultCA(ALIAS).equals("CN=NonExistingCa"));
        assertEquals("Alias is not updated with new CA",cmpConfiguration.getCMPDefaultCA(ALIAS), "");
        log.trace("<test04CmpUpdateDefaultCaWithNonExistingCa()");
    }

    /**
     * Checks that running the update command for vendor CAs actually performs the update in the configuration.
     * Note that checks on the validity of the values are not performed, could be any String.
     */
    @Test
    public void test05CmpUpdateVendorCaIdsCommand() throws Exception {
        log.trace(">test05CmpUpdateVendorCaIdsCommand()");
        assertTrue("Vendor CA ID list is initially epty", StringUtils.isEmpty(cmpConfiguration.getVendorCaIds(ALIAS)));
        final String[] updateVendorCaCommand = new String[]{ ALIAS, "vendorcaids", "1;100"};
        new org.ejbca.ui.cli.config.cmp.UpdateCommand().execute(updateVendorCaCommand);
        cmpConfiguration = (CmpConfiguration) globalConfigurationSession.getCachedConfiguration(CmpConfiguration.CMP_CONFIGURATION_ID);
        assertEquals("Vendor CAs in CmpConfiguration should now have the updated value from the command",
                "1;100", cmpConfiguration.getVendorCaIds(ALIAS));
        log.trace("<test05CmpUpdateVendorCaIdsCommand()");
    }
}
