/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.database;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Query;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventTypes;
import org.cesecore.audit.enums.ModuleTypes;
import org.cesecore.audit.enums.ServiceTypes;
import org.cesecore.audit.impl.integrityprotected.AuditRecordData;
import org.cesecore.authorization.cache.AccessTreeUpdateData;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CAFactory;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileData;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.StringTools;
import org.easymock.EasyMock;
import org.ejbca.core.ejb.approval.ApprovalData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for the class DatabaseCliCommand
 *
 * @version $Id$
 *
 */
@SuppressWarnings("deprecation")
public class DatabaseCliCommandTest {

    private static final String PERSISTENCE_UNIT = "foo";

    private DatabaseCliCommandStub command;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Before
    public void setUp() {
        command = new DatabaseCliCommandStub();
    }

    @Test
    public void testExportTableBinary() throws ErrorAdminCommandException, IOException, SecurityException, NoSuchFieldException,
            IllegalArgumentException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        CertificateProfileData certificateProfileData = new CertificateProfileData(0, PERSISTENCE_UNIT, certificateProfile);
        File exportFile = File.createTempFile("tmp", ".bin");
        long lengthBefore = exportFile.length();
        performExport(certificateProfileData, exportFile, PERSISTENCE_UNIT, OutputFormat.BINARY);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);

        //Import the binary object again using the same technique as the Command
        final ObjectInputStream ois = new ObjectInputStream(new FileInputStream(exportFile));
        CertificateProfileData result = (CertificateProfileData) command.getNextBatch(ois).get(0);
        assertEquals(certificateProfileData.getCertificateProfileName(), result.getCertificateProfileName());
    }

    @Test
    public void testExportTableXmlWithCertificateProfile() throws Exception {
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        CertificateProfileData certificateProfileData = new CertificateProfileData(0, PERSISTENCE_UNIT, certificateProfile);
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(certificateProfileData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        //Perform decoding
        List<CertificateProfileData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        CertificateProfileData result = results.get(0);
        assertEquals(certificateProfileData.getCertificateProfileName(), result.getCertificateProfileName());
    }

    @Test
    public void testExportTableXmlWithRoleData() throws Exception {
        AdminGroupData adminGroupData = new AdminGroupData(0, "foo");
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(adminGroupData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<AdminGroupData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        AdminGroupData result = results.get(0);
        assertEquals(adminGroupData, result);
    }

    @Test
    public void testExportTableXmlWithAccessRuleData() throws Exception {
        AccessRuleData accessRuleData = new AccessRuleData("foo", "/foo", AccessRuleState.RULE_ACCEPT, false);
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(accessRuleData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<AccessRuleData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        AccessRuleData result = results.get(0);
        assertEquals(accessRuleData, result);
    }

    @Test
    public void testExportTableXmlWithAccessUserAspectData() throws Exception {
        //Register match value
        Class.forName(X500PrincipalAccessMatchValue.class.getName());
        AccessUserAspectData accessUserAspectData = new AccessUserAspectData("foo", 0, X500PrincipalAccessMatchValue.WITH_COMMONNAME,
                AccessMatchType.TYPE_EQUALCASE, "foo");
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(accessUserAspectData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<AccessUserAspectData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        AccessUserAspectData result = results.get(0);
        assertEquals(accessUserAspectData, result);
    }

    @Test
    public void testExportTableXmlWithAdminPreferencesData() throws Exception {
        AdminPreference adminpreference = new AdminPreference();
        adminpreference.setTheme("bar");
        AdminPreferencesData adminPreferencesData = new AdminPreferencesData("foo", adminpreference);
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(adminPreferencesData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<AdminPreferencesData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        AdminPreferencesData result = results.get(0);
        assertEquals(adminPreferencesData.getAdminPreference().getTheme(), result.getAdminPreference().getTheme());
    }

    @Test
    public void testExportTableXmlWithApprovalData() throws Exception {
        ApprovalData approvalData = new ApprovalData(1337);
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(approvalData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<ApprovalData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        ApprovalData result = results.get(0);
        assertEquals(approvalData.getId(), result.getId());
    }

    @Test
    public void testExportTableXmlWithAuditRecordData() throws Exception {
        AuditRecordData auditRecordData = new AuditRecordData("foo", 0L, 0L, EventTypes.ACCESS_CONTROL, EventStatus.SUCCESS,
                "foo",ServiceTypes.CORE, ModuleTypes.ACCESSCONTROL, "foo", "foo", "foo", null);
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(auditRecordData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<AuditRecordData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        AuditRecordData result = results.get(0);
        assertEquals(auditRecordData.getEventStatusValue(), result.getEventStatusValue());
    }

    @Test
    public void testExportTableXmlWithAccessTreeUpdateData() throws Exception {
        AccessTreeUpdateData accessTreeUpdateData = new AccessTreeUpdateData();
        accessTreeUpdateData.setAccessTreeUpdateNumber(1337);
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(accessTreeUpdateData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<AccessTreeUpdateData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        AccessTreeUpdateData result = results.get(0);
        assertEquals(accessTreeUpdateData.getAccessTreeUpdateNumber(), result.getAccessTreeUpdateNumber());
    }

    @Test
    public void testExportTableXmlWithCaData() throws Exception {
        CAData caData = new CAData("CN=foo", "foo", 0, createTestCA("CN=foo", AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        File exportFile = File.createTempFile("tmp", ".xml");
        long lengthBefore = exportFile.length();
        performExport(caData, exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        long lengthAfter = exportFile.length();
        assertTrue("Nothing was written to exportfile", lengthBefore < lengthAfter);
        List<CAData> results = performImportWithGetNextBatch(exportFile);
        assertEquals("Incorrect result set, should have been one", 1, results.size());
        CAData result = results.get(0);
        assertTrue("Written map has differences to read map.", UpgradeableDataHashMap.diffMaps(caData.getDataMap(), result.getDataMap()).size() == 0);
    }

    @Test
    public void testExportWithMultipleObjects() throws Exception {
        CAData foo = new CAData("CN=foo", "foo", 0, createTestCA("CN=foo", AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        CAData bar = new CAData("CN=bar", "bar", 0, createTestCA("CN=bar", AlgorithmConstants.SIGALG_SHA256_WITH_RSA));
        File exportFile = File.createTempFile("tmp", ".xml");
        performExport(Arrays.asList(foo, bar), exportFile, PERSISTENCE_UNIT, OutputFormat.XML);
        List<CAData> results = performImportWithGetNextBatch(exportFile);
        int foundObjects = 0;
        for (CAData resultItem : results) {
            if (UpgradeableDataHashMap.diffMaps(resultItem.getDataMap(), foo.getDataMap()).size()==0) {
                foundObjects++;
            }
            if (UpgradeableDataHashMap.diffMaps(resultItem.getDataMap(), bar.getDataMap()).size()==0) {
                foundObjects++;
            }
        }
        assertTrue("Not all CAData objects were recovered", foundObjects == 2);
    }

    /**
     * Performs an import using the private method GetNextBatch for XML serialized objects
     * @throws Exception
     */
    @SuppressWarnings("unchecked")
    private <T> List<T> performImportWithGetNextBatch(File exportFile) throws Exception {
        //Use some magick to get at the method.
        Method getNextBatch = DatabaseCliCommand.class.getDeclaredMethod("getNextBatch", ObjectInputStream.class, int.class);
        getNextBatch.setAccessible(true);
        ObjectInputStream objectInputStream = DatabaseCliCommand.createXstream().createObjectInputStream(new FileInputStream(exportFile));
        return (List<T>) getNextBatch.invoke(command, objectInputStream, 10);
    }

    /**
     * Private utility method for creating a CA
     *
     * @param cadn
     * @param sigAlg
     * @return
     * @throws Exception
     */
    private static X509CA createTestCA(final String cadn, final String sigAlg) throws Exception {
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, "foobar123");
        final CryptoToken cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), cryptoTokenProperties, null, 666, "name");
        cryptoToken.generateKeyPair("1024", CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair("1024", CAToken.SOFTPRIVATEDECKEYALIAS);
        // Create CAToken (what key in the CryptoToken should be used for what)
        final Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATEDECKEYALIAS);
        final CAToken catoken = new CAToken(cryptoToken.getId(), caTokenProperties);
        catoken.setSignatureAlgorithm(sigAlg);
        catoken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_RSA);
        catoken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        catoken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        // No extended services
        final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>(0);
        final X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(cadn, "TEST", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, catoken);
        cainfo.setDescription("JUnit RSA CA");
        cainfo.setExtendedCAServiceInfos(extendedcaservices);
        X509CA x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        x509ca.setCAToken(catoken);
        // A CA certificate
        PrivateKey privateKey = cryptoToken.getPrivateKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        PublicKey publicKey = cryptoToken.getPublicKey(catoken.getAliasFromPurpose(CATokenConstants.CAKEYPURPOSE_CERTSIGN));
        X509Certificate cacert = CertTools.genSelfCert(cadn, 10L, "1.1.1.1", privateKey, publicKey, "SHA256WithRSA", true);
        assertNotNull(cacert);
        List<Certificate> cachain = new ArrayList<Certificate>();
        cachain.add(cacert);
        x509ca.setCertificateChain(cachain);
        // Now our CA should be operational
        return x509ca;
    }

    private <T> void performExport(T objectToExport, File exportFile, String persistenceUnit, OutputFormat format) throws FileNotFoundException,
            IOException, SecurityException, IllegalArgumentException, NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        List<T> exportList = new ArrayList<T>();
        exportList.add(objectToExport);
        performExport(exportList, exportFile, persistenceUnit, format);
    }

    /** Utility method that performs an export with mocks and stubs. */
    private <T> void performExport(List<T> entities, File exportFile, String persistenceUnit, OutputFormat format) throws FileNotFoundException,
            IOException, SecurityException, IllegalArgumentException, NoSuchMethodException, IllegalAccessException, InvocationTargetException {
        EntityManagerFactory entityManagerFactoryMock = EasyMock.createMock(EntityManagerFactory.class);
        entityManagerFactoryMock.close();
        EasyMock.replay(entityManagerFactoryMock);

        List<String> primaryKeys = new ArrayList<String>();
        primaryKeys.add("0");

        Query queryMock = EasyMock.createMock(Query.class);
        EasyMock.expect(queryMock.setMaxResults(EasyMock.anyInt())).andReturn(queryMock).anyTimes();
        EasyMock.expect(queryMock.setFirstResult(0)).andReturn(queryMock).anyTimes();
        EasyMock.expect(queryMock.getResultList()).andReturn(primaryKeys);
        EasyMock.expect(queryMock.getResultList()).andReturn(entities);
        EasyMock.expect(queryMock.getResultList()).andReturn(primaryKeys);
        EasyMock.expect(queryMock.setParameter("primaryKey0", "0")).andReturn(queryMock).anyTimes();
        EasyMock.replay(queryMock);

        EntityTransaction entityTransactionMock = EasyMock.createMock(EntityTransaction.class);
        EasyMock.expect(entityTransactionMock.isActive()).andReturn(false).anyTimes();
        EasyMock.replay(entityTransactionMock);

        EntityManager entityManagerMock = EasyMock.createMock(EntityManager.class);
        EasyMock.expect(entityManagerMock.createQuery(EasyMock.anyObject(String.class))).andReturn(queryMock).anyTimes();
        entityManagerMock.clear();
        entityManagerMock.clear();
        entityManagerMock.close();
        EasyMock.expect(entityManagerMock.getTransaction()).andReturn(entityTransactionMock).anyTimes();
        EasyMock.replay(entityManagerMock);
        command.setEntityManager(entityManagerMock, entityManagerFactoryMock, persistenceUnit);
        command.exportTable(CertificateProfileData.class, new String[] { "0" }, 1, exportFile, persistenceUnit, false, format);
        EasyMock.verify(entityTransactionMock, entityManagerMock, queryMock, entityManagerFactoryMock);
    }

}

class DatabaseCliCommandStub extends DatabaseCliCommand {

    private EntityManager entityManager;

    @Override
    public String getSubCommand() {
        return null;
    }

    @Override
    public String getMainCommand() {
        return null;
    }

    @Override
    public String getDescription() {

        return null;
    }

    @Override
    public void execute(String[] args) throws ErrorAdminCommandException {

    }

    @Override
    public <T> void importTable(final Class<T> c, final String[] primaryKeys, final int batchSize, final File exportFile, final String persistenceUnit) {
        super.importTable(c, primaryKeys, batchSize, exportFile, persistenceUnit);
    }

    @Override
    public <T> void exportTable(final Class<T> c, final String[] primaryKeys, final int batchSize, final File exportFile,
            final String persistenceUnit, final boolean verifyIntegrity, final OutputFormat outputFormat) {
        super.exportTable(c, primaryKeys, batchSize, exportFile, persistenceUnit, verifyIntegrity, outputFormat);
    }

    public void setEntityManager(EntityManager entityManager, EntityManagerFactory entityManagerFactory, String persistenceUnit) {
        this.entityManager = entityManager;
        this.entityManagerFactories.put(persistenceUnit, entityManagerFactory);
    }

    @Override
    protected EntityManager getEntityManager(String persistenceUnit) {
        return entityManager;
    }

    @SuppressWarnings("unchecked")
    public <T> List<T> getNextBatch(final ObjectInputStream ois) throws SecurityException, NoSuchMethodException, IllegalArgumentException,
            IllegalAccessException, InvocationTargetException {
        Method getNextBatch = DatabaseCliCommand.class.getDeclaredMethod("getNextBatch", ObjectInputStream.class, int.class);
        getNextBatch.setAccessible(true);
        return (List<T>) getNextBatch.invoke(this, ois, 1);
    }

    @Override
    public String[] getMainCommandAliases() {
        return new String[]{};
    }
}
