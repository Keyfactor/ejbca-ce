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

package org.ejbca.database;

import static org.junit.Assert.assertTrue;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.LinkedHashMap;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.persistence.EntityTransaction;
import javax.persistence.Persistence;

import org.apache.log4j.Logger;
import org.bouncycastle.util.Arrays;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificateprofile.CertificateProfileData;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.configuration.GlobalConfigurationData;
import org.cesecore.keybind.InternalKeyBindingData;
import org.cesecore.keys.token.CryptoTokenData;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.member.RoleMemberData;
import org.ejbca.core.ejb.approval.ApprovalData;
import org.ejbca.core.ejb.ca.publisher.PublisherData;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueData;
import org.ejbca.core.ejb.ca.store.CertReqHistoryData;
import org.ejbca.core.ejb.hardtoken.HardTokenCertificateMap;
import org.ejbca.core.ejb.hardtoken.HardTokenData;
import org.ejbca.core.ejb.hardtoken.HardTokenIssuerData;
import org.ejbca.core.ejb.hardtoken.HardTokenProfileData;
import org.ejbca.core.ejb.hardtoken.HardTokenPropertyData;
import org.ejbca.core.ejb.hardtoken.HardTokenPropertyDataPK;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryData;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryDataPK;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceData;
import org.ejbca.core.ejb.services.ServiceData;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/**
 * Simple class to trigger Hibernate's JPA schema validation.
 * 
 * run with "ant test:dbschema"
 * 
 * We also validate that all fields can hold the values that we assume they can.
 * 
 * Must have 'max_allowed_packet' size set to a large value, >2MB
 * 
 * @version $Id$
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class DatabaseSchemaTest {

    private static final Logger LOG = Logger.getLogger(DatabaseSchemaTest.class);

    private static String VARCHAR_80B;
    private static String VARCHAR_250B;
    private static String VARCHAR_400B;
    private static String VARCHAR_2000B;
    private static String CLOB_10KiB;
    private static String CLOB_100KiB;
    private static String CLOB_1MiB;
    private static final LinkedHashMap<String, byte[]> HASHMAP_200K = new LinkedHashMap<String, byte[]>();
    private static final LinkedHashMap<String, byte[]> HASHMAP_1M = new LinkedHashMap<String, byte[]>();
    private static final int BOGUS_INT = -32; // Very random..
    private static final Integer BOGUS_INTEGER = Integer.valueOf(BOGUS_INT);
    private static EntityManagerFactory entityManagerFactory;
    private EntityManager entityManager;

    @BeforeClass
    public static void beforeClass() throws Exception {
        LOG.trace(">setup");
        if (entityManagerFactory == null) {
            entityManagerFactory = Persistence.createEntityManagerFactory("ejbca-pu");
        }
        LOG.trace("<setup");
    }

    @Before
    public void before() {
        entityManager = entityManagerFactory.createEntityManager();
    }

    @After
    public void tearDown() throws Exception {
        LOG.trace(">tearDown");
        entityManager.close();
        LOG.trace("<tearDown");
    }

    @AfterClass
    public static void afterClass() throws Exception {
        if (entityManagerFactory != null) {
            if (entityManagerFactory.isOpen()) {
                entityManagerFactory.close();
            }
        }
        logMemStats();
    }

    @Test
    public void test000Setup() throws Exception {
        LOG.trace(">test000Setup");
        logMemStats();
        LOG.debug("Allocating memory..");
        VARCHAR_80B = getClob(80);
        VARCHAR_250B = getClob(250);
        VARCHAR_400B = getClob(400);
        VARCHAR_2000B = getClob(2000);
        CLOB_10KiB = getClob(10 * 1024);
        CLOB_100KiB = getClob(100 * 1024);
        CLOB_1MiB = getClob(1024 * 1024);
        LOG.debug("VARCHAR_80B   is      " + VARCHAR_80B.length() + " chars and     " + VARCHAR_80B.getBytes().length + " bytes.");
        LOG.debug("VARCHAR_250B  is     " + VARCHAR_250B.length() + " chars and     " + VARCHAR_250B.getBytes().length + " bytes.");
        LOG.debug("VARCHAR_400B  is     " + VARCHAR_400B.length() + " chars and     " + VARCHAR_400B.getBytes().length + " bytes.");
        LOG.debug("VARCHAR_2000B is    " + VARCHAR_2000B.length() + " chars and    " + VARCHAR_2000B.getBytes().length + " bytes.");
        LOG.debug("CLOB_10KiB    is   " + CLOB_10KiB.length()     + " chars and   " + CLOB_10KiB.getBytes().length + " bytes.");
        LOG.debug("CLOB_100KiB   is  " + CLOB_100KiB.length()     + " chars and  " + CLOB_100KiB.getBytes().length + " bytes.");
        LOG.debug("CLOB_1MiB     is " + CLOB_1MiB.length()        + " chars and " + CLOB_1MiB.getBytes().length + " bytes.");
        LOG.debug("Filling HashMaps..");
        HASHMAP_200K.put("object", getLob(196 * 1024)); // It need to be less than 200KiB in Serialized format..
        HASHMAP_1M.put("object", getLob(996 * 1024)); // It need to be less than 1MiB in Serialized format.. 
        logMemStats();
        LOG.trace("<test000Setup");
    }

    private byte[] getLob(int size) {
        byte[] ret = new byte[size];
        Arrays.fill(ret, (byte) '0');
        return ret;
    }

    private String getClob(int size) {
        return new String(getLob(size));
    }

    @Test
    public void testApprovalData() {
        LOG.trace(">testApprovalData");
        logMemStats();
        ApprovalData entity = new ApprovalData();
        entity.setApprovalid(0);
        entity.setApprovaldata(CLOB_1MiB);
        entity.setApprovaltype(0);
        entity.setCaid(0);
        entity.setEndentityprofileid(0);
        entity.setExpiredate(0);
        entity.setId(Integer.valueOf(0));
        entity.setRemainingapprovals(0);
        entity.setReqadmincertissuerdn(VARCHAR_250B);
        entity.setReqadmincertsn(VARCHAR_250B);
        entity.setRequestdata(CLOB_1MiB);
        entity.setRequestdate(0);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setStatus(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testApprovalData");
    }

    @Test
    public void testAccessRulesData() {
        LOG.trace(">testAccessRulesData");
        logMemStats();
        AccessRuleData entity = new AccessRuleData(BOGUS_INTEGER.intValue(), VARCHAR_250B, AccessRuleState.RULE_ACCEPT, false);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testAccessRulesData");
    }

    @Test
    public void testAdminEntityData() {
        LOG.trace(">testAdminEntityData");
        logMemStats();
        AccessUserAspectData entity = new AccessUserAspectData(VARCHAR_250B, BOGUS_INTEGER, X500PrincipalAccessMatchValue.WITH_SERIALNUMBER,
                AccessMatchType.TYPE_EQUALCASEINS, VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testAdminEntityData");
    }
    
    @Test
    public void testRoleMemberData() {
        LOG.trace(">testAdminEntityData");
        logMemStats();
        RoleMemberData entity = new RoleMemberData(BOGUS_INT, VARCHAR_250B, BOGUS_INT, BOGUS_INT, BOGUS_INT, VARCHAR_2000B, BOGUS_INT, null, null);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testAdminEntityData");
    }

    @Test
    public void testAdminGroupData() {
        LOG.trace(">testRoleData");
        logMemStats();
        AdminGroupData entity = new AdminGroupData(BOGUS_INTEGER, VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testRoleData");
    }

    @Test
    public void testRoleData() {
        LOG.trace(">testRoleData");
        logMemStats();
        RoleData entity = new RoleData();
        entity.setId(123);
        entity.setNameSpaceNeverNull(VARCHAR_250B);
        entity.setRoleName(VARCHAR_250B);
        entity.setRawData(CLOB_1MiB);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testRoleData");
    }

    @Test
    public void testCAData() {
        LOG.trace(">testCAData");
        logMemStats();
        CAData entity = new CAData();
        entity.setCaId(BOGUS_INTEGER);
        entity.setData(CLOB_100KiB);
        entity.setExpireTime(0);
        entity.setName(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setStatus(0);
        entity.setSubjectDN(VARCHAR_250B);
        entity.setUpdateTime(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testCAData");
    }

    @Test
    public void testCertificateProfileData() {
        LOG.trace(">testCertificateProfileData");
        logMemStats();
        CertificateProfileData entity = new CertificateProfileData();
        entity.setCertificateProfileName(VARCHAR_250B);
        entity.setDataUnsafe(HASHMAP_1M);
        entity.setId(BOGUS_INTEGER);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testCertificateProfileData");
    }

    @Test
    public void testPublisherData() {
        LOG.trace(">testPublisherData");
        logMemStats();
        PublisherData entity = new PublisherData();
        entity.setData(CLOB_100KiB);
        entity.setId(BOGUS_INTEGER);
        entity.setName(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setUpdateCounter(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testPublisherData");
    }

    @Test
    public void testPublisherQueueData() {
        LOG.trace(">testPublisherQueueData");
        logMemStats();
        PublisherQueueData entity = new PublisherQueueData();
        entity.setFingerprint(VARCHAR_250B);
        entity.setLastUpdate(0);
        entity.setPk(VARCHAR_250B);
        entity.setPublisherId(0);
        entity.setPublishStatus(0);
        entity.setPublishType(0);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setTimeCreated(0);
        entity.setTryCounter(0);
        entity.setVolatileData(CLOB_100KiB);
        storeAndRemoveEntity(entity);
        LOG.trace("<testPublisherQueueData");
    }

    @Test
    public void testCertificateData() {
        LOG.trace(">testCertificateData");
        logMemStats();
        CertificateData entity = new CertificateData();
        entity.setBase64Cert(CLOB_1MiB);
        entity.setCaFingerprint(VARCHAR_250B);
        entity.setCertificateProfileId(BOGUS_INTEGER);
        entity.setExpireDate(0L);
        entity.setFingerprint(VARCHAR_250B);
        entity.setIssuerDN(VARCHAR_250B);
        //setPrivateField(entity, "issuerDN", VARCHAR_250B);
        entity.setRevocationDate(0L);
        entity.setRevocationReason(0);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setSerialNumber(VARCHAR_250B);
        entity.setStatus(0);
        entity.setSubjectDN(VARCHAR_400B);
        entity.setSubjectAltName(VARCHAR_2000B);
        entity.setSubjectKeyId(VARCHAR_250B);
        entity.setTag(VARCHAR_250B);
        entity.setType(0);
        entity.setUpdateTime(Long.valueOf(0L));
        entity.setUsername(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testCertificateData");
    }

    @Test
    public void testCertReqHistoryData() {
        LOG.trace(">testCertReqHistoryData");
        logMemStats();
        CertReqHistoryData entity = new CertReqHistoryData();
        entity.setIssuerDN(VARCHAR_250B);
        entity.setFingerprint(VARCHAR_250B);
        //setPrivateField(entity, "issuerDN", VARCHAR_250B);
        //setPrivateField(entity, "fingerprint", VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setSerialNumber(VARCHAR_250B);
        //setPrivateField(entity, "serialNumber", VARCHAR_250B);
        entity.setTimestamp(0L);
        entity.setUserDataVO(CLOB_1MiB);
        entity.setUsername(VARCHAR_250B);
        //setPrivateField(entity, "username", VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testCertReqHistoryData");
    }

    @Test
    public void testCryptoTokenData() {
        LOG.trace(">testCryptoTokenData");
        logMemStats();
        CryptoTokenData entity = new CryptoTokenData();
        entity.setId(BOGUS_INT);
        entity.setLastUpdate(0L);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setTokenData(CLOB_1MiB);
        entity.setTokenName(VARCHAR_250B);
        entity.setTokenProps(CLOB_10KiB);
        entity.setTokenType(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testCryptoTokenData");
    }

    // ZZ to run this test last, since we often run out of memory here and mess up the database connection.
    @Test
    public void testZZCRLData() {
        LOG.trace(">testCRLData");
        logMemStats();
        String CLOB_10MiB = getClob(10 * 1024 * 1024);
        CRLData entity = new CRLData();
        entity.setBase64Crl(CLOB_10MiB);
        CLOB_10MiB = null;
        System.gc();
        entity.setCaFingerprint(VARCHAR_250B);
        entity.setCrlNumber(0);
        entity.setDeltaCRLIndicator(0);
        entity.setFingerprint(VARCHAR_250B);
        entity.setIssuerDN(VARCHAR_250B);
        //setPrivateField(entity, "issuerDN", VARCHAR_250B);
        entity.setNextUpdate(0L);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setThisUpdate(0L);
        storeAndRemoveEntity(entity);
        LOG.trace("<testCRLData");
    }

    @Test
    public void testHardTokenCertificateMap() {
        LOG.trace(">testHardTokenCertificateMap");
        logMemStats();
        HardTokenCertificateMap entity = new HardTokenCertificateMap();
        entity.setCertificateFingerprint(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setTokenSN(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testHardTokenCertificateMap");
    }

    @Test
    public void testHardTokenData() {
        LOG.trace(">testHardTokenData");
        logMemStats();
        HardTokenData entity = new HardTokenData();
        entity.setCtime(0L);
        entity.setData(HASHMAP_200K);
        entity.setMtime(0L);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setSignificantIssuerDN(VARCHAR_250B);
        entity.setTokenSN(VARCHAR_250B);
        entity.setTokenType(0);
        entity.setUsername(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testHardTokenData");
    }

    @Test
    public void testHardTokenIssuerData() {
        LOG.trace(">testHardTokenIssuerData");
        logMemStats();
        HardTokenIssuerData entity = new HardTokenIssuerData();
        entity.setAdminGroupId(0);
        entity.setAlias(VARCHAR_250B);
        entity.setDataUnsafe(HASHMAP_200K);
        entity.setId(BOGUS_INTEGER);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testHardTokenIssuerData");
    }

    @Test
    public void testHardTokenProfileData() {
        LOG.trace(">testHardTokenProfileData");
        logMemStats();
        HardTokenProfileData entity = new HardTokenProfileData();
        entity.setData(CLOB_1MiB);
        entity.setId(BOGUS_INTEGER);
        entity.setName(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setUpdateCounter(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testHardTokenProfileData");
    }

    @Test
    public void testHardTokenPropertyData() {
        LOG.trace(">testHardTokenPropertyData");
        logMemStats();
        HardTokenPropertyData entity = new HardTokenPropertyData();
        // Combined primary key id+property has to be less than 1000 bytes on MyISAM (UTF8: 3*(80+250) < 1000 bytes)
        entity.setHardTokenPropertyDataPK(new HardTokenPropertyDataPK(VARCHAR_80B, VARCHAR_250B));
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setValue(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testHardTokenPropertyData");
    }

    @Test
    public void testInternalKeyBindingData() {
        LOG.trace(">testInternalKeyBindingData");
        logMemStats();
        InternalKeyBindingData entity = new InternalKeyBindingData();
        entity.setCertificateId(VARCHAR_250B);
        entity.setCryptoTokenId(BOGUS_INT);
        entity.setId(BOGUS_INT);
        entity.setKeyBindingType(VARCHAR_250B);
        entity.setKeyPairAlias(VARCHAR_250B);
        entity.setLastUpdate(0L);
        entity.setName(VARCHAR_250B);
        entity.setRawData(CLOB_1MiB);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setStatus(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testInternalKeyBindingData");
    }

    @Test
    public void testKeyRecoveryData() {
        LOG.trace(">testKeyRecoveryData");
        logMemStats();
        KeyRecoveryData entity = new KeyRecoveryData();
        entity.setKeyRecoveryDataPK(new KeyRecoveryDataPK(VARCHAR_80B, VARCHAR_250B));
        entity.setKeyData(CLOB_1MiB);
        entity.setMarkedAsRecoverable(false);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setUsername(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testKeyRecoveryData");
    }

    @Test
    public void testUserData() {
        LOG.trace(">testUserData");
        logMemStats();
        UserData entity = new UserData();
        entity.setCaId(0);
        entity.setCardNumber(VARCHAR_250B);
        entity.setCertificateProfileId(0);
        entity.setClearPassword(VARCHAR_250B);
        entity.setEndEntityProfileId(0);
        entity.setExtendedInformationData(CLOB_1MiB);
        entity.setHardTokenIssuerId(0);
        entity.setKeyStorePassword(VARCHAR_250B);
        entity.setPasswordHash(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setStatus(0);
        entity.setSubjectAltName(VARCHAR_2000B);
        entity.setSubjectDN(VARCHAR_400B);
        entity.setSubjectEmail(VARCHAR_250B);
        entity.setTimeCreated(0L);
        entity.setTimeModified(0L);
        entity.setTokenType(0);
        entity.setType(0);
        entity.setUsername(VARCHAR_250B);
        storeAndRemoveEntity(entity);
        LOG.trace("<testUserData");
    }

    @Test
    public void testAdminPreferencesData() {
        LOG.trace(">testAdminPreferencesData");
        logMemStats();
        AdminPreferencesData entity = new AdminPreferencesData();
        entity.setDataUnsafe(HASHMAP_200K);
        entity.setId(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testAdminPreferencesData");
    }

    @Test
    public void testEndEntityProfileData() {
        LOG.trace(">testEndEntityProfileData");
        logMemStats();
        EndEntityProfileData entity = new EndEntityProfileData();
        entity.setDataUnsafe(HASHMAP_200K);
        entity.setId(BOGUS_INTEGER);
        entity.setProfileName(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testEndEntityProfileData");
    }

    @Test
    public void testGlobalConfigurationData() {
        LOG.trace(">testGlobalConfigurationData");
        logMemStats();
        GlobalConfigurationData entity = new GlobalConfigurationData();
        entity.setConfigurationId(VARCHAR_250B);
        entity.setObjectUnsafe(HASHMAP_200K);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testGlobalConfigurationData");
    }

    @Test
    public void testUserDataSourceData() {
        LOG.trace(">testUserDataSourceData");
        logMemStats();
        UserDataSourceData entity = new UserDataSourceData();
        entity.setData(CLOB_100KiB);
        entity.setId(BOGUS_INTEGER);
        entity.setName(VARCHAR_250B);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setUpdateCounter(0);
        storeAndRemoveEntity(entity);
        LOG.trace("<testUserDataSourceData");
    }

    @Test
    public void testServiceData() {
        LOG.trace(">testServiceData");
        logMemStats();
        ServiceData entity = new ServiceData();
        entity.setData(CLOB_100KiB);
        entity.setId(BOGUS_INTEGER);
        entity.setName(VARCHAR_250B);
        entity.setNextRunTimeStamp(0L);
        entity.setRowProtection(CLOB_10KiB);
        entity.setRowVersion(0);
        entity.setRunTimeStamp(0L);
        storeAndRemoveEntity(entity);
        LOG.trace("<testServiceData");
    }

    /**
     * Outputs which method it is run from.
     * Validates that all getters on the entity that is annotated with @javax.persistence.Column is set. 
     * Commits the entity in one transaction and then removes it in another transaction.
     */
    private void storeAndRemoveEntity(Object entity) {
        LOG.trace(">storeAndRemoveEntity");
        logMemStats();
        try {
            Class<?> entityClass = entity.getClass();
            LOG.info("  - verifying that all getter has an assigned value for " + entityClass.getName());
            boolean allOk = true;
            for (Method m : entityClass.getDeclaredMethods()) {
                for (Annotation a : m.getAnnotations()) {
                    if (a.annotationType().equals(javax.persistence.Column.class) && m.getName().startsWith("get")) {
                        try {
                            m.setAccessible(true);
                            if (m.invoke(entity) == null) {
                                LOG.warn(m.getName() + " was annotated with @Column, but value was null. Test should be updated!");
                                allOk = false;
                            }
                        } catch (Exception e) {
                            LOG.error(m.getName() + " was annotated with @Column and could not be read. " + e.getMessage());
                            allOk = false;
                        }
                    }
                }
            }
            assertTrue("There is a problem with a @Column annotated getter. Please refer to log output for further info.", allOk);
            LOG.info("  - adding entity.");
            EntityTransaction transaction = entityManager.getTransaction();
            transaction.begin();
            entityManager.persist(entity);
            transaction.commit();
            LOG.info("  - removing entity.");
            transaction = entityManager.getTransaction();
            transaction.begin();
            entityManager.remove(entity);
            transaction.commit();
        } finally {
            if (entityManager.getTransaction().isActive()) {
                entityManager.getTransaction().rollback();
            }
            logMemStats();
        }
        LOG.trace("<storeAndRemoveEntity");
    }

    private static void logMemStats() {
        System.gc();
        final long maxMemory = Runtime.getRuntime().maxMemory() / 1024 / 1024;
        final long freeMemory = Runtime.getRuntime().freeMemory() / 1024 / 1024;
        LOG.info("JVM Runtime reports: freeMemory=" + freeMemory + "MiB, maxMemory=" + maxMemory + "MiB, (" + (maxMemory - freeMemory) * 100
                / maxMemory + "% used)");
    }

    /* * Used in order to bypass validity check of different private fields that are access via transient setters. * /
    private void setPrivateField(Object entity, String fieldName, Object value) {
    	LOG.trace(">setPrivateField");
    	try {
    		Field field = entity.getClass().getDeclaredField(fieldName);
    		field.setAccessible(true);
    		field.set(entity, value);
    	} catch (Exception e) {
    		LOG.error("", e);
    		assertTrue("Could not set " + fieldName + " to " + value + ": " + e.getMessage(), false);
    	}
    	LOG.trace("<setPrivateField");
    }
    */
}
