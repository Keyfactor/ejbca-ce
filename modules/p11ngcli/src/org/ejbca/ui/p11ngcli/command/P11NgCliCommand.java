
package org.ejbca.ui.p11ngcli.command;


import static org.cesecore.keys.token.p11ng.TokenEntry.TYPE_PRIVATEKEY_ENTRY;
import static org.cesecore.keys.token.p11ng.TokenEntry.TYPE_SECRETKEY_ENTRY;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.PSSParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.x500.X500Principal;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.RSAPublicKeyStructure;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11ng.CK_CP5_AUTHORIZE_PARAMS;
import org.cesecore.keys.token.p11ng.CK_CP5_AUTH_DATA;
import org.cesecore.keys.token.p11ng.CK_CP5_INITIALIZE_PARAMS;
import org.cesecore.keys.token.p11ng.PToPBackupObj;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.cesecore.keys.token.p11ng.provider.GeneratedKeyData;
import org.cesecore.keys.token.p11ng.provider.SlotEntry;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.FailureCallback;
import org.ejbca.ui.p11ngcli.helper.OneTimeThread;
import org.ejbca.ui.p11ngcli.helper.OperationsThread;
import org.ejbca.ui.p11ngcli.helper.TestSignThread;
import org.ejbca.ui.p11ngcli.helper.UnwrapThread;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKK;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_INFO;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.CK_SLOT_INFO;
import org.pkcs11.jacknji11.CK_TOKEN_INFO;
import org.pkcs11.jacknji11.Ci;
import org.pkcs11.jacknji11.Hex;
import org.pkcs11.jacknji11.LongRef;
import org.pkcs11.jacknji11.jna.JNAi;
import org.pkcs11.jacknji11.jna.JNAiNative;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.NativeLibrary;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.LongByReference;

/**
 * CLI command providing actions using JackNJI11 for troubleshooting.
 *
 * $Id$
 */
public class P11NgCliCommand extends P11NgCliCommandBase {
	  
    /** Logger for this class. */
    private static final Logger log = Logger.getLogger(P11NgCliCommand.class);
    
    private static final String LIBFILE = "-libfile";
    private static final String ACTION = "-action";
    private static final String SLOT = "-slot";
    private static final String PIN = "-pin";
    private static final String USER_AND_PIN = "-user_and_pin";
    private static final String USER2_AND_PIN = "-user2_and_pin";
    private static final String ALIAS = "-alias";
    private static final String WRAPKEY = "-wrapkey";
    private static final String UNWRAPKEY = "-unwrapkey";
    private static final String PRIVATEKEY = "-privatekey";
    private static final String PUBLICKEY = "-publickey";
    private static final String PLAINTEXT = "-plaintext";
    private static final String METHOD = "-method";
    private static final String SELFCERT = "-selfcert";
    private static final String OBJECT = "-object";
    private static final String ATTRIBUTES_FILE = "-attributes_file";
    private static final String THREADS = "-threads";
    private static final String WARMUPTIME = "-warmuptime";
    private static final String TIMELIMIT = "-timelimit";
    private static final String USE_CACHE = "-use_cache";
    private static final String SIGNATUREALGORITHM = "-signaturealgorithm";
    private static final String OBJECT_SPEC_ID = "-object_spec_id";
    private static final String BACKUPFILE = "-backupFile"; 
    private static final String KAK_FILE_PATH = "-kak_file_path";
    private static final String MAX_OPERATIONS = "-max_operations";
    
    private static final int KAK_SIZE = 2048;
    private static final int KEY_AUTHORIZATION_INIT_SIGN_SALT_SIZE = 32;
    private static final int HASH_SIZE = 32;
    private static final int KEY_AUTHORIZATION_ASSIGNED = 1;
    private static final int KAK_PUBLIC_EXP_BUF_SIZE = 3;
    private static long AUTH_CTR = 4294967295L; // Max Operations Number for the key, default is unlimited 
    
    private static final String DEFAULT_PROPERTY_USE_CACHE = "TRUE";
    
    private static CEi ce;
    // used by the testSign stresstest command
    private long startTime;
    
    private static int exitCode;
    
    
  //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Shared library path"));
        registerParameter(
                new Parameter(ACTION, "action", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Operation to perform. Any of: "));
        registerParameter(
                new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Slot on the HSM which will be used."));        
        registerParameter(
                new Parameter(PIN, "PIN for the slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "The pin which is used to connect to HSM slot."));
        registerParameter(
                new Parameter(USER_AND_PIN, "User name and pin ", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "This option is used to provide user cridential for running the CP5 command."));
        registerParameter(
                new Parameter(USER2_AND_PIN, "User name 2 and pin", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "This option is used to provide user cridential for running the CP5 command (subset of them need two users)."));
        registerParameter(
                new Parameter(ALIAS, "alias", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Alias of the key pair on the HSM."));
        registerParameter(
                new Parameter(WRAPKEY, "wrap key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Label of key to wrap with"));
        registerParameter(
                new Parameter(UNWRAPKEY, "unwrap key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Label of key to unwrap with"));
        registerParameter(
                new Parameter(PRIVATEKEY, "private key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "base64 encoded encrypted (wrapped) private key"));
        registerParameter(
                new Parameter(PUBLICKEY, "public key", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "base64 encoded public key"));
        registerParameter(
                new Parameter(PLAINTEXT, "plain text", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "text string to sign"));
        registerParameter(
                new Parameter(METHOD, "method", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Method to use, either pkcs11 (default) or provider"));
        registerParameter(
                new Parameter(SELFCERT, "self cert", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Generate a self-signed certificate for the new key-pair"));
        registerParameter(
                new Parameter(OBJECT, "object", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Object ID (decimal)"));
        registerParameter(
                new Parameter(ATTRIBUTES_FILE, "attributes file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Path of file containing attributes to be used while generating key pair"));
        registerParameter(
                new Parameter(THREADS, "threads", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Number of stresstest threads to run (default: 1)"));
        registerParameter(
                new Parameter(WARMUPTIME, "warm up time", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Don't count number of signings and response times until after this time (in milliseconds). Default=0 (no warmup time)."));
        registerParameter(
                new Parameter(TIMELIMIT, "time limit", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Optional. Only run for the specified time (in milliseconds)."));
        registerParameter(
                new Parameter(USE_CACHE, "use cache", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Whether key objects are fetched from cache instead of HSM token (default: true)"));
        registerParameter(
                new Parameter(SIGNATUREALGORITHM, "signature algorithm", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "For sign-/unwrapPerformanceTest: Signature algorithm to use (default: SHA256withRSA)"));
        registerParameter(
                new Parameter(OBJECT_SPEC_ID, "object spec id", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "idx of the key to back up"));        
        registerParameter(
                new Parameter(BACKUPFILE, "backup file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "full path to the file where backup bytes would be stored"));   
        registerParameter(
                new Parameter(KAK_FILE_PATH, "KAK file path", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "The path which will be used to save the KAK file to and later for authorization the KAK will be read from it."));
        registerParameter(
                new Parameter(MAX_OPERATIONS, "object spec id", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Maximum number of operations associated with the key, if not provided the number of operations will be unlimited"));   
    }
    
    static {Security.addProvider(new BouncyCastleProvider());}

    private static enum Action {
        showInfo,
        showSlotInfo,
        showTokenInfo,
        showAttributeInfo,
        listObjects,
        listKeyStoreEntries,
        generateKey,
        generateAndWrapKeyPair,
        unwrapAndSign,
        deleteKeyStoreEntryByAlias,
        deleteObject,
        generateKeyPair,
        signPerformanceTest,
        unwrapPerformanceTest,
        oneTimePerformanceTest,
        keyAuthorizationInit,
        keyAuthorization,
        unblockKey,
        backupObject,
        restoreObject
    }
    
    private static enum Method {
        pkcs11,
        provider
    }
    
    public String getUsages() {
        final String NL = "\n";
        final String COMMAND = "p11ng-tool";
        StringBuilder footer = new StringBuilder();
        footer.append(NL)
            .append("Sample usages:").append(NL)
            .append("a) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action listSlots").append(NL)
            .append("b) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action showInfo").append(NL)
            .append("c) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action listObjects -slot 0 -pin foo123").append(NL)
            .append("d) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateKey -slot 0 -pin foo123 -alias wrapkey1").append(NL)
            .append("e) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateKeyPair -slot 0 -pin foo123 -alias myprivkey").append(NL)
            .append("f) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateKeyPair -slot 0 -pin foo123 -alias myprivkey -attributes_file /home/user/attribute_file.properties").append(NL)
            .append("g) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action deleteObjects -slot 0 -pin foo123 -object 4").append(NL)
            .append("h) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action deleteObjects -slot 0 -pin foo123 -object 4 -object 5").append(NL)
            .append("i) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action deleteKeyStoreEntryByAlias -slot 0 -alias mykey1").append(NL)
            .append("j) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action listKeyStoreEntries -slot 0 -pin foo123").append(NL)
            .append("k) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action generateAndWrapKeyPair -slot 0 -pin foo123 -wrapkey wrapkey1 -selfcert -alias wrappedprivkey").append(NL)
            .append("l) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action signPerformanceTest -slot 0 -pin foo123 -alias mykey1 -warmuptime 10000 -timelimit 100000 -threads 10").append(NL)
            .append("m) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action unwrapPerformanceTest -slot 0 -pin foo123 -wrapkey wrapkey1 -warmuptime 10000 -timelimit 100000 -threads 10").append(NL)
            .append("n) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action keyAuthorizationInit  -slot 0 -user_and_pin USR_0000,foo123 -alias key_alias -kak_file_path path_of_kak_file").append(NL)
            .append("o) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action keyAuthorization -slot 0 -user_and_pin USR_0000,foo123 -alias key_alias -kak_file_path path_of_kak_file -max_operations 10").append(NL)
            .append("p) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action unblockKey -slot 0 -user_and_pin USR_0000,foo123 -alias signKey").append(NL)
            .append("q) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action backupObject -slot 0 -user_and_pin USR_0000,foo123 -alias Alias -object_spec_id 1 -backupFile /tmp/backupkey1").append(NL)
            .append("r) ").append(COMMAND).append(" -libfile /opt/ETcpsdk/lib/linux-x86_64/libctsw.so -action restoreObject -slot 0 -user_and_pin USR_0000,foo123 -user2_and_pin USR_0001,foo123 -object_spec_id 1 -backupFile /tmp/backupkey1").append(NL);
        
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        return bout.toString();
    }
    
    @Override
    public String getCommandDescription() {
        return "P11NG commands";
    }
    
    @Override 
    public CommandResult execute(ParameterContainer parameters) {
        log.trace(">executeCommand");
        
        final String lib = parameters.get(LIBFILE);
        final Action action = Action.valueOf(parameters.get(ACTION));

        // Doesn't seem to work, anyway...
        System.setProperty("jna.debug_load", "true");
        System.setProperty("jna.nosys", "true");
        System.setProperty("CS_AUTH_KEYS", "C:\\Users\\tarmo\\Desktop\\cs0000.key");
     
        log.debug("Action: " + action);
        
        try {
            final File library = new File(lib);
            final String libDir = library.getParent();
            final String libName = library.getName();
            log.debug("Adding search path: " + libDir);
            NativeLibrary.addSearchPath(libName, libDir);
            JNAiNative jnaiNative = (JNAiNative) Native.loadLibrary(libName, JNAiNative.class);
            ce = new CEi(new Ci(new JNAi(jnaiNative)));
            
            switch (action) {
                case showInfo: {
                    ce.Initialize();
                    CK_INFO info = ce.GetInfo();
                    System.out.println("info: " + info);
                    break;
                }
                
                case showSlotInfo: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    ce.Initialize();
                    CK_SLOT_INFO info = ce.GetSlotInfo(slotId);
                    System.out.println("info: " + info);
                    break;
                }
                
                case showTokenInfo: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    ce.Initialize();
                    CK_TOKEN_INFO info = ce.GetTokenInfo(slotId);
                    System.out.println("info: " + info);
                    break;
                }
                case showAttributeInfo: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    final String alias = parameters.get(ALIAS);
                    // Getting the key if it exist on the slot with the provided alias
                    // Final long key = getKeyIfExists(commandLine, slot, alias); 
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
                    long[] privateObjects = ce.FindObjects(session, new CKA(CKA.TOKEN, true), new CKA(CKA.CLASS, CKO.PRIVATE_KEY), new CKA(CKA.LABEL, alias));
                    System.out.println("Size of the privateObjects array is " + privateObjects.length);
                    for (long object : privateObjects) {
                        System.out.println("The key label is : " + ce.GetAttributeValue(session, object, CKA.VENDOR_PTK_USAGE_COUNT).getValueStr());
                    }
                    break;
                }
                case listObjects: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    ce.Initialize();
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    
                    // tmp - remove later
                    //long slot = ce.GetSlot("RootCA");
                    ce.Login(session, CKU.USER, parameters.get(PIN).getBytes());
                    long[] privateObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PRIVATE_KEY));
                    System.out.println("Private Key Objects: " +  Arrays.toString(privateObjects));
                    StringBuilder buff = new StringBuilder();
                    for (long object : privateObjects) {
                        printGeneralObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());

                    long[] publicObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PUBLIC_KEY));
                    System.out.println("Public Key Objects: " +  Arrays.toString(publicObjects));
                    buff = new StringBuilder();
                    for (long object : publicObjects) {
                        printGeneralObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());
                    
                    long[] certificateObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.CERTIFICATE));
                    System.out.println("Certificate Objects: " +  Arrays.toString(certificateObjects));
                    buff = new StringBuilder();
                    for (long object : certificateObjects) {
                        printGeneralObjectInfo(buff, object, session);
                        printCertificateObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());
                    
                    long[] secretObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.SECRET_KEY));
                    System.out.println("Secret Objects: " +  Arrays.toString(secretObjects));
                    buff = new StringBuilder();
                    for (long object : secretObjects) {
                        printGeneralObjectInfo(buff, object, session);
                    }
                    System.out.println(buff.toString());
                    break;
                }
                case listKeyStoreEntries: {
                    log.debug("Using provider");

                    Security.addProvider(new BouncyCastleProvider());
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    
                    Enumeration<SlotEntry> e = null;
                    try {
                        e = slot.aliases();
                    } catch (CryptoTokenOfflineException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    }
                    final StringBuilder buff = new StringBuilder();
                    while (e.hasMoreElements()) {
                        final SlotEntry slotEntry  = e.nextElement();                
                        final String keyAlias = slotEntry.getAlias();
                        final String type;
                        if (slotEntry.getType().equals(TYPE_PRIVATEKEY_ENTRY)) {
                            type = TYPE_PRIVATEKEY_ENTRY;
                        } else if (slotEntry.getType().equals(TYPE_SECRETKEY_ENTRY)) {
                            type = TYPE_SECRETKEY_ENTRY;
                        } else {
                            type = null;
                        }
                        
                        buff.append("Entry ").append(type).append(" \"").append(keyAlias).append("\"");
                        List<Certificate> certificateChain = slot.getCertificateChain(keyAlias);
                        for (Certificate cert : certificateChain) {
                            buff.append(", ");
                            buff.append("0x");
                            buff.append(((X509Certificate) cert).getSerialNumber().toString(16));
                        }
                        buff.append("\n");
                    }
                    System.out.println(buff.toString());
                    break;
                }
                case generateKey: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String alias = parameters.get(ALIAS);

                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    slot.login(parameters.get(PIN));                  
                    slot.generateKey(CKM.AES_KEY_GEN, 128, alias);
                    System.out.println("Generated wrapKey" + " with alias " + alias);
                    break;
                }
                case generateAndWrapKeyPair: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String wrapkey = parameters.get(WRAPKEY);
                    final boolean selfCert = Boolean.getBoolean(parameters.get(SELFCERT));
                    final String alias = parameters.get(ALIAS);

                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    slot.login(parameters.get(PIN));                    

                    GeneratedKeyData generatedKeyData = slot.generateWrappedKey(wrapkey, "RSA", "2048", CKM.AES_CBC_PAD);

                    // Converting java PublicKey to BC RSAPublicKey
                    byte[] encoded = generatedKeyData.getPublicKey().getEncoded();
                    SubjectPublicKeyInfo subjectPublicKeyInfo = new SubjectPublicKeyInfo(
                            ASN1Sequence.getInstance(encoded));
                    RSAPublicKey rsaPublicKey;
                    try {
                        byte[] rsaPublicKeyEncoded = subjectPublicKeyInfo.parsePublicKey().getEncoded();
                        ASN1InputStream ais = new ASN1InputStream(rsaPublicKeyEncoded);
                        Object asnObject = ais.readObject();
                        ASN1Sequence sequence = (ASN1Sequence) asnObject;
                        RSAPublicKeyStructure rsaPublicKeyStructure = new RSAPublicKeyStructure(sequence);
                        rsaPublicKey = new RSAPublicKey(rsaPublicKeyStructure.getModulus(), rsaPublicKeyStructure.getPublicExponent());
                        System.out.println("Public key: " + new String(Base64.encode(rsaPublicKey.getEncoded())));
                    } catch (IOException ex) {
                        log.error("IO error while generating wrapped key ", ex);
                        System.err.println("IO error while generating wrapped key " + ex.getMessage());
                        break;
                    }

                    System.out.println("Wrapped private key: " + new String(Base64.encode(generatedKeyData.getWrappedPrivateKey())));

                    if (selfCert) {

                        PrivateKey privateKey = slot.unwrapPrivateKey(generatedKeyData.getWrappedPrivateKey(), wrapkey, CKM.AES_CBC_PAD);

                        StringWriter out = new StringWriter();
                        try {
                            Calendar cal = Calendar.getInstance();
                            Date notBefore = cal.getTime();
                            cal.add(Calendar.YEAR, 50);
                            Date notAfter = cal.getTime();

                            X500Name dn = new X500Name("CN=Dummy cert for " + alias);
                            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn, new BigInteger("123"), notBefore, notAfter, dn, generatedKeyData.getPublicKey());
                            X509CertificateHolder cert = builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(privateKey));

                            try (JcaPEMWriter writer = new JcaPEMWriter(out)) {
                                writer.writeObject(cert);
                            }
                            String pemCertificates = out.toString();

                            System.out.println("Self signed certificate for generated wrapped key pair alias: " + alias);
                            System.out.println(pemCertificates);
                        } catch (IOException | OperatorCreationException ex) {
                            log.error("Self signed certificate creation failed: ", ex);
                            System.err.println("Self signed certificate creation failed: " + ex.getMessage());
                        } finally {
                            if (privateKey != null) {
                                slot.releasePrivateKey(privateKey);
                            }
                        }
                    }
                    break;
                }
                case unwrapAndSign: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String unwrapkey = parameters.get(UNWRAPKEY);
                    final String wrapped = parameters.get(PRIVATEKEY);
                    final String publickey = parameters.get(PUBLICKEY);
                    final String plaintext = parameters.get(PLAINTEXT);
                    try {
                        RSAPublicKey rsa = RSAPublicKey.getInstance(new ASN1InputStream(Base64.decode(publickey.getBytes())).readObject());
                        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));

                        if (!StringUtils.isBlank(parameters.get(METHOD)) && Method.valueOf(parameters.get(METHOD)) == Method.provider) {
                            unwrapAndSignUsingProvider(libName, libDir, slotId, parameters.get(PIN), unwrapkey, wrapped, plaintext, publicKey);
                        } else {
                            unwrapAndSignUsingPKCS11(slotId, parameters.get(PIN), unwrapkey, wrapped, plaintext, publicKey);
                        }

                    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException | InvalidKeySpecException | IOException ex) {
                        log.error("unwrapAndSign failed:", ex);
                        System.err.println("unwrapAndSign failed: " + ex.getMessage());
                    }
                    
                    break;
                }
                case deleteKeyStoreEntryByAlias: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String alias = parameters.get(ALIAS);

                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    if (!StringUtils.isBlank(parameters.get(PIN))) {
                        slot.login(parameters.get(PIN));
                    }

                    if (slot.removeKey(alias)) {
                        System.out.println("Destroyed object with alias " + alias);
                    } else {
                        System.err.println("Something went wrong. All objects could not be deleted with alias " + alias);
                    }

                    break;
                }
                case deleteObject: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String objectId = parameters.get(OBJECT);
                    ce.Initialize();
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    ce.Login(session, CKU.USER, parameters.get(PIN).getBytes());                    
                    System.out.println("Destroying object " + objectId);
                    ce.DestroyObject(session, Long.parseLong(objectId));
                    break;
                }
                case generateKeyPair: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String alias = parameters.get(ALIAS);
                    
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    final CryptokiDevice.Slot slot = device.getSlot(slotId);
                    slot.login(parameters.get(PIN));       
                    
                    final Map<Long, Object> publicAttributesMap = new HashMap<>();
                    final Map<Long, Object> privateAttributesMap = new HashMap<>();

                    try {
                        slot.generateRsaKeyPair("RSA", alias, false, publicAttributesMap, privateAttributesMap, null, true);
                    } catch (CertificateException | OperatorCreationException ex) {
                        log.error("Key generation failed! ", ex);
                        System.err.println("Key generation failed! " + ex.getMessage()); 
                    }
                    System.out.println("Generated key pair with alias " + alias);
                    
                    break;
                }
                case signPerformanceTest: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String pin = parameters.get(PIN);
                    final String alias = parameters.get(ALIAS);
                    String signatureAlgorithm = parameters.get(SIGNATUREALGORITHM);
                    if (signatureAlgorithm == null) {
                        signatureAlgorithm = "SHA256withRSA";
                    }

                    final String threadsString = parameters.get(THREADS);
                    int numThreads = 0;
                    int warmupTime = 0;
                    int timeLimit = 0;
                    
                    try {
                        numThreads = Integer.parseInt(threadsString);
                    } catch (NumberFormatException e) {
                        log.error("Illegal number of threads: " + threadsString);
                    }
                    
                    if (numThreads < 1) {
                        log.error("Illegal number of threads: " + threadsString);
                    }
                    
                    final String warmupTimeString = parameters.get(WARMUPTIME);
                    try {
                        warmupTime = Integer.parseInt(warmupTimeString);
                    } catch (NumberFormatException e) {
                        log.error("Illegal warmup time: " + warmupTimeString);
                    }
                    
                    if (warmupTime < 0) {
                        log.error("Warmup time can not be negative");
                    }
                    
                    final String timeLimitString = parameters.get(TIMELIMIT);
                    
                    if (timeLimitString != null) {
                        try {
                            timeLimit = Integer.parseInt(timeLimitString);
                            
                            if (timeLimit < 0) {
                                log.error("Time limit can not be negative");
                            }
                        } catch (NumberFormatException ex) {
                            log.error("Illegal time limit: " + timeLimitString, ex);
                        }
                    } else {
                        timeLimit = -1;
                    }

                    boolean useCache = Boolean.parseBoolean(parameters.get(USE_CACHE));

                    try {
                        runSignPerformanceTest(alias, libName, libDir, slotId, pin,
                                       numThreads, warmupTime, timeLimit, useCache, signatureAlgorithm);
                    } catch (InterruptedException ex) {
                        log.error("Failed to start: " + ex.getMessage());
                        exitCode = -1;
                    }
                    break;
                }
                case oneTimePerformanceTest: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String pin = parameters.get(PIN);                

                    String signatureAlgorithm = parameters.get(SIGNATUREALGORITHM);
                    if (signatureAlgorithm == null) {
                        signatureAlgorithm = "SHA256withRSA";
                    }

                    final String threadsString = parameters.get(THREADS);
                    int numThreads = 0;
                    int warmupTime = 0;
                    int timeLimit = 0;
                    
                    try {
                        numThreads = Integer.parseInt(threadsString);
                    } catch (NumberFormatException e) {
                        log.error("Illegal number of threads: " + threadsString, e);
                    }
                    
                    if (numThreads < 1) {
                        log.error("Illegal number of threads: " + threadsString);
                    }
                    
                    final String warmupTimeString = parameters.get(WARMUPTIME);
                    try {
                        warmupTime = Integer.parseInt(warmupTimeString);
                    } catch (NumberFormatException e) {
                        log.error("Illegal warmup time: " + warmupTimeString);
                    }
                    
                    if (warmupTime < 0) {
                        log.info("Warmup time can not be negative");
                    }
                    
                    final String timeLimitString = parameters.get(TIMELIMIT);
                    
                    if (timeLimitString != null) {
                        try {
                            timeLimit = Integer.parseInt(timeLimitString);
                            
                            if (timeLimit < 0) {
                                log.info("Time limit can not be negative");
                            }
                        } catch (NumberFormatException ex) {
                            log.info("Illegal time limit: " + timeLimitString);
                        }
                    } else {
                        timeLimit = -1;
                    }

                    boolean useCache = Boolean.parseBoolean(parameters.get(USE_CACHE));
                    
                    // For simplicity we skip overriding the default attributes.
                    Properties attributesConfig;
                    Map<Long, Object> publicAttributesMap = new HashMap<>();
                    Map<Long, Object> privateAttributesMap = new HashMap<>();

                    try {
                        oneTimePerformanceTest(libName, libDir, slotId, pin,
                                       numThreads, warmupTime, timeLimit, useCache, signatureAlgorithm, publicAttributesMap, privateAttributesMap);
                    } catch (InterruptedException ex) {
                        log.error("Failed to start: " + ex.getMessage());
                        exitCode = -1;
                    }
                    break;
                }                
                case unwrapPerformanceTest: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String pin = parameters.get(PIN);
                    final String wrapkey = parameters.get(WRAPKEY);
                    
                    String signatureAlgorithm = parameters.get(SIGNATUREALGORITHM);
                    if (signatureAlgorithm == null) {
                        signatureAlgorithm = "SHA256withRSA";
                    }
                    
                    final String threadsString = parameters.get(THREADS);
                    int numThreads = 0;
                    int warmupTime = 0;
                    int timeLimit = 0;
                    
                    try {
                        numThreads = Integer.parseInt(threadsString);
                    } catch (NumberFormatException e) {
                        log.info("Illegal number of threads: " + threadsString);
                    }
                    
                    if (numThreads < 1) {
                        log.info("Illegal number of threads: " + threadsString);
                    }
                    
                    final String warmupTimeString = parameters.get(WARMUPTIME);
                    try {
                        warmupTime = Integer.parseInt(warmupTimeString);
                    } catch (NumberFormatException e) {
                        log.info("Illegal warmup time: " + warmupTimeString);
                    }
                    
                    if (warmupTime < 0) {
                        log.info("Warmup time can not be negative");
                    }
                    
                    final String timeLimitString = parameters.get(TIMELIMIT);
                    
                    if (timeLimitString != null) {
                        try {
                            timeLimit = Integer.parseInt(timeLimitString);
                            
                            if (timeLimit < 0) {
                                log.error("Time limit can not be negative");
                            }
                        } catch (NumberFormatException ex) {
                            log.error("Illegal time limit: " + timeLimitString);
                        }
                    } else {
                        timeLimit = -1;
                    }
                    
                    boolean useCache = Boolean.parseBoolean(parameters.get(USE_CACHE));
                    
                    try {
                        runUnwrapPerformanceTest(wrapkey, libName, libDir, slotId, pin,
                                                 numThreads, warmupTime, timeLimit, 
                                                 signatureAlgorithm, useCache);
                    } catch (InterruptedException ex) {
                        log.error("Failed to start: " + ex.getMessage());
                        exitCode = -1;
                    }
                    break;
                }
                case keyAuthorizationInit:{
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final String alias = parameters.get(ALIAS);
                    final String kakFilePath = parameters.get(KAK_FILE_PATH);
                    
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    
                    // KAK generation part
                    KeyPair kakPair = generateKeyPair(); 
                    Key kakPublicKey = kakPair.getPublic();
                    Key kakPrivateKey = kakPair.getPrivate();

                    // Saving the private key, later it will be used in key authorization section.
                    try { 
                    	savePrivateKey(kakFilePath, kakPrivateKey);
                    } catch (IOException e) {
                    	log.error("IOException happened while saving the kak private key on the disk!", e);
                    }
                    
                    RSAPublicKeySpec publicSpec = (RSAPublicKeySpec) generateKeySpec(kakPublicKey);
                    BigInteger kakPublicExponent  = publicSpec.getPublicExponent();
                    BigInteger kakModulus = publicSpec.getModulus();
                    
                    byte[] kakModBuf = new byte[bitsToBytes(KAK_SIZE)];
                    byte[] kakPubExpBuf = new byte[KAK_PUBLIC_EXP_BUF_SIZE];
                    
                    int kakModLen = kakModulus.toByteArray().length;
                    int kakPubExpLen = kakPublicExponent.toByteArray().length;

                    assert(kakModBuf.length >= kakModLen);
                    assert(kakPubExpBuf.length >= kakPubExpLen);
                    
                    kakModBuf = kakModulus.toByteArray();
                    kakPubExpBuf = kakPublicExponent.toByteArray();

                    CK_CP5_INITIALIZE_PARAMS params = new CK_CP5_INITIALIZE_PARAMS();
                    CK_CP5_AUTH_DATA authData = new CK_CP5_AUTH_DATA();
                    authData.ulModulusLen = new NativeLong(kakModLen);
                    
                    // allocate sufficient native memory to hold the java array Pointer ptr = new Memory(arr.length);
                    // Copy the java array's contents to the native memory ptr.write(0, arr, 0, arr.length);
                    Pointer kakModulusPointer = new Memory(kakModLen);
                    kakModulusPointer.write(0, kakModBuf, 0, kakModLen);
                    authData.pModulus = kakModulusPointer;
                    authData.ulPublicExponentLen = new NativeLong(kakPubExpLen);
                    
                    Pointer kakPublicKeyExponentPointer = new Memory(kakPubExpLen);
                    kakPublicKeyExponentPointer.write(0, kakPubExpBuf, 0, kakPubExpLen);
                    authData.pPublicExponent = kakPublicKeyExponentPointer;
                    authData.protocol = (byte) CKM.CP5_KEY_AUTH_PROT_RSA_PSS_SHA256;

                    params.authData = authData;
                    params.bAssigned = KEY_AUTHORIZATION_ASSIGNED;
                    
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
                    
                    params.write(); // Write data before passing structure to function
					CKM mechanism = new CKM(CKM.CKM_CP5_INITIALIZE, params.getPointer(), params.size());
                    
                    byte[] hash = new byte[HASH_SIZE];
                    long hashLen = hash.length;

                    // Get the private key from HSM
                    long[] privateKeyObjects = getPrivateKeyFromHSM(slot, alias);
                    
                    long rvAuthorizeKeyInit = ce.authorizeKeyInit(session, mechanism, privateKeyObjects[0], hash, new LongRef(hashLen));
                    if (rvAuthorizeKeyInit != CKR.OK) {
                    	cleanUp(session);
                    	throw new CKRException(rvAuthorizeKeyInit);
                    }

                    byte[] initSig = new byte[bitsToBytes(KAK_SIZE)];
                    try {
						initSig = signHashPss(hash, hashLen, initSig.length, kakPrivateKey);
					} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException 
						     | InvalidAlgorithmParameterException | SignatureException e) {
						log.error("Error happened while signing the hash!", e);
					}

                    long rvAuthorizeKey = ce.authorizeKey(session, initSig, initSig.length);
                    if (rvAuthorizeKey != CKR.OK) {
                    	cleanUp(session);
                    	throw new CKRException(rvAuthorizeKey);
                    }

                    cleanUp(session);
                    break;
                }
                case keyAuthorization: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    
                    final String alias = parameters.get(ALIAS);
                    final String kakFilePath = parameters.get(KAK_FILE_PATH);
                    
                    CK_CP5_AUTHORIZE_PARAMS params = new CK_CP5_AUTHORIZE_PARAMS();
                    
                    params.ulCount = AUTH_CTR;
                    
                    params.write(); // Write data before passing structure to function
					CKM mechanism = new CKM(CKM.CKM_CP5_AUTHORIZE, params.getPointer(), params.size());

                    byte[] hash = new byte[HASH_SIZE];
                    long hashLen = hash.length;
                    
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
                    
                    long[] privateKeyObjects = getPrivateKeyFromHSM(slot, alias);
                    
                    long rvAuthorizeKeyInit = ce.authorizeKeyInit(session, mechanism, privateKeyObjects[0], hash, new LongRef(hashLen));
                    if (rvAuthorizeKeyInit != CKR.OK) {
                    	cleanUp(session);
                    	throw new CKRException(rvAuthorizeKeyInit);
                    }
                    
                    // Here obtain the private key created in the previous init part, reading it from file
                    Key kakPrivateKey = null;
                    try {
                    	kakPrivateKey = loadPrivateKey(kakFilePath, "RSA");
                    } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
						log.error("Error happened while loading the kak key pair from disk!", e);
                    }

                    byte[] authSig = new byte[bitsToBytes(KAK_SIZE)];
                    try {
                    	authSig = signHashPss(hash, hashLen, authSig.length, kakPrivateKey);
					} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException 
							 | InvalidAlgorithmParameterException | SignatureException e) {
						log.error("Error happened while signing the hash!", e);
					}
                    
                    long rvAuthorizeKey = ce.authorizeKey(session, authSig, authSig.length);
                    if (rvAuthorizeKey != CKR.OK) {
                    	cleanUp(session);
                    	throw new CKRException(rvAuthorizeKey);
                    }
                    
                    cleanUp(session);
                    break;
                }
                case unblockKey: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    CryptokiDevice.Slot slot = device.getSlot(slotId);
                    final String alias = parameters.get(ALIAS);
                    // Getting the key if it exist on the slot with the provided alias
                    long[] privateKeyObjects = getPrivateKeyFromHSM(slot, alias);
                    
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
                    long rvUnblockKey = ce.unblockKey(session, privateKeyObjects[0]);
                    if (rvUnblockKey != CKR.OK) {
                    	cleanUp(session);
                    	throw new CKRException(rvUnblockKey);
                    }
                    cleanUp(session);
                    break;
                } case backupObject: {
                	final long slotId = Long.parseLong(parameters.get(SLOT));
                    CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    device.getSlot(slotId);                    
                    
                    long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
                    ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
                    long objectHandle = Long.parseLong(parameters.get(OBJECT_SPEC_ID));
                    
                    PToPBackupObj ppBackupObj = new PToPBackupObj(null);
                    LongByReference backupObjectLength = new LongByReference();
                    
                    ce.backupObject(session, objectHandle, ppBackupObj.getPointer(), backupObjectLength);
                    
                    int length = (int) backupObjectLength.getValue();
                    byte[] resultBytes = ppBackupObj.getValue().getByteArray(0, length);
                    final String backupFile = parameters.get(BACKUPFILE);
                    
                    write2File(resultBytes, backupFile);
                    cleanUp(session);
                    break;
                } case restoreObject: {
                    final long slotId = Long.parseLong(parameters.get(SLOT));
                    final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
                    device.getSlot(slotId); // Initialize slot
                    final long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);                    
                    ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
                    ce.Login(session, CKU.CKU_CS_GENERIC, parameters.get(USER2_AND_PIN).getBytes(StandardCharsets.UTF_8));
                    
                    final Path filePath = Paths.get(parameters.get(BACKUPFILE));
                    final byte[] bytes = Files.readAllBytes(filePath);
                    final long flags = 0; // alternative value here would be something called "CXI_KEY_FLAG_VOLATILE" but this causes 0x00000054: FUNCTION_NOT_SUPPORTED
                    
                    final long objectHandle = Long.parseLong(parameters.get(OBJECT_SPEC_ID));
                    ce.restoreObject(session, flags, bytes, objectHandle);
                    /*
                      CK_SESSION_HANDLE     hSession,
                      CK_ULONG              flags,        
                      CK_BYTE_PTR           pBackupObj,
                      CK_ULONG              ulBackupObjLen,
                      CK_OBJECT_HANDLE_PTR  phObject
                     */
                    break;
                }
            }
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } finally {
            // CE.Finalize();
        }
        return CommandResult.SUCCESS;      
    }

    private long[] getPrivateKeyFromHSM(CryptokiDevice.Slot slot, final String alias) {
        // Get the private key from HSM
        long[] privateKeyObjects = slot.findPrivateKeyObjectsByID(slot.aquireSession(), new CKA(CKA.ID, alias.getBytes(StandardCharsets.UTF_8)).getValue());
        if (privateKeyObjects.length == 0) {
            throw new IllegalStateException("No private key found for alias '" + alias + "'");
        }
        if (log.isDebugEnabled()) {
            log.debug("Private key  with Id: '" + privateKeyObjects[0] + "' found for key alias '" + alias + "'");
        }
        return privateKeyObjects;
    }

	private synchronized void cleanUp(final long session) {
		ce.Logout(session);
		ce.CloseSession(session);
		ce.Finalize();
	}
    
    private KeySpec generateKeySpec(final Key key) {
    	KeyFactory kf = null;
    	KeySpec spec = null;
        try {
            kf = KeyFactory.getInstance("RSA");
            spec = kf.getKeySpec(key, KeySpec.class);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
        	log.error("Error happened while getting the key spec!", e);
        }
        return spec;
	}

	private KeyPair generateKeyPair() {
    	KeyPairGenerator kpg = null;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
        	log.error("Error happened while generationg the key pair!", e);
        }
        kpg.initialize(KAK_SIZE);
        return kpg.generateKeyPair();
	}
	
	private void savePrivateKey(final String path, final Key privateKey) throws IOException {
	    final Path pathToKeyDirectory = Paths.get(path);

	    if(Files.notExists(pathToKeyDirectory)){
	        log.info("Target directory \"" + path + "\" will be created.");
	        Files.createDirectories(pathToKeyDirectory);
	    }
		// Store Private Key.
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(
				privateKey.getEncoded());
		
	    final Path pathToPrivateKey = Paths.get(pathToKeyDirectory.toString() + "/privateKey");
	    Files.write(pathToPrivateKey, pkcs8EncodedKeySpec.getEncoded());
	}
	
	private Key loadPrivateKey(final String path, final String algorithm)
			throws IOException, NoSuchAlgorithmException,
			InvalidKeySpecException {
 
		// Read Private Key.
		File filePrivateKey = new File(path + "/privateKey");
		byte[] encodedPrivateKey = null;
		try (FileInputStream fis = new FileInputStream(path + "/privateKey")) {
		    encodedPrivateKey = new byte[(int) filePrivateKey.length()];
		    fis.read(encodedPrivateKey);
		}
 
		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
 
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				encodedPrivateKey);
		return keyFactory.generatePrivate(privateKeySpec);
	}

	private byte[] signHashPss(byte[] hash, long hashLen, int length, Key privateKey) 
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, SignatureException {
		// Due to requirements at the HSM side we have to use RAW signer
		Signature signature = Signature.getInstance("RawRSASSA-PSS", "BC");
		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, KEY_AUTHORIZATION_INIT_SIGN_SALT_SIZE, 
				PSSParameterSpec.DEFAULT.getTrailerField());
		signature.setParameter(pssParameterSpec);
		signature.initSign((PrivateKey) privateKey, new SecureRandom());
		signature.update(hash);
		byte[] signBytes = signature.sign();
		return signBytes;
    }
    
    private void write2File(byte[] bytes, String filePath) {
        try (OutputStream os = new FileOutputStream(new File(filePath))) {
            os.write(bytes);
        } catch (Exception e) {
        	log.error("Error happened while writing key to file!", e);
        }
    }

	private int bitsToBytes(final int kakSize) {
		int result = (((kakSize) + 7)/8);
		return result;
	}
    
    private void runSignPerformanceTest(final String alias, final String libName,
                                        final String libDir, final long slotId,
                                        final String pin, final int numberOfThreads,
                                        final int warmupTime, final int timeLimit, final boolean useCache, final String signatureAlgorithm)
            throws InterruptedException {
        final TestSignThread[] threads = new TestSignThread[numberOfThreads];

        Thread shutdownHook = new Thread() {
            @Override
            public void run() {
                if (log.isDebugEnabled()) {
                    log.debug("Shutdown hook called");
                }
                shutdown(threads, warmupTime);
            }
        };

        Runtime.getRuntime().addShutdownHook(shutdownHook);

        final FailureCallback failureCallback = new FailureCallback() {

            @Override
            public void failed(OperationsThread thread, String message) {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }

                // Print message
                log.error("   " + message);
                exitCode = -1;
            }
        };
        
        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new TestSignThread(i, failureCallback, alias, libName,
                                            libDir, slotId, pin, warmupTime,
                                            timeLimit, useCache, signatureAlgorithm);
        }

        // wait 1 sec to start
        Thread.sleep(1000);
        
        startTime = System.currentTimeMillis();
        
        for (int i = 0; i < numberOfThreads; i++) {
            if (log.isDebugEnabled()) {
                log.debug("thread: " + i);
            }
            threads[i].start();
        }
        
        // Wait for the threads to finish
        try {
            for (final TestSignThread w : threads) {
                if (log.isDebugEnabled()) {
                    log.debug("Waiting for thread " + w.getName());
                }
                w.join();
                if (log.isDebugEnabled()) {
                    log.debug("Thread " + w.getName() + " stopped");
                }
            }
        } catch (InterruptedException ex) {
            if (log.isDebugEnabled()) {
                log.debug("Interupted when waiting for thread: " + ex.getMessage());
            }
        }
    }
    
    private void oneTimePerformanceTest(final String libName,
                                        final String libDir, final long slotId,
                                        final String pin, final int numberOfThreads,
                                        final int warmupTime, final int timeLimit, final boolean useCache, final String signatureAlgorithm, 
                                        Map<Long, Object> publicAttributesMap, Map<Long, Object> privateAttributesMap)
            throws InterruptedException {
        final OneTimeThread[] threads = new OneTimeThread[numberOfThreads];

        Thread shutdownHook = new Thread() {
            @Override
            public void run() {
                if (log.isDebugEnabled()) {
                    log.debug("Shutdown hook called");
                }
                shutdown(threads, warmupTime);
            }
        };

        Runtime.getRuntime().addShutdownHook(shutdownHook);

        final FailureCallback failureCallback = new FailureCallback() {

            @Override
            public void failed(OperationsThread thread, String message) {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }

                // Print message
                log.error("   " + message);
                exitCode = -1;
            }
        };
        
        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new OneTimeThread(i, failureCallback, libName,
                                            libDir, slotId, pin, warmupTime,
                                            timeLimit, useCache, signatureAlgorithm, publicAttributesMap, privateAttributesMap);
        }

        // wait 1 sec to start
        Thread.sleep(1000);
        
        startTime = System.currentTimeMillis();
        
        for (int i = 0; i < numberOfThreads; i++) {
            if (log.isDebugEnabled()) {
                log.debug("thread: " + i);
            }
            threads[i].start();
        }
        
        // Wait for the threads to finish
        try {
            for (final OneTimeThread w : threads) {
                if (log.isDebugEnabled()) {
                    log.debug("Waiting for thread " + w.getName());
                }
                w.join();
                if (log.isDebugEnabled()) {
                    log.debug("Thread " + w.getName() + " stopped");
                }
            }
        } catch (InterruptedException ex) {
            if (log.isDebugEnabled()) {
                log.debug("Interupted when waiting for thread: " + ex.getMessage());
            }
        }
    }
    
    private void runUnwrapPerformanceTest(final String alias, final String libName,
                                        final String libDir, final long slotId,
                                        final String pin, final int numberOfThreads,
                                        final int warmupTime, final int timeLimit,
                                        final String signatureAlgorithm,
                                        final boolean useCache)
            throws InterruptedException {
        final UnwrapThread[] threads = new UnwrapThread[numberOfThreads];

        Thread shutdownHook = new Thread() {
            @Override
            public void run() {
                if (log.isDebugEnabled()) {
                    log.debug("Shutdown hook called");
                }
                shutdown(threads, warmupTime);
            }
        };

        Runtime.getRuntime().addShutdownHook(shutdownHook);

        final FailureCallback failureCallback = new FailureCallback() {

            @Override
            public void failed(OperationsThread thread, String message) {
                for (final OperationsThread w : threads) {
                    w.stopIt();
                }

                // Print message
                log.error("   " + message);
                exitCode = -1;
            }
        };
        
        final CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        final CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);
        final long wrappingCipherAlgo = CKM.AES_CBC_PAD;
        final GeneratedKeyData wrappedKey =
                slot.generateWrappedKey(alias, "RSA", "2048", wrappingCipherAlgo);
        
        for (int i = 0; i < numberOfThreads; i++) {
            threads[i] = new UnwrapThread(i, failureCallback, alias, libName,
                                            libDir, slotId, pin, warmupTime,
                                            timeLimit, signatureAlgorithm,
                                            wrappedKey, wrappingCipherAlgo,
                                            useCache);
        }

        // wait 1 sec to start
        Thread.sleep(1000);
        
        startTime = System.currentTimeMillis();
        
        for (int i = 0; i < numberOfThreads; i++) {
            if (log.isDebugEnabled()) {
                log.debug("thread: " + i);
            }
            threads[i].start();
        }
        
        // Wait for the threads to finish
        try {
            for (final UnwrapThread w : threads) {
                if (log.isDebugEnabled()) {
                    log.debug("Waiting for thread " + w.getName());
                }
                w.join();
                if (log.isDebugEnabled()) {
                    log.debug("Thread " + w.getName() + " stopped");
                }
            }
        } catch (InterruptedException ex) {
            if (log.isDebugEnabled()) {
                log.debug("Interupted when waiting for thread: " + ex.getMessage());
            }
        }
    }
    
    private void shutdown(final OperationsThread[] threads,
                          final int warmupTime) {
        for (final OperationsThread thread : threads) {
            thread.stopIt();
        }
        
        int totalOperationsPerformed = 0;
        
        // wait until all stopped
        try {
            for (int i = 0; i < threads.length; i++) {
                final OperationsThread thread = threads[i];
                thread.join();
                final int numberOfOperations = thread.getNumberOfOperations();
                log.info("Number of operations for thread " + i + ": " + numberOfOperations);
                totalOperationsPerformed += thread.getNumberOfOperations();
            }
        } catch (InterruptedException ex) {
            log.error("Interrupted: " + ex.getMessage());
        }
        
        long totalRunTime = System.currentTimeMillis() - startTime - warmupTime;
        final double tps;
        if (totalRunTime > 1000) {
            tps = totalOperationsPerformed / (totalRunTime / 1000d);
        } else {
            tps = Double.NaN;
        }
        
        
        log.info("Total number of signings: " + totalOperationsPerformed);
        log.info("Signings per second: " + tps);
    }

    private static void printGeneralObjectInfo(StringBuilder buff, long object, long session) {
        buff.append("Object ").append(object).append("\n");
        printStringOrHexObjectInfo(buff, object, session, CKA.ID, "CKA_ID");
        printStringOrHexObjectInfo(buff, object, session, CKA.LABEL, "CKA_LABEL");
    }

    private static void printCertificateObjectInfo(StringBuilder buff, long object, long session) {
        printX509NameObjectInfo(buff, object, session, CKA.SUBJECT, "CKA_SUBJECT");
        printX509NameObjectInfo(buff, object, session, CKA.ISSUER, "CKA_ISSUER");
    }

    private static void printStringOrHexObjectInfo(StringBuilder buff, long object, long session, long cka, String name) {
        CKA ckaValue = ce.GetAttributeValue(session, object, cka);
        byte[] value = ckaValue.getValue();
        buff.append("   ").append(name).append(":    ");
        if (value == null) {
            buff.append("-");
        } else {
            buff.append("0x").append(Hex.b2s(ckaValue.getValue()));
            buff.append(" \"").append(new String(ckaValue.getValue(), StandardCharsets.UTF_8)).append("\"");
        }
        buff.append("\n");
    }

    private static void printX509NameObjectInfo(StringBuilder buff, long object, long session, long cka, String name) {
        CKA ckaValue = ce.GetAttributeValue(session, object, cka);
        byte[] value = ckaValue.getValue();
        buff.append("   ").append(name).append(":    ");
        if (value == null) {
            buff.append("-");
        } else {
            buff.append(" \"").append(new X500Principal(value).toString()).append("\"");
        }
        buff.append("\n");
    } 

    private void unwrapAndSignUsingPKCS11(final long slotId, final String pin, final String unwrapkey, final String wrapped, final String plaintext, final PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        log.debug("Using p11");
        
        ce.Initialize();
        long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        ce.Login(session, CKU.USER, pin.getBytes());   

        // Find unWrapKey
        long[] secretObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.SECRET_KEY));
        long unWrapKey = -1;
        for (long object : secretObjects) {
            CKA ckaLabel = ce.GetAttributeValue(session, object, CKA.LABEL);
            if (ckaLabel != null && unwrapkey.equals(ckaLabel.getValueStr())) {
                unWrapKey = object;
                break;
                }
        }
        if (unWrapKey < 0) {
            System.err.println("No such secret key found: " + unwrapkey);
            return;
        }

        CKA[] unwrappedPrivateKeyTemplate = new CKA[] {
            new CKA(CKA.CLASS, CKO.PRIVATE_KEY),
            new CKA(CKA.KEY_TYPE, CKK.RSA),
            new CKA(CKA.PRIVATE, true),
            new CKA(CKA.DECRYPT, true),
            new CKA(CKA.SIGN, true),
            new CKA(CKA.SENSITIVE, true),
            new CKA(CKA.EXTRACTABLE, true),
        };
        long privateKey = ce.UnwrapKey(session, new CKM(CKM.AES_CBC_PAD), unWrapKey, Base64.decode(wrapped), unwrappedPrivateKeyTemplate);
        System.out.println("Unwrapped key: " + privateKey);

        ce.SignInit(session, new CKM(CKM.SHA256_RSA_PKCS), privateKey);
        ce.SignUpdate(session, plaintext.getBytes());
        byte[] signed = ce.SignFinal(session);
        System.out.println("signed: " + new String(Base64.encode(signed)));

        Security.addProvider(new BouncyCastleProvider());

        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initVerify(publicKey);
        sig.update(plaintext.getBytes());
        System.out.println("Consistent: " + sig.verify(signed));
        System.out.println();
    }

    private void unwrapAndSignUsingProvider(final String libName, final String libDir, final long slotId, final String pin, final String unwrapkey, final String wrapped, final String plaintext, final PublicKey publicKey) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
        log.debug("Using provider");
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);
        slot.login(pin);

        PrivateKey privateKey = null;
        try {
            privateKey = slot.unwrapPrivateKey(Base64.decode(wrapped), unwrapkey, CKM.AES_CBC_PAD);

            Signature sig1 = Signature.getInstance("SHA256withRSA", device.getProvider());
            sig1.initSign(privateKey);
            sig1.update(plaintext.getBytes());
            byte[] signed = sig1.sign();
            System.out.println("signed: " + new String(Base64.encode(signed)));

            Security.addProvider(new BouncyCastleProvider());

            Signature sig2 = Signature.getInstance("SHA256withRSA", "BC");
            sig2.initVerify(publicKey);
            sig2.update(plaintext.getBytes());
            System.out.println("Consistent: " + sig2.verify(signed));
            System.out.println();
        } finally {
            if (privateKey != null) {
                slot.releasePrivateKey(privateKey);
            }
        }
    }

    @Override
    public String getMainCommand() {
        return "p11ngcli";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
    
}
