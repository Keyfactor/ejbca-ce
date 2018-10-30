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

package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.DSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.ObjectNotFoundException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.KeyRecoveryCAServiceInfo;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.ocsp.extension.certhash.OcspCertHashExtension;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;


/**
 * Tests http pages of ocsp
 * 
 * @version $Id$
 *
 */
public class ProtocolOcspHttpTest extends ProtocolOcspTestBase {

    public static final String DEFAULT_SUPERADMIN_CN = "SuperAdmin";

    private static final String DSA_DN = "CN=OCSPDSATEST,O=Foo,C=SE";
    
    private static final Logger log = Logger.getLogger(ProtocolOcspHttpTest.class);

    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("ProtocolOcspHttpTest"));


    private static byte[] ks3 = Base64.decode(("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCAyYwgDCABgkqhkiG9w0BBwGggCSABIID"
            + "DjCCAwowggMGBgsqhkiG9w0BDAoBAqCCAqkwggKlMCcGCiqGSIb3DQEMAQMwGQQU" + "/h0pQXq7ZVjYWlDvzEwwmiJ8O8oCAWQEggJ4MZ12+kTVGd1w7SP4ZWlq0bCc4MsJ"
            + "O0FFSX3xeVp8Bx16io1WkEFOW3xfqjuxKOL6YN9atoOZdfhlOMhmbhglm2PJSzIg" + "JSDHvWk2xKels5vh4hY1iXWOh48077Us4wP4Qt94iKglCq4xwxYcSCW8BJwbu93F"
            + "uxE1twnWXbH192nMhaeIAy0v4COdduQamJEtHRmIJ4GZwIhH+lNHj/ARdIfNw0Dm" + "uPspuSu7rh6rQ8SrRsjg63EoxfSH4Lz6zIJKF0OjNX07T8TetFgznCdGCrqOZ1fK"
            + "5oRzXIA9hi6UICiuLSm4EoHzEpifCObpiApwNj3Kmp2uyz2uipU0UKhf/WqvmU96" + "yJj6j1JjZB6p+9sgecPFj1UMWhEFTwxMEwR7iZDvjkKDNWMit+0cQyeS7U0Lxn3u"
            + "m2g5e6C/1akwHZsioLC5OpFq/BkPtnbtuy4Kr5Kwb2y7vSiKpjFr7sKInjdAsgCi" + "8kyUV8MyaIfZdtREjwqBe0imfP+IPVqAsl1wGW95YXsLlK+4P1bspAgeHdDq7Q91"
            + "bJJQAS5OTD38i1NY6MRtt/fWsShVBLjf2FzNpw6siHHl2N7BDNyO3ALtgfp50e0Z" + "Dsw5WArgKLiXfwZIrIKbYA73RFc10ReDqnJSF+NXgBo1/i4WhZLHC1Osl5UoKt9q"
            + "UoXIUmYhAwdAT5ZKVw6A8yp4e270yZTXNsDz8u/onEwNc1iM0v0RnPQhNE5sKEZH" + "QrMxttiwbKe3YshCjbruz/27XnNA51t2p1M6eC1HRab4xSHAyH5NTxGJ8yKhOfiT"
            + "aBKqdTH3P7QzlcoCUDVDDe7aLMaZEf+a2Te63cZTuUVpkysxSjAjBgkqhkiG9w0B" + "CRQxFh4UAHAAcgBpAHYAYQB0AGUASwBlAHkwIwYJKoZIhvcNAQkVMRYEFCfeHSg6"
            + "EdeP5A1IC8ydjyrjyFSdAAQBAAQBAAQBAAQBAASCCBoAMIAGCSqGSIb3DQEHBqCA" + "MIACAQAwgAYJKoZIhvcNAQcBMCcGCiqGSIb3DQEMAQYwGQQURNy47tUcttscSleo"
            + "8gY6ZAPFOl0CAWSggASCB8jdZ+wffUP1B25Ys48OFBMg/itT0EBS6J+dYVofZ84c" + "x41q9U+CRMZJwVNZbkqfRZ+F3tLORSwuIcwyioa2/JUpv8uJCjQ2tru5+HtqCrzR"
            + "Huh7TfdiMqvjkKpnXi69DPPjQdCSPwYMy1ahZrP5KgEZg4S92xpU2unF1kKQ30Pq" + "PTEBueDlFC39rojp51Wsnqb1QzjPo53YvJQ8ztCoG0yk+0omELyPbc/qMKe5/g5h"
            + "Lx7Q+2D0PC/ZHtoDkCRfMDKwgwALFsSj2uWNJsCplspmc7YgIzSr/GqqeSXHp4Ue" + "dwVJAswrhpkXZTlp1rtl/lCSFl9akwjY1fI144zfpYKpLqfoHL1uI1c3OumrFzHd"
            + "ZldZYgsM/h3qjgu8qcXqI0sKVXsffcftCaVs+Bxmdu9vpY15rlx1e0an/O05nMKU" + "MBU2XpGkmWxuy0tOKs3QtGzHUJR5+RdEPURctRyZocEjJgTvaIMq1dy/FIaBhi+d"
            + "IeAbFmjBu7cv9C9v/jMuUjLroycmo7QW9jGgyTOQ68J+6w2/PtqiqIo3Ry9WC0SQ" + "8+fVNOGLr5O2YPpw17sDQa/+2gjozngvL0OHiABwQ3EbXAQLF046VYkTi5R+8iGV"
            + "3jlTvvStIKY06E/s/ih86bzwJWAQENCazXErN69JO+K3IUiwxac+1AOO5WyR9qyv" + "6m/yHdIdbOVE21M2RARbI8UiDpRihCzk4duPfj/x2bZyFqLclIMhbTd2UOQQvr+W"
            + "4etpMJRtyFGhdLmNgYAhYrbUgmdL1kRkzPzOs77PqleMpfkii7HPk3HlVkM7NIqd" + "dN0WQaQwGJuh5f1ynhyqtsaw6Gu/X56H7hpziAh0eSDQ5roRE7yy98h2Mcwb2wtY"
            + "PqVFTmoKuRWR2H5tT6gCaAM3xiSC7RLa5SF1hYQGaqunqBaNPYyUIg/r03dfwF9r" + "AkOhh6Mq7Z2ktzadWTxPl8OtIZFVeyqIOtSKBHhJyGDGiz3+SSnTnSX81NaTSJYZ"
            + "7YTiXkXvSYNpjpPckIKfjpBw0T4pOva3a6s1z5p94Dkl4kz/zOmgveGd3dal6wUV" + "n3TR+2cyv51WcnvB9RIp58SJOc+CvCvYTvkEdvE2QtRw3wt4ngGJ5pxmC+7+8fCf"
            + "hRDzw9LBNz/ry88y/0Bidpbhwr8gEkmHuaLp43WGQQsQ+cWYJ8AeLZMvKplbCWqy" + "iuks0MnKeaC5dcB+3BL55OvcTfGkMtz0oYBkcGBTbbR8BKJZgkIAx7Q+/rCaqv6H"
            + "HN/cH5p8iz5k+R3MkmR3gi6ktelQ2zx1pbPz3IqR67cTX3IyTX56F2aY54ueY17m" + "7hFwSy4aMen27EO06DXn/b6vPKj73ClE2B/IPHO/H2e8r04JWMltFWuStV0If5x0"
            + "5ZImXx068Xw34eqSWvoMzr97xDxUwdlFgrKrkMKNoTDhA4afrZ/lwHdUbNzh6cht" + "jHW/IfIaMo3NldN/ihO851D399FMsWZW7YA7//RrWzBDiLvh+RfwkMOfEpbujy0G"
            + "73rO/Feed2MoVXvmuKBRpTNyFuBVvFDwIzBT4m/RaVf5m1pvprSk3lo43aumdN9f" + "NDETktVZ/CYaKlYK8rLcNBKJicM5+maiQSTa06XZXDMY84Q0xtCqJ/aUH4sa/z8j"
            + "KukVUSyUZDJk/O82B3NA4+CoP3Xyc9LAUKucUvoOmGt2JCw6goB/vqeZEg9Tli0Q" + "+aRer720QdVRkPVXKSshL2FoXHWUMaBF8r//zT6HbjTNQEdxbRcBNvkUXUHzITfl"
            + "YjQcEn+FGrF8+HVdXCKzSXSgu7mSouYyJmZh42spUFCa4j60Ks1fhQb2H1p72nJD" + "n1mC5sZkU68ITVu1juVl/L2WJPmWfasb1Ihnm9caJ/mEE/i1iKp7qaY9DPTw5hw4"
            + "3QplYWFv47UA/sOmnWwupRuPk7ISdimuUnih8OYR75rJ0z6OYexvj/2svx9/O5Mw" + "654jFF2hAq69jt7GJo6VZaeCRCAxEU7N97l3EjqaKJVrpIPQ+3yLmqHit/CWxImB"
            + "iIl3sW7MDEHgPdQy3QiZmAYNLQ0Te0ygcIHwtPyzhFoFmjbQwib2vxDqWaMQpUM1" + "/W96R/vbCjA7tfKYchImwAPCyRM5Je2FHewErG413kZct5tJ1JqkcjPsP7Q8kmgw"
            + "Ec5QNq1/PZOzL1ZLr6ryfA4gLBXa6bJmf43TUkdFYTvIYbvH2jp4wpAtA152YgPI" + "FL19/Tv0B3Bmb1qaK+FKiiQmYfVOm/J86i/L3b8Z3jj8dRWEBztaI/KazZ/ZVcs/"
            + "50bF9jH7y5+2uZxByjkM/kM/Ov9zIHbYdxLw2KHnHsGKTCooSSWvPupQLBGgkd6P" + "M9mgE6MntS+lk9ucpP5j1LXo5zlZaLSwrvSzE3/bbWJKsJuomhRbKeZ+qSYOWvPl"
            + "/1RqREyZHbSDKzVk39oxH9EI9EWKlCbrz5EHWiSv0+9HPczxbO3q+YfqcY8plPYX" + "BvgxHUeDR+LxaAEcVEX6wd2Pky8pVwxQydU4cEgohrgZnKhxxLAvCp5sb9kgqCrh"
            + "luvBsHpmiUSCi/r0PNXDgApvTrVS/Yv0jTpX9u9IWMmNMrnskdcP7tpEdkw8/dpf" + "RFLLgqwmNEhCggfbyT0JIUxf2rldKwd6N1wZozaBg1uKjNmAhJc1RxsABAEABAEA"
            + "BAEABAEABAEABAEABAEABAEABAEABAEABAEAAAAAAAAAMDwwITAJBgUrDgMCGgUA" + "BBSS2GOUxqv3IT+aesPrMPNn9RQ//gQUYhjCLPh/h2ULjh+1L2s3f5JIZf0CAWQA" + "AA==")
            .getBytes());

    private static byte[] ksexpired = Base64.decode(("MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+gwgDCABgkqhkiG9w0BBwGggCSABIID"
            + "FzCCAxMwggMPBgsqhkiG9w0BDAoBAqCCArIwggKuMCgGCiqGSIb3DQEMAQMwGgQU" + "+FPoYyKdBmCiikns2YwMZh4pPSkCAgQABIICgC5leUCbJ8w3O8KEUMRvHOA+Xhzm"
            + "R5y7aHJHL1z3ZnoskDL4YW/r1TQ5AFliaH7e7kuA7NYOjv9HdFsZ9BekLkWPybit" + "rcryLkPbRF+YdAXNkbGluukY0F8O4FP9n7FtfBd5uKitvOHZgHp3JAC9A+jYfayk"
            + "ULfZRRGmzUys+D4czobY1tkCbQIb3kzR1kaqBownMkie+y5P56dRB2lJXpkpeilM" + "H0PZvckG5jQw7ua4sVUkIzyDAZpiCtNmOF5nvyRwQRLWAHwn7Yid5e8w2A6xTq6P"
            + "wko+2OdqHK/r/fmABREWf9GJa5Lb1QkUzITsWmPVskCUdl+VZzcYL8EV8cREH7DG" + "sWuKyp8UJ0m3fiJEZHR2538Ydp6yp6R6/9DcGwxj20fO9FQnUanYcs6bDgwZ46UK"
            + "blnbJAWGaChG3C9T6moXroLT7Mt2gxefW8RCds09EslhVTES01fmkovpcNuF/3U9" + "ukGTCN49/mnuUpeMDrm8/BotuL+jkWBOnFy3RfEfsHyPzYflBb/M9T7Q8wsGuh0O"
            + "oPecIsVvo4hgXX6R0fpYdPArMfuI5JaGopt07XRhbUuCqlEc4Q6DD46F/SVLk34Q" + "Yaq76xwVplsa4QZZKNE6QTpApM61KpIKFxP3FzkqQIL4AKNb/mbSclr7L25aQmMw"
            + "YiIgWOOaXlVh1U+4eZjqqVyYH5a6Y5e0EpMdMagvfuIA09b/Bp9LVnxQD6GmQgRC" + "MRCaTr3wMQqEv92iTrj718rWmyYWTRArH/7mb4Ef250x2WgqjytuShBcL4McagQG"
            + "NMpMBZLFAlseQYQDlgkGDMfcSZJQ34CeH7Uvy+lBYvFIGnb2o3hnHuZicOgxSjAj" + "BgkqhkiG9w0BCRQxFh4UAG8AYwBzAHAAYwBsAGkAZQBuAHQwIwYJKoZIhvcNAQkV"
            + "MRYEFO0W5oXdg6jY3vp316fMaEFzMEYpAAAAAAAAMIAGCSqGSIb3DQEHBqCAMIAC" + "AQAwgAYJKoZIhvcNAQcBMCgGCiqGSIb3DQEMAQYwGgQU30rkEXMscb9M1uCfhs6v"
            + "wV3eWCICAgQAoIAEggcYMs4iLKX/OQHK9oFu7l79H2zf0IlV58kAyjQG4yvadJnK" + "Y6FOVLkwidcX33qRnMkGI1vidvRBbxnyH5+HVd3hVws/v3XBbZvhhX7A8loZZmye"
            + "wFlHwT6TzIy/MJsz3Ev6EwoYBIID6HUrQhJiT/YPmiVhoWuaMw50YSbRGOUKwxEJ" + "ggqnC4WOPxdP8xZbD+h3V1/W0KdbKyqFyXYVnfTgDisyEBnEn2BN3frl7vlucRsS"
            + "ci0ZpJpkdlCyuF77KzPaq6/yAgPHAhABvjgiEPE11hsdDA635mDb1dRPoM6IFfzR" + "n6JGZ7PEkKHdHudimx55eoUTJskXYaNcrPR2jlrxxX6tWV07m1G61kbgNIeuBdK6"
            + "trJslSVPlli2YsTDQ2g+EmtDZc186nAYuQN03/TdSdhByPZxcT5nVs+xv1A3BdDX" + "ow1HCyuGyBrAIEVoITE171csT78iPxNY9bukYy678XDxWkDQu7QMV8FeGEXec5sh"
            + "NL/IUSYtzuPxaP5V/QALC0ybGxjIoxmdKS0zPxyekA+Cj8XjQBKVW2DPjWXWtAHR" + "6lfWpwIgTwD0B7o59RVjKo/jrWRsH+RKfN17FXSKInTrm1gNHQPDCyIAv2luTSUa"
            + "2qMRqH7/qivEWXbAWBz9dtEkqeuf/j698Rfie3QNtZ5qXmaVq1LBI0sduSJM+jHr" + "uRtICzEzWMvSqVnW+3ejyHmpLc6zBYx8VwNuFy8IH+qtV0pDYyoNL96KBOJhX2hf"
            + "DsH82SNf1CbIf8245YNmtzDby8h+3NXNIo8qAleLvgTgSN1tmS5kEJKw3M9/MYgE" + "8XHGATAJB0E7uVRS1Ktr8R1w0hunautq7ylsw62zXdPp+6EsO0tMluCyWB0lMNAh"
            + "uPiIMudNMA+O7NlCFQVTPxPxaRXg37dLm2XFy4ZnquKDuLvKkujdIwc9VBMER+MC" + "6FiNtJw5Kq4PcARt1ulKGMknn38+3jSh3Dzg93XNMUx7lmqZCosYc4kf5X6dAWKd"
            + "xBVNi3/hLejvWCCb55BncXiGMvs75L6b07IXcm3HTXZxCzzl5QtWM7XqpPVqbqhW" + "wz03K4qko97YdD61oa8719SRjqBpbaW6RKIx5qGvAWYKg5usNorm/SsGg37zAfPa"
            + "0LRoD22M5psU8MmH2E0iDDsf4sZDjeAY7LUGhgUGyyQ9t6hlEjD1Nhsxb9TSKNc+" + "UBzCVRqjUWqImo8q7ZHhcDn64eXY4sSyQWWRP+TUfbpfgo+tb6NQvEhceU8sQlAh"
            + "HGqi1/4kvc54O+dUFsRMJkXoobSRc053JgdUgaLQ22iI0nZSVVLgcR8/jTTvQhbv" + "LRNES5vdoSUd+QiC83Hlx38uZtCgJ7HZfdnhYdaRIFIc7K1nqV+8ht6s7DdXK/JP"
            + "8/QhtsLLfn1kies1/Xi+FeATef57jtBKh75yeBR5WFigEtSgFbRUNTLIrQQiDK07" + "71bi+VA8QGH/dpUVNg0EggLZI0qqSXqD+2f2XnhK90fHl3RLZWX8xvU6sP6wGMLj"
            + "R+OlW0Gsv0gWeVLbSKRmNyesl0lznC2yVAeoyLMSkU6YLYCuzQTzZ2dpjdPwkBOP" + "7YhIIL7c1PWPGDLb35E/57Zd+I+dUdSX8SQyKzDgWyxyLGTaozkyaR3PK3XPKJNf"
            + "t+RjfAJOtN3uSIjhpj90YL28p+kSlWxGRLM7FFDsS8nkcWQ113ZSfUnC5k5HmGmK" + "FA5b6oVkxk98uxgK7jJ6h9wONZR9t8WbyfMYnjMgo5ZgGmKzoBRJ9rD0WiIJfHiR"
            + "zrv9yejClIHdseps4rB96hqQjXDSk1f3e/5IQ6Zp++x7nIZy50C9HfnuDugigpNr" + "IJS46o/86AgrBikc+CUoGLnu9OKvVCznFkwyz6ZzBdE3ITwHW4TXnlbkP888wax9"
            + "lCKde+7/dBdUVwasgrU/F05MKCGqjWHIZ0po0owOTjMzkllqDtEmUdyUrGmLEmsA" + "0tE8txLSi6TPmqL/th/7Os0B+7nyC3Ju8kBhmXVmoudcmWh2QH6VM6pegqETkCtA"
            + "hGErIKKrdUSVNXy4izJFh9dgyYJKwm+X6XAaLWN1nlQlS08U0jR3vikDfJqUknxP" + "Dg14TeC5Sgl2UjIpGX+XVxM8PV+2+WwvcwR0Nn1HFu99toZUD7FjkP6DR+XcHOhQ"
            + "1tZZsutVPuyVJW9sTiYw48fIlYWDJXVESbLHDNN5TJD4NY9fhzfG3BYlex+YbbOx" + "sCvmUNrrFwi1ZOGa/Z2ow5V7Kdf4rbWbyuV+0CCVJBcPTKageONp4AOaARpBMFg3"
            + "QuTvzwEXmrTMbbrPY2o1GOS8ulwOp1VI8PcOyGwRpHXzpRZPv2u9gTmYgnfu2PcU" + "F8NfHRFnPzFkO95KYFTYxZrg3vrU49IRJXqbjaeruQaKxPibxTDOsatJpWYAnw/s"
            + "KuCHXrnUlw5RLeublCbUAAAAAAAAAAAAAAAAAAAAAAAAMD0wITAJBgUrDgMCGgUA" + "BBRo3arw4fuHPsqvDnvA8Q/TLyjoRQQU3Xm6ZsAJT0/iLV7S3mKeme0FVGACAgQA" + "AAA=")
            .getBytes());
    
    private final CAAdminSessionRemote caAdminSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
    private final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private final CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private final RevocationSessionRemote revocationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RevocationSessionRemote.class);
    private final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private final OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(OcspResponseGeneratorSessionRemote.class);

    @Rule
    public final TestWatcher traceLogMethodsRule = new TestWatcher() {
        @Override
        protected void starting(final Description description) {
            log.trace(">" + description.getMethodName());
            super.starting(description);
        };
        @Override
        protected void finished(final Description description) {
            log.trace("<" + description.getMethodName());
            super.finished(description);
        }
    };
    
    @BeforeClass
    public static void beforeClass() throws CertificateException {
        // Install BouncyCastle provider
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    public ProtocolOcspHttpTest() throws MalformedURLException, URISyntaxException {
        super("http", "ejbca", "publicweb/status/ocsp");
    }

    @Before
    public void setUp() throws Exception {
        CaTestCase.removeTestCA();
        CaTestCase.createTestCA();
        unknowncacert = CertTools.getCertfromByteArray(unknowncacertBytes, X509Certificate.class);
        helper.reloadKeys();
        log.debug("httpReqPath=" + httpReqPath);
        assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection())
                .getResponseCode() == 200);
        cacert = (X509Certificate) CaTestCase.getTestCACert();
        caid = CaTestCase.getTestCAId();
        
        Map<String, String> config = new HashMap<String, String>();
        
        config.put("ocsp.nonexistingisgood", "false");
        config.put("ocsp.nonexistingisrevoked", "false");
        helper.alterConfig(config);
        helper.reloadKeys();
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference(CertTools.getSubjectDN(CaTestCase.getTestCACert()));
        globalConfigurationSession.saveConfiguration(admin, ocspConfiguration);
    }

    @After
    public void tearDown() throws Exception {
        CaTestCase.removeTestCA();
        removeDSACA();
        removeECDSACA();
    }

    public String getRoleName() {
        return this.getClass().getSimpleName();
    }

    @Test
    public void test01Access() throws Exception {
        super.test01Access();
    }

    /**
     * Tests ocsp message
     *
     * @throws Exception
     *           error
     */
    @Test
    public void test02OcspGood() throws Exception {
        log.trace(">test02OcspGood()");

        // find a CA (TestCA?) create a user and generate his cert
        // send OCSP req to server and get good response
        // change status of cert to bad status
        // send OCSP req and get bad status
        // (send crap message and get good error)

        // Get user and ocspTestCert that we know...
        loadUserCert(this.caid);
        this.helper.reloadKeys();

        this.helper.verifyStatusGood( this.caid, this.cacert, this.ocspTestCert.getSerialNumber());
        log.trace("<test02OcspGood()");
    }


    /**
     * Tests ocsp message
     *
     * @throws Exception
     *           error
     */
    @Test
    public void test03OcspRevoked() throws Exception {
        log.trace(">test03OcspRevoked()");
        loadUserCert(this.caid);
        // Now revoke the certificate and try again
        this.revocationSession.revokeCertificate(admin, this.ocspTestCert, null, RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);
        this.helper.reloadKeys();
        this.helper.verifyStatusRevoked( this.caid, this.cacert, this.ocspTestCert.getSerialNumber(), 
                            RevokedCertInfo.REVOCATION_REASON_KEYCOMPROMISE, null);
        log.trace("<test03OcspRevoked()");
    }

    @Test
    public void test04OcspUnknown() throws Exception {
        super.test04OcspUnknown();
    }    
    
    @Test
    public void test05OcspUnknownCA() throws Exception {
        super.test05OcspUnknownCA();
    }


    @Test
    public void test06OcspSendWrongContentType() throws Exception {
        super.test06OcspSendWrongContentType();
    }

    @Test
    public void test07SignedOcsp() throws Exception {
        assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection())
                .getResponseCode() == 200);

        // find a CA (TestCA?) create a user and generate his cert
        // send OCSP req to server and get good response
        // change status of cert to bad status
        // send OCSP req and get bad status
        // (send crap message and get good error)
        try {
            KeyPair keys = createUserCert(caid);

            // And an OCSP request
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
            Extension[] extensions = new Extension[1];
            extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
            gen.setRequestExtensions(new Extensions(extensions));
            
            X509CertificateHolder chain[] = new X509CertificateHolder[2];
            chain[0] = new JcaX509CertificateHolder(ocspTestCert);
            chain[1] = new JcaX509CertificateHolder(cacert);
            gen.setRequestorName(chain[0].getSubject());
            OCSPReq req = gen.build(new JcaContentSignerBuilder("SHA1WithRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(keys.getPrivate()), chain);

            // First test with a signed OCSP request that can be verified
            Collection<Certificate> cacerts = new ArrayList<Certificate>();
            cacerts.add(cacert);
            CaCertificateCache certcache = CaCertificateCache.INSTANCE;
            certcache.loadCertificates(cacerts);
            X509Certificate signer = checkRequestSignature("127.0.0.1", req, certcache);
            assertNotNull(signer);
            assertEquals(ocspTestCert.getSerialNumber().toString(16), signer.getSerialNumber().toString(16));

            // Try with an unsigned request, we should get a SignRequestException
            req = gen.build();
            boolean caught = false;
            try {
                signer = checkRequestSignature("127.0.0.1", req, certcache);
            } catch (SignRequestException e) {
                caught = true;
            }
            assertTrue(caught);

            // sign with a keystore where the CA-certificate is not known
            KeyStore store = KeyStore.getInstance("PKCS12", "BC");
            ByteArrayInputStream fis = new ByteArrayInputStream(ks3);
            store.load(fis, "foo123".toCharArray());
            Certificate[] certs = KeyTools.getCertChain(store, "privateKey");
            chain[0] = new JcaX509CertificateHolder((X509Certificate) certs[0]);
            chain[1] = new JcaX509CertificateHolder((X509Certificate) certs[1]);
            PrivateKey pk = (PrivateKey) store.getKey("privateKey", "foo123".toCharArray());
            req = gen.build(new BufferingContentSigner(new JcaContentSignerBuilder("SHA1WithRSA").build(pk), 20480), chain);
            // Send the request and receive a singleResponse, this response should
            // throw an SignRequestSignatureException
            caught = false;
            try {
                signer = checkRequestSignature("127.0.0.1", req, certcache);
            } catch (SignRequestSignatureException e) {
                caught = true;
            }
            assertTrue(caught);

            // sign with a keystore where the signing certificate has expired
            store = KeyStore.getInstance("PKCS12", "BC");
            fis = new ByteArrayInputStream(ksexpired);
            store.load(fis, "foo123".toCharArray());
            certs = KeyTools.getCertChain(store, "ocspclient");
            chain[0] =  new JcaX509CertificateHolder((X509Certificate) certs[0]);
            chain[1] =  new JcaX509CertificateHolder((X509Certificate) certs[1]);
            pk = (PrivateKey) store.getKey("ocspclient", "foo123".toCharArray());
            req = gen.build(new BufferingContentSigner(new JcaContentSignerBuilder("SHA1WithRSA").build(pk), 20480), chain);
            // Send the request and receive a singleResponse, this response should
            // throw an SignRequestSignatureException
            caught = false;
            try {
                signer = checkRequestSignature("127.0.0.1", req, certcache);
            } catch (SignRequestSignatureException e) {
                caught = true;
            }
            assertTrue(caught);
        } finally {
            endEntityManagementSession.deleteUser(admin, "ocsptest");
        }

    } // test07SignedOcsp

    /**
     * Tests ocsp message
     *
     * @throws Exception error
     */
    @Test
    public void test08OcspEcdsaGood() throws Exception {
        assertTrue("This test can only be run on a full EJBCA installation.",
                ((HttpURLConnection) new URL(httpReqPath + '/').openConnection()).getResponseCode() == 200);
        final int ecdsacaid = "CN=OCSPECDSATEST".hashCode();
        final CAInfo caInfo = addECDSACA("CN=OCSPECDSATEST", "secp256r1");
        final X509Certificate ecdsacacert = (X509Certificate) caInfo.getCertificateChain().iterator().next();
        helper.reloadKeys();
        try {
            // Make user and ocspTestCert that we know...
            createUserCert(ecdsacaid);
            this.helper.verifyStatusGood( ecdsacaid, ecdsacacert, this.ocspTestCert.getSerialNumber() );
        } finally {
            endEntityManagementSession.deleteUser(admin, "ocsptest");
            CryptoTokenTestUtils.removeCryptoToken(admin, caInfo.getCAToken().getCryptoTokenId());
        }
    } // test08OcspEcdsaGood

    /**
     * Tests ocsp message
     *
     * @throws Exception
     *           error
     */
    @Test
    public void test09OcspEcdsaImplicitlyCAGood() throws Exception {
        assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection())
                .getResponseCode() == 200);
        int ecdsacaid = "CN=OCSPECDSAIMPCATEST".hashCode();
        final CAInfo caInfo = addECDSACA("CN=OCSPECDSAIMPCATEST", "implicitlyCA");
        final X509Certificate ecdsacacert = (X509Certificate) caInfo.getCertificateChain().iterator().next();
        helper.reloadKeys();
        try {
            // Make user and ocspTestCert that we know...
            createUserCert(ecdsacaid);
            this.helper.verifyStatusGood( ecdsacaid, ecdsacacert, this.ocspTestCert.getSerialNumber() );
        } finally {
            endEntityManagementSession.deleteUser(admin, "ocsptest");
            CryptoTokenTestUtils.removeCryptoToken(admin, caInfo.getCAToken().getCryptoTokenId());
        }
    } // test09OcspEcdsaImplicitlyCAGood

    @Test
    public void test10MultipleRequests() throws Exception {
        this.helper.reloadKeys();
        super.test10MultipleRequests();
    }

    @Test
    public void test11MalformedRequest() throws Exception {     
        super.test11MalformedRequest();
    }

    @Test
    public void test12CorruptRequests() throws Exception {
        super.test12CorruptRequests();
    }

    /**
     * Just verify that a simple GET works.
     */
    @Test
    public void test13GetRequests() throws Exception {
        // See if the OCSP Servlet can read non-encoded requests
        final String plainReq = httpReqPath
                + '/'
                + resourceOcsp
                + '/'
                + "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB+Aevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCCzdx5N0v9XwoiEwHzAdBgkrBgEFBQcwAQIEECrZswo/a7YW+hyi5Sn85fs=";
        URL url = new URL(plainReq);
        log.info(url.toString()); // Dump the exact string we use for access
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be considered malformed.", OCSPRespBuilder.MALFORMED_REQUEST != response.getStatus());
        final String dubbleSlashNonEncReq = httpReqPath + '/' + resourceOcsp + '/'
                + "MGwwajBFMEMwQTAJBgUrDgMCGgUABBRBRfilzPB%2BAevx0i1AoeKTkrHgLgQUFJw5gwk9BaEgsX3pzsRF9iso29ICCAvB//HJyKqpoiEwHzAdBgkrBgEFBQcwAQIEEOTzT2gv3JpVva22Vj8cuKo%3D";
        url = new URL(dubbleSlashNonEncReq);
        log.info(url.toString()); // Dump the exact string we use for access
        con = (HttpURLConnection) url.openConnection();
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        assertNotNull("Response should not be null.", response);
        assertTrue("Should not be concidered malformed.", OCSPRespBuilder.MALFORMED_REQUEST != response.getStatus());
        // An OCSP request, ocspTestCert is already created in earlier tests
        loadUserCert(this.caid);
        this.helper.reloadKeys();
        this.helper.verifyStatusGood( this.caid, this.cacert, this.ocspTestCert.getSerialNumber() );
    }

    @Test
    public void test14CorruptGetRequests() throws Exception {
        super.test14CorruptGetRequests();
    }

    @Test
    public void test15MultipleGetRequests() throws Exception {
        super.test15MultipleGetRequests();
    }

    /**
     * Tests ocsp message
     *
     * @throws Exception
     *           error
     */
    @Test
    public void test16OcspDsaGood() throws Exception {
        assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection())
                .getResponseCode() == 200);

        int dsacaid = DSA_DN.hashCode();
        X509Certificate ecdsacacert = addDSACA(DSA_DN, "DSA1024");
        helper.reloadKeys();

        // Make user and ocspTestCert that we know...
        createUserCert(dsacaid);

        this.helper.verifyStatusGood( dsacaid, ecdsacacert, this.ocspTestCert.getSerialNumber() );
    } // test16OcspDsaGood

    /**
     * Verify that Internal OCSP responses are signed by CA signing key.
     */
    @Test
    public void test17OCSPResponseSignature() throws Exception {

        // Get user and ocspTestCert that we know...
        loadUserCert(caid);
        this.helper.reloadKeys();
        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();

        // POST the OCSP request
        URL url = new URL(httpReqPath + '/' + resourceOcsp);
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(req.getEncoded());
        os.close();
        assertTrue("HTTP error", con.getResponseCode() == 200);

        // Some appserver (Weblogic) responds with
        // "application/ocsp-response; charset=UTF-8"
        assertNotNull("No Content-Type in reply.", con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        assertTrue("Response status not the expected.", response.getStatus() != 200);

        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        boolean verify = brep.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(cacert.getPublicKey()));
        assertTrue("Signature verification", verify);
    }

    /**
     * Verify OCSP response for a malicious request. Uses nonsense payload.
     *
     * HTTP Content-length: 1000 byte ASN1 sequence length: 199995 byte Payload
     * size: 200000 byte (not including HTTP header)
     */
    @Test
    public void test18MaliciousOcspRequest() throws Exception {
        log.trace(">test18MaliciousOcspRequest");
        int i = 0;
        // Construct the fake data.
        byte data[] = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE * 2];
        // The first byte indicate that this is a sequence. Necessary to past
        // the first test as an accepted OCSP object.
        data[0] = (byte) BERTags.SEQUENCE;
        // The second byte indicates the number if the following bytes are more
        // than can be represented by one byte and will be represented by 3
        // bytes instead.
        data[1] = (byte) 0x83;
        // The third through the forth bytes are the number of the following
        // bytes. (0x030D3B = 199995)
        data[2] = (byte) 0x03; // MSB
        data[3] = (byte) 0x0D;
        data[4] = (byte) 0x3B; // LSB
        // Fill the rest of the array with some fake data.
        for (i = 5; i < data.length; i++) {
            data[i] = (byte) i;
        }
        // Create the HTTP header
        String path = "/ejbca/" + resourceOcsp;
        String headers = "POST " + path + " HTTP/1.1\r\n" + "Host: "+httpHost+"\r\n" + "Content-Type: application/ocsp-request\r\n" + "Content-Length: 1000\r\n"
                + "\r\n";
        // Merge the HTTP headers and the raw data into one package.
        byte input[] = concatByteArrays(headers.getBytes(), data);
        // Create the socket.
        Socket socket = new Socket(InetAddress.getByName(httpHost), Integer.parseInt(httpPort));
        OutputStream os = socket.getOutputStream();
        try {
            // Send data byte for byte.
            try {
                os.write(input);
            } catch (IOException e) {
                log.info("Socket threw an IOException.", e);
                // Windows throws an IOException when trying to write more bytes to
                // the server than it should. JBoss on Linux does not.
                // assertTrue("Tried to write more than it should to the server (>1000), "+i, i > 1000);
                return;
            }
            /* Note that an Apache proxy interprets this as two requests in the same session (where the second one is bad):
HTTP/1.1 200 OK
Date: Thu, 27 Mar 2014 16:13:24 GMT
Server: Apache/2.4.6 (Unix) OpenSSL/1.0.1e
Content-Type: application/ocsp-response
Content-Length: 5

0
HTTP/1.1 400 Bad Request
Date: Thu, 27 Mar 2014 16:13:24 GMT
Server: Apache/2.4.6 (Unix) OpenSSL/1.0.1e
Content-Length: 226
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
</body></html>

            But since the response is ANS1 encoded, the response is still correctly parsed even though we provide 420 bytes extra.
             */
            // Reading the response.
            InputStream ins = socket.getInputStream();
            byte ret[] = new byte[1024];
            int len = ins.read(ret);
            assertTrue("Could not read response.", len!=-1);
            // Removing the HTTP headers. The HTTP headers end at the first occurrence of "\r\n\r\n".
            for (i = 3; i < len; i++) {
                if ((ret[i] == 0x0A) && (ret[i - 1] == 0x0D) && (ret[i-2] == 0x0A) && (ret[i - 3] == 0x0D)) {
                    break;
                }
            }
            log.info("response headers:  " + new String(ret, 0, i));
            int start = i + 1;
            byte respa[] = new byte[len - start];
            for (i = start; i < len; i++) {
                respa[i - start] = ret[i];
            }
            log.info("response contains: " + respa.length + " bytes.");
            log.info("response bytes:    " + Hex.toHexString(respa));
            log.info("response as string:" + new String(respa));
            // Reading the response as a OCSPResp. When the input data array is
            // longer than allowed the OCSP response will return as an internal
            // error.
            OCSPResp response = new OCSPResp(respa);
            assertEquals("Incorrect response status.", OCSPRespBuilder.INTERNAL_ERROR, response.getStatus());
        } finally {
            os.close();
            socket.close();
        }
        log.trace("<test18MaliciousOcspRequest");
    }

    /**
     * Verify OCSP response for a malicious request. Uses nonsense payload.
     *
     * HTTP Content-length: 200000 byte ASN1 sequence length: 9996 byte Payload
     * size: 200000 byte (not including HTTP header)
     */
    @Test
    public void test19MaliciousOcspRequest() throws Exception {
        log.trace(">test19MaliciousOcspRequest");
        int i = 0;
        // Construct the fake data.
        byte data[] = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE * 2];
        // The first byte indicate that this is a sequence. Necessary to past
        // the first test as an accepted OCSP object.
        data[0] = (byte) BERTags.SEQUENCE;
        // The second byte indicates the number of the following bytes are more
        // than can be represented by one byte and will be represented by 2
        // bytes instead.
        data[1] = (byte) 0x82;
        // The third through the forth bytes are the number of the following
        // bytes. (0x270C = 9996)
        data[2] = (byte) 0x27; // MSB
        data[3] = (byte) 0x0C; // LSB
        // Fill the rest of the array with some fake data.
        for (i = 4; i < data.length; i++) {
            data[i] = (byte) i;
        }
        // Create the HTTP header
        String path = "/ejbca/" + resourceOcsp;
        String headers = "POST " + path + " HTTP/1.1\r\n" + "Host: "+httpHost+"\r\n" + "Content-Type: application/ocsp-request\r\n" + "Content-Length: 200000\r\n"
                + "\r\n";
        // Merge the HTTP headers and the raw data into one package.
        byte input[] = concatByteArrays(headers.getBytes(), data);
        // Create the socket.
        Socket socket = new Socket(InetAddress.getByName(httpHost), Integer.parseInt(httpPort));
        // Send data byte for byte.
        OutputStream os = socket.getOutputStream();
        try {
            os.write(input);
        } catch (IOException e) {
            log.info("Socket threw an IOException.", e);
        }
        // Reading the response.
        InputStream ins = socket.getInputStream();
        byte ret[] = new byte[1024];
        ins.read(ret);
        socket.close();
        // Removing the HTTP headers. The HTTP headers end at the last
        // occurrence of "\r\n".
        for (i = ret.length - 1; i > 0; i--) {
            if ((ret[i] == 0x0A) && (ret[i - 1] == 0x0D)) {
                break;
            }
        }
        int start = i + 1;
        byte respa[] = new byte[ret.length - start];
        for (i = start; i < ret.length; i++) {
            respa[i - start] = ret[i];
        }
        log.info("response contains: " + respa.length + " bytes.");
        // Reading the response as a OCSPResp.
        OCSPResp response = new OCSPResp(respa);
        assertEquals("Incorrect response status.", OCSPRespBuilder.MALFORMED_REQUEST, response.getStatus());
        log.trace("<test19MaliciousOcspRequest");
    }

    /**
     * Verify OCSP response for a malicious request where the POST data starts
     * with a proper OCSP request.
     */
    @Test
    public void test20MaliciousOcspRequest() throws Exception {
        log.trace(">test20MaliciousOcspRequest");
        // Start by sending a valid OCSP requests so we know the helpers work
        byte validOcspReq[] = getValidOcspRequest();
        OCSPResp response = sendRawRequestToOcsp(validOcspReq.length, validOcspReq, false);
        if (OCSPRespBuilder.SUCCESSFUL != response.getStatus()) {
            throw new IllegalStateException("Could not send standard raw request, test cannot continue. Instead of Successful (0), status was " + response.getStatus());
        }
        // Try sending a valid request and then keep sending some more data.
        byte[] buf = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE * 2];
        Arrays.fill(buf, (byte) 123);
        buf = concatByteArrays(validOcspReq, buf);
        // This should return an error because we only allow content length of 100000 bytes
        response = sendRawRequestToOcsp(buf.length, buf, false);
        assertEquals("Incorrect response status.", OCSPRespBuilder.MALFORMED_REQUEST, response.getStatus());
        // Now try with a fake HTTP content-length header
        try {
            response = sendRawRequestToOcsp(validOcspReq.length, buf, false);
            // When sending a large request body with a too short content-length the serves sees this as two streaming
            // requests. The first request will be read and processed by EJBCA normally and sent back, but the
            // second one will not be a valid request so the server will send back an error.
            // Glassfish actually sends back a "400 Bad request". Our reading code in sendRawRequestToOcsp
            // does not handle multiple streaming responses so it will barf on the second one.
            // This is different for JBoss and Glassfish though, with JBoss we will get a IOException trying
            // to read the response, while for Glassfish we will get the response with 0 bytes from the 400 response

            // Only glassfish will come here, with a non-null response, but of length 2(/r/n?). JBoss (4, 5, 6) will go to the
            // IOException below
            try {
                byte[] encoded = response.getEncoded();
                if ((encoded != null) && (encoded.length > 2)) {
                    // Actually this error message is wrong, since it is our client that does not handle streaming responses
                    // where the first response should be good.
                    fail("Was able to send a lot of data with a fake HTTP Content-length without any error.");
                }
            } catch (NullPointerException npe) { // NOPMD
                // the response.getEncoded() can give NPE, in some versions of BC, if it was not created with correct input
            }
        } catch (IOException e) {
        }
        // Try sneaking through a payload that is just under the limit. The
        // responder will answer politely, but log a warning.
        buf = new byte[LimitLengthASN1Reader.MAX_REQUEST_SIZE - validOcspReq.length];
        Arrays.fill(buf, (byte) 123);
        buf = concatByteArrays(validOcspReq, buf);
        response = sendRawRequestToOcsp(buf.length, buf, false);
        assertEquals("Server accepted malicious request. (This might be a good thing!)", OCSPRespBuilder.SUCCESSFUL, response.getStatus());
        log.trace("<test20MaliciousOcspRequest");
    }

    /**
     * Tests ocsp message
     *
     * @throws Exception
     *           error
     */
    @Test
    public void test50OcspUnknownMayBeGood() throws Exception {
        log.trace(">test50OcspUnknownMayBeGood()");
        loadUserCert(this.caid);
        // An OCSP request for an unknown certificate (not exist in db)
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        final String bad1 = "Bad";
        final String bad2 = "Ugly";
        final String good1 = "Good";
        final String good2 = "Beautiful";
        {
            final Map<String,String> map = new HashMap<String, String>();
            map.put(OcspConfiguration.NON_EXISTING_IS_GOOD, "true");
            map.put(OcspConfiguration.NON_EXISTING_IS_BAD_URI+'1', ".*"+bad1+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_BAD_URI+'2', ".*"+bad2+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_GOOD_URI+'1', ".*"+good1+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_GOOD_URI+'2', ".*"+good2+"$");
            this.helper.alterConfig(map);
        }
        this.helper.reloadKeys();
        this.helper.verifyStatusGood( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(bad1);
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(bad2);
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        {
            final Map<String,String> map = new HashMap<String, String>();
            map.put(OcspConfiguration.NON_EXISTING_IS_GOOD, "false");
            this.helper.alterConfig(map);
        }
        this.helper.setURLEnding("");
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(good1);
        this.helper.verifyStatusGood( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(good2);
        this.helper.verifyStatusGood( this.caid, this.cacert, new BigInteger("1") );
        log.trace("<test50OcspUnknownMayBeGood()");
    }
    
    /**
     * This test tests the feature of extensions of setting a '*' in front of the value in ocsp.extensionoid
     * forces that extension to be used for all requests. 
     * The Common PKI CertHash extension is on such extension that is always used, if configured to be used. 
     * This extension is specified in the German Common PKI standard:
     * <a href="http://www.t7ev.org/T7-de/Common-PKI">Common PKI</a> SigG CertHash OCSP extension.
     * 
     * @throws Exception
     */
    @Test
    public void testUseAlwaysExtensions() throws Exception {
        log.trace(">testUseAlwaysExtensions");
        final String ALWAYSUSE_EXT = "ocsp.alwayssendcustomextension";
        final String oldAlwaysUseExt = cesecoreConfigurationProxySession.getConfigurationValue(ALWAYSUSE_EXT);
        try {
            cesecoreConfigurationProxySession.setConfigurationValue(ALWAYSUSE_EXT, OcspCertHashExtension.CERT_HASH_OID);
            ocspResponseGeneratorSession.reloadOcspExtensionsCache();

            // An OCSP request, ocspTestCert is already created in earlier tests
            OCSPReqBuilder gen = new OCSPReqBuilder();
            loadUserCert(this.caid);
            this.helper.reloadKeys();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
            OCSPReq req = gen.build();
            BasicOCSPResp response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
            if (response == null) {
                throw new Exception("Could not retrieve response, test could not continue.");
            }
            // The CertHash is an extension in the responseItem, not in the full response
            Extension responseExtension = response.getExtension(new ASN1ObjectIdentifier(OcspCertHashExtension.CERT_HASH_OID));
            assertNull("There should be no CertHash extension in the ResponseExtensions, it should be in the responseItem Extensions", responseExtension);
            SingleResp[] responseItems = response.getResponses();
            assertNotNull("There should be one response item in the OCSP response", responseItems);
            assertEquals("There should be one response item in the OCSP response", 1, responseItems.length);
            responseExtension = responseItems[0].getExtension(new ASN1ObjectIdentifier(OcspCertHashExtension.CERT_HASH_OID));
            assertNotNull("No extension sent with reply in the responseItem", responseExtension);
        } finally {
            cesecoreConfigurationProxySession.setConfigurationValue(ALWAYSUSE_EXT, oldAlwaysUseExt);
            ocspResponseGeneratorSession.reloadOcspExtensionsCache();
            log.trace("<testUseAlwaysExtensions");
        }
    }
    
    /**
     * Tests ocsp message
     *
     * @throws Exception
     *           error
     */
    @Test
    public void test60OcspUnknownIsRevoked() throws Exception {
        log.trace(">test60OcspUnknownIsRevoked()");
        
        loadUserCert(this.caid);
        // An OCSP request for an unknown certificate (not exist in db)
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        final String bad1 = "Bad";
        final String bad2 = "Ugly";
        final String good1 = "Good";
        final String good2 = "Beautiful";
        final String revoked1 = "Revoked";
        final String revoked2 = "Denied";
        {
            final Map<String,String> map = new HashMap<String, String>();
            map.put(OcspConfiguration.NON_EXISTING_IS_REVOKED, "true");
            map.put(OcspConfiguration.NON_EXISTING_IS_BAD_URI+'1', ".*"+bad1+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_BAD_URI+'2', ".*"+bad2+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_GOOD_URI+'1', ".*"+good1+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_GOOD_URI+'2', ".*"+good2+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_REVOKED_URI+'1', ".*"+revoked1+"$");
            map.put(OcspConfiguration.NON_EXISTING_IS_REVOKED_URI+'2', ".*"+revoked2+"$");
            this.helper.alterConfig(map);
        }
        this.helper.reloadKeys();
        this.helper.verifyStatusRevoked( this.caid, this.cacert, new BigInteger("1"), CRLReason.certificateHold, new Date(0) );
        this.helper.setURLEnding(bad1);
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(bad2);
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(good1);
        this.helper.verifyStatusGood( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(good2);
        this.helper.verifyStatusGood( this.caid, this.cacert, new BigInteger("1") );
        {
            final Map<String,String> map = new HashMap<String, String>();
            map.put(OcspConfiguration.NON_EXISTING_IS_REVOKED, "false");
            this.helper.alterConfig(map);
        }
        this.helper.setURLEnding("");
        this.helper.verifyStatusUnknown( this.caid, this.cacert, new BigInteger("1") );
        this.helper.setURLEnding(revoked1);
        this.helper.verifyStatusRevoked( this.caid, this.cacert, new BigInteger("1"), CRLReason.certificateHold, new Date(0) );
        this.helper.setURLEnding(revoked2);
        this.helper.verifyStatusRevoked( this.caid, this.cacert, new BigInteger("1"), CRLReason.certificateHold, new Date(0) );

        log.trace("<test60OcspUnknownIsRevoked()");
    }

    
    /**
     * This test tests that the OCSP response contains the extension "id-pkix-ocsp-extended-revoke" in case the 
     * status of an unknown cert is returned as revoked.
     * 
     * @throws Exception
     */
    @Test
    public void testExtendedRevokedExtension() throws Exception {
        
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, new BigInteger("1") ));
        OCSPReq req = gen.build();
        BasicOCSPResp response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response);
        assertTrue(response.getResponses()[0].getCertStatus() instanceof UnknownStatus); 
        // RFC 6960: id-pkix-ocsp-extended-revoke OBJECT IDENTIFIER ::= {id-pkix-ocsp 9}
        Extension responseExtension = response.getExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp + ".9"));
        assertNull("Wrong extension sent with reply", responseExtension);
        
        final Map<String,String> map = new HashMap<String, String>();
        map.put(OcspConfiguration.NON_EXISTING_IS_REVOKED, "true");
        this.helper.alterConfig(map);
        
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, new BigInteger("1") ));
        req = gen.build();
        response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response);
        assertTrue(response.getResponses()[0].getCertStatus() instanceof RevokedStatus); 
        responseExtension = response.getExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp + ".9"));
        assertNotNull("No extension sent with reply", responseExtension);
        assertEquals(DERNull.INSTANCE, responseExtension.getParsedValue());
    }
    
    
    /**
     * This test tests that the OCSP response contains the extension "id_pkix_ocsp_archive_cutoff" if "ocsp.expiredcert.retentionperiod" 
     * is set in the condfiguration file
     * 
     * @throws Exception
     */
    @Test
    public void testExpiredCertArchiveCutoffExtension() throws Exception {
        
        final String username = "expiredCertUsername";
        String cpname = "ValidityCertProfile";
        String eepname = "ValidityEEProfile";
        X509Certificate xcert = null;
        
        CertificateProfileSessionRemote certProfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        EndEntityProfileSessionRemote eeProfSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        
        try {
            if (certProfSession.getCertificateProfile(cpname) == null) {
                final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
                cp.setAllowValidityOverride(true);
                try {
                    certProfSession.addCertificateProfile(admin, cpname, cp);
                } catch (CertificateProfileExistsException e) {
                    log.error("Certificate profile exists: ", e);
                }
            }
            final int cpId = certProfSession.getCertificateProfileId(cpname);
            if (eeProfSession.getEndEntityProfile(eepname) == null) {
                final EndEntityProfile eep = new EndEntityProfile(true);
                eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + cpId);
                try {
                    eeProfSession.addEndEntityProfile(admin, eepname, eep);
                } catch (EndEntityProfileExistsException e) {
                    log.error("Could not create end entity profile.", e);
                }
            }
            final int eepId = eeProfSession.getEndEntityProfileId(eepname);
        
            if (!endEntityManagementSession.existsUser(username)) {
                endEntityManagementSession.addUser(admin, username, "foo123", "CN=expiredCertUsername", null, "ocsptest@anatom.se", false,
                        eepId, cpId, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
                log.debug("created user: expiredCertUsername, foo123, CN=expiredCertUsername");
            } else {
                log.debug("User expiredCertUsername already exists.");
                EndEntityInformation userData = new EndEntityInformation(username, "CN=expiredCertUsername",
                        caid, null, "ocsptest@anatom.se", EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                        eepId, cpId, null, null, SecConst.TOKEN_SOFT_PEM, 0, null);
                userData.setPassword("foo123");
                endEntityManagementSession.changeUser(admin, userData, false);
                log.debug("Reset status to NEW");
            }
            
            // Generate certificate for the new user
            KeyPair keys = KeyTools.genKeys("512", "RSA");
            long now = (new Date()).getTime();
            long notAfter = now + 1000;
            xcert = (X509Certificate) signSession.createCertificate(admin, username, "foo123", 
                    new PublicKeyWrapper(keys.getPublic()), -1, new Date(), new Date(notAfter));
            assertNotNull("Failed to create new certificate", xcert);
        
            
            Thread.sleep(2000L); // wait for the certificate to expire
            
            // -------- Testing with default config value
            
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, xcert.getSerialNumber() ));
            OCSPReq req = gen.build();
            BasicOCSPResp response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
            assertNotNull("Could not retrieve response, test could not continue.", response);
            SingleResp resp = response.getResponses()[0];
            Extension singleExtension = resp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
            assertNotNull("No extension sent with reply", singleExtension);
        
            ASN1GeneralizedTime extvalue = ASN1GeneralizedTime.getInstance(singleExtension.getParsedValue());
            long expectedValue = (new Date()).getTime() - (31536000L * 1000);
            long actualValue = extvalue.getDate().getTime();
            long diff = expectedValue - actualValue;
            assertTrue("Wrong archive cutoff value.", diff < 60000);
            
            // -------- Send a request where id_pkix_ocsp_archive_cutoff SHOULD NOT be used
            // set ocsp configuration
            Map<String,String> map = new HashMap<String, String>();
            map.put(OcspConfiguration.EXPIREDCERT_RETENTIONPERIOD, "-1");
            this.helper.alterConfig(map);
        
            gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, xcert.getSerialNumber() ));
            req = gen.build();
            response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
            assertNotNull("Could not retrieve response, test could not continue.", response);
            resp = response.getResponses()[0];
            singleExtension = resp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
            assertNull("The wrong extension was sent with reply", singleExtension);
        
            
            // ------------ Send a request where id_pkix_ocsp_archive_cutoff SHOULD be used
            // set ocsp configuration
            map = new HashMap<String, String>();
            map.put(OcspConfiguration.EXPIREDCERT_RETENTIONPERIOD, "63072000"); // 2 years
            this.helper.alterConfig(map);
        
            gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, xcert.getSerialNumber() ));
            req = gen.build();
            response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
            assertNotNull("Could not retrieve response, test could not continue.", response);
            resp = response.getResponses()[0];
            singleExtension = resp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff);
            assertNotNull("No extension sent with reply", singleExtension);
        
            extvalue = ASN1GeneralizedTime.getInstance(singleExtension.getParsedValue());
            expectedValue = (new Date()).getTime() - (63072000L * 1000);
            actualValue = extvalue.getDate().getTime();
            diff = expectedValue - actualValue;
            assertTrue("Wrong archive cutoff value.", diff < 60000);
        
        } finally {
            endEntityManagementSession.revokeAndDeleteUser(admin, username, CRLReason.unspecified);
            eeProfSession.removeEndEntityProfile(admin, eepname);
            certProfSession.removeCertificateProfile(admin, cpname);
        }
    }

    
    /**
     * This test tests that the OCSP response for a status unknown contains the header "cache-control" with the value "no-cache, must-revalidate"
     * 
     * @throws Exception
     */
    @Test
    public void testUnknownStatusCacheControlHeader() throws Exception {
        
        // set ocsp configuration
        Map<String,String> map = new HashMap<String, String>();
        map.put(OcspConfiguration.UNTIL_NEXT_UPDATE, "1");
        this.helper.alterConfig(map);
        
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, new BigInteger("1") ));
        OCSPReq req = gen.build();
        
        String sBaseURL = httpReqPath + '/' + resourceOcsp;
        String urlEnding = "";
        String b64 = new String(Base64.encode(req.getEncoded(), false));
        //String urls = URLEncoder.encode(b64, "UTF-8");    // JBoss/Tomcat will not accept escaped '/'-characters by default
        URL url = new URL(sBaseURL + '/' + b64 + urlEnding);
        HttpURLConnection con = (HttpURLConnection)url.openConnection();
        if (con.getResponseCode() != 200) {
            log.info("URL when request gave unexpected result: " + url.toString() + " Message was: " + con.getResponseMessage());
        }
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        
        assertNotNull("No Cache-Control in reply.", con.getHeaderField("Cache-Control"));
        assertEquals("no-cache, must-revalidate", con.getHeaderField("Cache-Control"));
        
        // Create a GET request using Nonce extension, in this case we should have no cache-control header
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, new BigInteger("1") ));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        req = gen.build();        
        b64 = new String(Base64.encode(req.getEncoded(), false));
        url = new URL(sBaseURL + '/' + b64 + urlEnding);
        con = (HttpURLConnection)url.openConnection();
        if (con.getResponseCode() != 200) {
            log.info("URL when request gave unexpected result: " + url.toString() + " Message was: " + con.getResponseMessage());
        }
        assertEquals("Response code did not match. ", 200, con.getResponseCode());
        assertNotNull(con.getContentType());
        assertTrue(con.getContentType().startsWith("application/ocsp-response"));
        OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        byte[] noncerep = brep.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce).getExtnValue().getEncoded();
        // Make sure we have a nonce in the response, we should have since we sent one in the request
        assertNotNull("Response should have nonce since we sent a nonce in the request", noncerep);
        ASN1InputStream ain = new ASN1InputStream(noncerep);
        ASN1OctetString oct = ASN1OctetString.getInstance(ain.readObject());
        ain.close();
        assertEquals("Response Nonce was not the same as the request Nonce, it must be", "123456789", new String(oct.getOctets()));
        assertNull("Cache-Control in reply although we used Nonce in the request. Responses with Nonce should not have a Cache-control header.", con.getHeaderField("Cache-Control"));
    }
    
    /**
     * This test tests that the OCSP response contains is signed by the preferred signature algorithm specified in the request.
     * 
     * @throws Exception
    */
    @Test
    @Deprecated // This test verifies legacy behavior from EJBCA 6.1.0 and should be removed when we no longer need to support it
    public void testSigAlgExtensionLegacy() throws Exception {
        loadUserCert(this.caid);
        
        // Try sending a request where the preferred signature algorithm in the extension is expected to be used to sign the response.
        
        // set ocsp configuration
        Map<String,String> map = new HashMap<String, String>();
        map.put("ocsp.signaturealgorithm", AlgorithmConstants.SIGALG_SHA256_WITH_RSA + ";" + AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        this.helper.alterConfig(map);
        
        
        ASN1EncodableVector algVec = new ASN1EncodableVector();
        algVec.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        algVec.add(PKCSObjectIdentifiers.sha1WithRSAEncryption);
        ASN1Sequence algSeq = new DERSequence(algVec);
        ExtensionsGenerator extgen = new ExtensionsGenerator();
        // RFC 6960: id-pkix-ocsp-pref-sig-algs   OBJECT IDENTIFIER ::= { id-pkix-ocsp 8 } 
        extgen.addExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp + ".8"), false, algSeq);
        Extensions exts = extgen.generate();
        assertNotNull(exts);
        
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber() ), exts);
        gen.setRequestExtensions(exts);
        OCSPReq req = gen.build();
        assertTrue(req.hasExtensions());
        
        BasicOCSPResp response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response);
        assertEquals(PKCSObjectIdentifiers.sha1WithRSAEncryption, response.getSignatureAlgOID());
        
        
        // Try sending a request where the preferred signature algorithm is not compatible with the signing key, but 
        // the configured algorithm is. Expected a response signed using the first configured algorithm
        
        algVec = new ASN1EncodableVector();
        algVec.add(X9ObjectIdentifiers.ecdsa_with_SHA256);
        algSeq = new DERSequence(algVec);
        
        extgen = new ExtensionsGenerator();
        extgen.addExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp + ".8"), false, algSeq);
        exts = extgen.generate();
        assertNotNull(exts);
        
        gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber() ), exts);
        gen.setRequestExtensions(exts);
        req = gen.build();
        assertTrue(req.hasExtensions());
        
        response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response);
        assertEquals(PKCSObjectIdentifiers.sha256WithRSAEncryption, response.getSignatureAlgOID());
    }

    /** This test tests that the OCSP response contains is signed by the preferred signature algorithm specified in the request. */
    /* Example of the ASN.1 dump (with friendly names from the RFC added ) of what the extensions should look like.
     * 
     * Note that we have left out the optional
     *  PreferredSignatureAlgorithm.pubKeyAlgIdentifier
     * and
     *  AlgorithmIdentifier.parameters
     *  
     *               ...
     *  75  48:     requestExtensions [2] {
     *  77  46:       Extensions ::= SEQUENCE {
     *  79  44:         Extension ::= SEQUENCE {
     *  81   9:           extnID OBJECT IDENTIFIER '1 3 6 1 5 5 7 48 1 8'
     *  92  31:           extnValue OCTET STRING, encapsulates {
     *  94  29:             PreferredSignatureAlgorithms ::= SEQUENCE {
     *  96  12:               PreferredSignatureAlgorithm ::= SEQUENCE {
     *  98  10:                 sigIdentifier AlgorithmIdentifier ::= SEQUENCE {
     * 100   8:                   algorithm OBJECT IDENTIFIER
     *        :                     ecdsaWithSHA256 (1 2 840 10045 4 3 2)
     *        :                   }
     *        :                 }
     * 110  13:               PreferredSignatureAlgorithm ::= SEQUENCE {
     * 112  11:                 sigIdentifier AlgorithmIdentifier ::= SEQUENCE {
     * 114   9:                   algorithm OBJECT IDENTIFIER
     *        :                     sha1WithRSAEncryption (1 2 840 113549 1 1 5)
     *        :                   }
     *        :                 ...
     */
    @Test
    public void testSigAlgExtension() throws Exception {
        log.trace(">testSigAlgExtensionNew");
        loadUserCert(caid);
        // Try sending a request where the preferred signature algorithm in the extension is expected to be used to sign the response.
        // set ocsp configuration
        Map<String,String> map = new HashMap<String, String>();
        map.put("ocsp.signaturealgorithm", AlgorithmConstants.SIGALG_SHA256_WITH_RSA + ";" + AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        helper.alterConfig(map);
        final ASN1Sequence preferredSignatureAlgorithms = getPreferredSignatureAlgorithms(X9ObjectIdentifiers.ecdsa_with_SHA256, PKCSObjectIdentifiers.sha1WithRSAEncryption);
        final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        // RFC 6960: id-pkix-ocsp-pref-sig-algs   OBJECT IDENTIFIER ::= { id-pkix-ocsp 8 } 
        extensionsGenerator.addExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp + ".8"), false, preferredSignatureAlgorithms);
        final Extensions extensions = extensionsGenerator.generate();
        assertNotNull(extensions);
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        ocspReqBuilder.setRequestExtensions(extensions);
        OCSPReq ocspRequest = ocspReqBuilder.build();
        assertTrue(ocspRequest.hasExtensions());
        log.debug("base64 encoded request: " + new String(Base64.encode(ocspRequest.getEncoded(), false)));
        BasicOCSPResp response1 = helper.sendOCSPGet(ocspRequest.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response1);
        // We requested SHA1WithRSA in the request, and it is allowed, so we should expect that.
        assertEquals(PKCSObjectIdentifiers.sha1WithRSAEncryption, response1.getSignatureAlgOID());

        // Try not requesting any specific algorithm
        ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        ocspRequest = ocspReqBuilder.build();
        assertFalse(ocspRequest.hasExtensions());
        log.debug("base64 encoded request: " + new String(Base64.encode(ocspRequest.getEncoded(), false)));
        response1 = helper.sendOCSPGet(ocspRequest.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response1);
        // We didn't request any specific signature algorithm in the request, so we should expect the first suitable one, SHA256WithRSA.
        assertEquals(PKCSObjectIdentifiers.sha256WithRSAEncryption, response1.getSignatureAlgOID());
        
        // Test requesting SHA1WithRSA, but not having that as an available signature algorithm
        map = new HashMap<String, String>();
        map.put("ocsp.signaturealgorithm", AlgorithmConstants.SIGALG_SHA256_WITH_RSA + ";" + AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        helper.alterConfig(map);
        ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        ocspReqBuilder.setRequestExtensions(extensions);
        ocspRequest = ocspReqBuilder.build();
        assertTrue(ocspRequest.hasExtensions());
        log.debug("base64 encoded request: " + new String(Base64.encode(ocspRequest.getEncoded(), false)));
        response1 = helper.sendOCSPGet(ocspRequest.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response1);
        // We requested SHA1WithRSA, but it's not one of the available ones, so we should expect the first suitable one, SHA256WithRSA.
        assertEquals(PKCSObjectIdentifiers.sha256WithRSAEncryption, response1.getSignatureAlgOID());

    }

    /** Test with a preferred signature algorithm specified in the request that is incompatible with the singing key. */
    @Test
    public void testSigAlgExtensionMismatch() throws Exception {
        log.trace(">testSigAlgExtensionNewMismatch");
        loadUserCert(caid);
        final Map<String,String> map = new HashMap<String, String>();
        map.put("ocsp.signaturealgorithm", AlgorithmConstants.SIGALG_SHA256_WITH_RSA + ";" + AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
        helper.alterConfig(map);
        // Try sending a request where the preferred signature algorithm is not compatible with the signing key, but 
        // the configured algorithm is. Expected a response signed using the first configured algorithm
        final ASN1Sequence preferredSignatureAlgorithms = getPreferredSignatureAlgorithms(X9ObjectIdentifiers.ecdsa_with_SHA256);
        final ExtensionsGenerator extensionsGenerator = new ExtensionsGenerator();
        extensionsGenerator.addExtension(new ASN1ObjectIdentifier(OCSPObjectIdentifiers.id_pkix_ocsp + ".8"), false, preferredSignatureAlgorithms);
        final Extensions extensions = extensionsGenerator.generate();
        assertNotNull(extensions);
        final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        ocspReqBuilder.setRequestExtensions(extensions);
        final OCSPReq ocspRequest = ocspReqBuilder.build();
        assertTrue(ocspRequest.hasExtensions());
        log.debug("base64 encoded request: " + new String(Base64.encode(ocspRequest.getEncoded(), false)));
        final BasicOCSPResp response2 = helper.sendOCSPGet(ocspRequest.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
        assertNotNull("Could not retrieve response, test could not continue.", response2);
        assertEquals(PKCSObjectIdentifiers.sha256WithRSAEncryption, response2.getSignatureAlgOID());
    }

    /** @return a RFC 6960 PreferredSignatureAlgorithms object. */
    private ASN1Sequence getPreferredSignatureAlgorithms(final ASN1ObjectIdentifier...algorithmOids) {
        final ASN1Encodable[] asn1Encodables = new ASN1Encodable[algorithmOids.length];
        for (int i=0; i<algorithmOids.length; i++) {
            // PreferredSignatureAlgorithm ::= SEQUENCE { sigIdentifier AlgorithmIdentifier, pubKeyAlgIdentifier SMIMECapability OPTIONAL } 
            final ASN1Sequence preferredSignatureAlgorithm = new DERSequence(new ASN1Encodable[] { new AlgorithmIdentifier(algorithmOids[i]) });
            asn1Encodables[i] = preferredSignatureAlgorithm;
        }
        // PreferredSignatureAlgorithms ::= SEQUENCE OF PreferredSignatureAlgorithm 
        final ASN1Sequence preferredSignatureAlgorithms = new DERSequence(asn1Encodables);
        return preferredSignatureAlgorithms;
    }

    /**
     * This test tests that the OCSP response does not contain the signing cert if Ejbca is configured that way.
     * 
     * @throws Exception
     */
    @Test
    public void testSignCertNotIncludedInResponse() throws Exception {
        loadUserCert(this.caid);
        // set OCSP configuration
        Map<String,String> map = new HashMap<String, String>();
        map.put(OcspConfiguration.INCLUDE_SIGNING_CERT, "false");
        helper.alterConfig(map);
        // This setting is part of the OCSP signing cache so a reload of the cache is required
        helper.reloadKeys();
        // Build the OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber() ), null);
        OCSPReq req = gen.build();
        // Send and verify the OCSP request
        BasicOCSPResp response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200, false, cacert);
        assertNotNull("Could not retrieve response, test could not continue.", response);
        assertTrue("Response does contain certificates", response.getCerts().length == 0);
    }
    
    /**
     * This test tests that the OCSP response does not contain the root CA cert in the included certificate chain.
     * 
     * @throws Exception
     */
    @Test
    public void testRootCACertNotIncludedInResponse() throws Exception {
        log.trace(">testRootCACertNotIncludedInResponse()");
        
        // Create a subCA and a subsubCA
        String subcaDN = "CN=SubTestCA";
        createSubCA(subcaDN, caid);
        
        String subSubCaDN = "CN=SubSubTestCA";
        X509Certificate subSubCaCert = createSubCA(subSubCaDN, subcaDN.hashCode());
        
        // set OCSP configuration
        Map<String,String> map = new HashMap<String, String>();
        map.put(OcspConfiguration.INCLUDE_CERT_CHAIN, "true");
        GlobalOcspConfiguration ocspConfiguration = (GlobalOcspConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        ocspConfiguration.setOcspDefaultResponderReference(subSubCaDN);
        globalConfigurationSession.saveConfiguration(admin, ocspConfiguration);
        this.helper.alterConfig(map);
        helper.reloadKeys();
        
        // Expects an OCSP response including a certchain that contains only the 2 subCAs and not their rootCA.
        try { 
            loadUserCert(subSubCaDN.hashCode());
            
            OCSPReqBuilder gen = new OCSPReqBuilder();
            gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), subSubCaCert, ocspTestCert.getSerialNumber() ), null);
            OCSPReq req = gen.build();
                
            BasicOCSPResp response = helper.sendOCSPGet(req.getEncoded(), null, OCSPRespBuilder.SUCCESSFUL, 200);
            assertNotNull("Could not retrieve response, test could not continue.", response);
            assertTrue("Response contains more that 2 certificate", response.getCerts().length == 2);
                
            X509CertificateHolder[] includedCerts = response.getCerts();
            assertEquals(subSubCaDN, includedCerts[0].getSubject().toString());
            assertEquals(subcaDN, includedCerts[1].getSubject().toString());
    
        } finally {
            try {
                endEntityManagementSession.deleteUser(admin, "ocsptest");
            } catch (Exception e) {
                log.error("",e);
            }
            
            try {
                int cryptoTokenId = caSession.getCAInfo(admin, subSubCaDN.hashCode()).getCAToken().getCryptoTokenId();
                CryptoTokenTestUtils.removeCryptoToken(admin, cryptoTokenId);
                
                cryptoTokenId = caSession.getCAInfo(admin, subcaDN.hashCode()).getCAToken().getCryptoTokenId();
                CryptoTokenTestUtils.removeCryptoToken(admin, cryptoTokenId);
            } catch (Exception e) {
                log.error("",e);
            }
            
            try {
                caSession.removeCA(admin, subSubCaDN.hashCode());
                caSession.removeCA(admin, subcaDN.hashCode());
            } catch (Exception e) {
                log.info("Could not remove CA with SubjectDN " + subSubCaDN);
            }
        }
            
        log.trace("<testRootCACertNotIncludedInResponse()");
    }

    /**
     * Attempts to perform OCSP lookup on a certificate with limited meta data
     * @throws Exception
     */
    @Test
    public void testOcspLookupWithLimitedCertificateData() throws Exception {
        loadUserCert(this.caid);
        // Delete currently stored certificate
        internalCertStoreSession.removeCertificate(this.ocspTestCert);
        // Update database (same certificate) with limited meta data
        internalCertStoreSession.storeCertificateNoAuth(admin, 
                this.ocspTestCert, 
                null,
                "someOtherFingerprint", 
                CertificateConstants.CERT_ACTIVE, 
                CertificateConstants.CERTTYPE_ENDENTITY, 
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, 
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, 
                null, 
                System.currentTimeMillis());
        this.helper.reloadKeys();
        this.helper.verifyStatusGood(this.caid, this.cacert, this.ocspTestCert.getSerialNumber());
        
    }
    
    
    /**
     * removes DSA CA
     *
     * @throws Exception
     *           error
     */
    public void removeDSACA() throws Exception {
        assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection())
                .getResponseCode() == 200);
        try {
            if (caSession.existsCa(DSA_DN.hashCode())) {
                final int cryptoTokenId = caSession.getCAInfo(admin, DSA_DN.hashCode()).getCAToken().getCryptoTokenId();
                CryptoTokenTestUtils.removeCryptoToken(admin, cryptoTokenId);
            }
        } catch (Exception e) {
            log.error("", e);
        }
        try {
            if (caSession.existsCa(DSA_DN.hashCode())) {
                caSession.removeCA(admin, DSA_DN.hashCode());
            }
        } catch (Exception e) {
            log.info("Could not remove CA with SubjectDN " + DSA_DN);
        }
        try {
            if (caSession.existsCa("CN=OCSPDSAIMPCATEST".hashCode())) {
                caSession.removeCA(admin, "CN=OCSPDSAIMPCATEST".hashCode());
            }
        } catch (Exception e) {
            log.info("Could not remove CA with SubjectDN CN=OCSPDSAIMPCATEST");
        }
    }

    /**
     * removes ECDSA CA
     *
     * @throws Exception
     *           error
     */
    public void removeECDSACA() throws Exception {
        assertTrue("This test can only be run on a full EJBCA installation.", ((HttpURLConnection) new URL(httpReqPath + '/').openConnection())
                .getResponseCode() == 200);
        try {
            caSession.removeCA(admin, "CN=OCSPECDSATEST".hashCode());
        } catch (Exception e) {
            log.info("Could not remove CA with SubjectDN CN=OCSPECDSATEST");
        }
        try {
            caSession.removeCA(admin, "CN=OCSPECDSAIMPCATEST".hashCode());
        } catch (Exception e) {
            log.info("Could not remove CA with SubjectDN CN=OCSPECDSAIMPCATEST");
        }
    }

    //
    // Private helper methods
    //

    /**
     * Generate a simple OCSP Request object
     */
    private byte[] getValidOcspRequest() throws Exception {
        // Get user and ocspTestCert that we know...
        loadUserCert(caid);
        // And an OCSP request
        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), cacert, ocspTestCert.getSerialNumber()));
        Extension[] extensions = new Extension[1];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("123456789".getBytes()));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();
        return req.getEncoded();
    }

    /**
     * Sends the payload to the OCSP Servlet using TCP. Can be used for testing
     * malformed or malicious requests.
     *
     * @param contentLength
     *          The HTTP 'Content-Length' header to send to the server.
     * @return the OCSP Response from the server
     * @throws IOException
     *           if the is a IO problem
     */
    private OCSPResp sendRawRequestToOcsp(int contentLength, byte[] payload, final boolean writeByteByByte) throws IOException {
        // Create the HTTP header
        String headers = "POST " + "/ejbca/" + resourceOcsp + " HTTP/1.1\r\n" + "Host: "+httpHost+"\r\n" + "Content-Type: application/ocsp-request\r\n"
                + "Content-Length: " + contentLength + "\r\n" + "\r\n";
        // Merge the HTTP headers, the OCSP request and the raw data into one
        // package.
        byte[] input = concatByteArrays(headers.getBytes(), payload);
        log.debug("HTTP request headers: " + headers);
        log.debug("HTTP headers size: " + headers.getBytes().length);
        log.debug("Size of data to send: " + input.length);
        // Create the socket.
        Socket socket = new Socket(InetAddress.getByName(httpHost), Integer.parseInt(httpPort));
        socket.setSoTimeout(120*1000); // The write() call can block for hours if the server doesn't read the data and/or silently drops the connection
        // Send data byte for byte.
        OutputStream os = socket.getOutputStream();
        if (writeByteByByte) {
            int i = 0;
            try {
                for (i = 0; i < input.length; i++) {
                    os.write(input[i]);
                }
            } catch (IOException e) {
                log.info("Socket wrote " + i + " bytes before throwing an IOException.");
            }
        } else {
            try {
                os.write(input);
            } catch (IOException e) {
                log.info("Could not write to TCP Socket " + e.getMessage());
            }
        }
        // Reading the response.
        byte rawResponse[] = getHttpResponse(socket.getInputStream());
        log.info("Response contains: " + rawResponse.length + " bytes.");
        socket.close();
        return new OCSPResp(rawResponse);
    }

    /**
     * Read the payload of a HTTP response as a byte array.
     */
    private byte[] getHttpResponse(InputStream ins) throws IOException {
        byte buf[] = IOUtils.toByteArray(ins);
        ins.close();
        int i = 0;
        // Removing the HTTP headers. The HTTP headers end at the last
        // occurrence of "\r\n".
        for (i = buf.length - 1; i > 0; i--) {
            if ((buf[i] == 0x0A) && (buf[i - 1] == 0x0D)) {
                break;
            }
        }
        byte[] header = ArrayUtils.subarray(buf, 0, i + 1);
        log.debug("HTTP reponse header: " + new String(header));
        log.debug("HTTP reponse header size: " + header.length);
        log.debug("Stream length: " + buf.length);
        log.debug("HTTP payload length: " + (buf.length - header.length));
        return ArrayUtils.subarray(buf, header.length, buf.length);
    }

    /**
     * @return a new byte array with the two arguments concatenated.
     */
    private byte[] concatByteArrays(byte[] array1, byte[] array2) {
        byte[] ret = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, ret, 0, array1.length);
        System.arraycopy(array2, 0, ret, array1.length, array2.length);
        return ret;
    }

    /**
     * adds a CA Using ECDSA keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception
     *           error
     */
    private CAInfo addECDSACA(String dn, String keySpec) throws Exception {
        log.trace(">addECDSACA()");
        boolean ret = false;
        int cryptoTokenId = 0;
        CAInfo info = null;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(admin, dn, keySpec);
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
            policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));

            X509CAInfo cainfo = new X509CAInfo(dn, dn, CAConstants.CA_ACTIVE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
            cainfo.setDescription("JUnit ECDSA CA");
            cainfo.setPolicies(policies);
            cainfo.setExtendedCAServiceInfos(extendedcaservices);
            caAdminSession.createCA(admin, cainfo);

            info = caSession.getCAInfo(admin, dn);

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertTrue("Error in created ca certificate", cert.getSubjectDN().toString().equals(dn));
            assertTrue("Creating CA failed", info.getSubjectDN().equals(dn));
            // Make BC cert instead to make sure the public key is BC provider type (to make our test below easier)
            X509Certificate bccert = CertTools.getCertfromByteArray(cert.getEncoded(), X509Certificate.class);
            PublicKey pk = bccert.getPublicKey();
            if (pk instanceof JCEECPublicKey) {
                JCEECPublicKey ecpk = (JCEECPublicKey) pk;
                assertEquals(ecpk.getAlgorithm(), "EC");
                org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
                if (StringUtils.equals(keySpec, "implicitlyCA")) {
                    assertNull("ImplicitlyCA must have null spec", spec);
                } else {
                    assertNotNull("secp256r1 must not have null spec", spec);
                }
            } else if (pk instanceof BCECPublicKey) {
                BCECPublicKey ecpk = (BCECPublicKey) pk;
                assertEquals(ecpk.getAlgorithm(), "EC");
                org.bouncycastle.jce.spec.ECParameterSpec spec = ecpk.getParameters();
                if (StringUtils.equals(keySpec, "implicitlyCA")) {
                    assertNull("ImplicitlyCA must have null spec", spec);
                } else {
                    assertNotNull("secp256r1 must not have null spec", spec);
                }               
            } else {
                assertTrue("Public key is not EC: "+pk.getClass().getName(), false);
            }

            ret = true;
        } catch (CAExistsException pee) {
            log.info("CA exists.");
        }
        assertTrue("Creating ECDSA CA failed", ret);
        log.trace("<addECDSACA()");
        return info;
    }

    /**
     * adds a CA Using DSA keys to the database.
     *
     * It also checks that the CA is stored correctly.
     *
     * @throws Exception
     *           error
     */
    private X509Certificate addDSACA(String dn, String keySpec) throws Exception {
        log.trace(">addDSACA()");
        boolean ret = false;
        X509Certificate cacert = null;
        int cryptoTokenId = 0;
        try {
            cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(admin, dn, keySpec);
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_DSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
            policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));

            X509CAInfo cainfo = new X509CAInfo(dn, dn, CAConstants.CA_ACTIVE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "365d", CAInfo.SELFSIGNED, null, catoken);
            cainfo.setDescription("JUnit DSA CA");
            cainfo.setPolicies(policies);
            caAdminSession.createCA(admin, cainfo);

            CAInfo info = caSession.getCAInfo(admin, dn);

            X509Certificate cert = (X509Certificate) info.getCertificateChain().iterator().next();
            assertEquals("Error in created ca certificate", dn, CertTools.getSubjectDN(cert));
            assertEquals("Creating CA failed, DN was incorrect.", dn, info.getSubjectDN());
            assertTrue("Public key was not an instance of DSAPublicKey", cert.getPublicKey() instanceof DSAPublicKey);

            ret = true;
            Collection<Certificate> coll = info.getCertificateChain();
            Object[] certs = coll.toArray();
            cacert = (X509Certificate) certs[0];
        } catch (CAExistsException e) {
            log.info("CA exists.");
            throw e;
        }
        assertTrue("Creating DSA CA failed", ret);
        log.trace("<addDSACA()");
        return cacert;
    }
    
    private X509Certificate createSubCA(String subcaDN, int signbyID) throws CryptoTokenOfflineException, 
                    CryptoTokenAuthenticationFailedException, InvalidAlgorithmException, AuthorizationDeniedException, 
                    CADoesntExistsException, CAExistsException {
        try {
            int cryptoTokenId = CryptoTokenTestUtils.createCryptoTokenForCA(admin, subcaDN, "1024");
            final CAToken catoken = CaTestUtils.createCaToken(cryptoTokenId, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, AlgorithmConstants.SIGALG_SHA1_WITH_RSA);
            // Create and active OSCP CA Service.
            final List<ExtendedCAServiceInfo> extendedcaservices = new ArrayList<ExtendedCAServiceInfo>();
            extendedcaservices.add(new HardTokenEncryptCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            extendedcaservices.add(new KeyRecoveryCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE));
            final List<CertificatePolicy> policies = new ArrayList<CertificatePolicy>(1);
            policies.add(new CertificatePolicy("2.5.29.32.0", "", ""));
            
            X509CAInfo cainfo = new X509CAInfo(subcaDN, subcaDN, CAConstants.CA_ACTIVE,
                    CertificateProfileConstants.CERTPROFILE_FIXED_SUBCA, "365d", signbyID, null, catoken);
            cainfo.setDescription("JUnit DSA CA");
            cainfo.setPolicies(policies);
            cainfo.setExtendedCAServiceInfos(extendedcaservices);    
            caAdminSession.createCA(admin, cainfo);
            
            CAInfo info = caSession.getCAInfo(admin, subcaDN);
                
            return (X509Certificate) info.getCertificateChain().iterator().next();
        } catch (CAExistsException e) {
            log.info("CA exists.");
            throw e;
        }
    }
    

    /**
     * This method creates the user "ocsptest" and generated a certificate for it
     */
    protected void loadUserCert(int caid) throws Exception {
        createUserCert(caid);
    }

    private KeyPair createUserCert(int caid) throws AuthorizationDeniedException, EndEntityProfileValidationException, ApprovalException,
            WaitingForApprovalException, Exception, ObjectNotFoundException, AuthStatusException, AuthLoginException, IllegalKeyException,
            CADoesntExistsException {
        final String USERNAME = "ocsptest";
        if (!endEntityManagementSession.existsUser(USERNAME)) {

            endEntityManagementSession.addUser(admin, USERNAME, "foo123", "C=SE,O=AnaTom,CN=OCSPTest", null, "ocsptest@anatom.se", false,
                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caid);
            log.debug("created user: ocsptest, foo123, C=SE, O=AnaTom, CN=OCSPTest");

        } else {
            log.debug("User ocsptest already exists.");
            EndEntityInformation userData = new EndEntityInformation(USERNAME, "C=SE,O=AnaTom,CN=OCSPTest",
                    caid, null, "ocsptest@anatom.se", EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, null, null, SecConst.TOKEN_SOFT_PEM, 0,
                    null);
            userData.setPassword("foo123");
            endEntityManagementSession.changeUser(admin, userData, false);
            log.debug("Reset status to NEW");
        }
        // Generate certificate for the new user
        KeyPair keys = KeyTools.genKeys("512", "RSA");

        // user that we know exists...
        ocspTestCert = (X509Certificate) signSession.createCertificate(admin, USERNAME, "foo123", new PublicKeyWrapper(keys.getPublic()));
        assertNotNull("Failed to create new certificate", ocspTestCert);
        return keys;
    }

    /** Checks the signature on an OCSP request and checks that it is signed by an allowed CA.
     * Does not check for revocation of the signer certificate
     * 
     * @param clientRemoteAddr The ip address or hostname of the remote client that sent the request, can be null.
     * @param req The signed OCSPReq
     * @param cacerts a CertificateCache of Certificates, the authorized CA-certificates. The signer certificate must be issued by one of these.
     * @return X509Certificate which is the certificate that signed the OCSP request
     * @throws SignRequestSignatureException if signature verification fail, or if the signing certificate is not authorized
     * @throws SignRequestException if there is no signature on the OCSPReq
     * @throws OCSPException if the request can not be parsed to retrieve certificates
     * @throws NoSuchProviderException if the BC provider is not installed
     * @throws CertificateException if the certificate can not be parsed
     * @throws NoSuchAlgorithmException if the certificate contains an unsupported algorithm
     * @throws InvalidKeyException if the certificate, or CA key is invalid
     * @throws OperatorCreationException 
     */
    public static X509Certificate checkRequestSignature(String clientRemoteAddr, OCSPReq req, CaCertificateCache cacerts) throws SignRequestException,
            OCSPException, NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException,
            SignRequestSignatureException, OperatorCreationException {
        
        X509Certificate signercert = null;
        
        if (!req.isSigned()) {
            String infoMsg = intres.getLocalizedMessage("ocsp.errorunsignedreq", clientRemoteAddr);
            log.info(infoMsg);
            throw new SignRequestException(infoMsg);
        }
        // Get all certificates embedded in the request (probably a certificate chain)
        X509CertificateHolder[] certs = req.getCerts();
        // Set, as a try, the signer to be the first certificate, so we have a name to log...
        String signer = null;
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        if (certs.length > 0) {
            signer = CertTools.getSubjectDN(converter.getCertificate(certs[0]));
        }
        
        // We must find a cert to verify the signature with...
        boolean verifyOK = false;
        for (int i = 0; i < certs.length; i++) {
            if (req.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(certs[i])) == true) {
                signercert = converter.getCertificate(certs[i]);
                signer = CertTools.getSubjectDN(signercert);
                Date now = new Date();
                String signerissuer = CertTools.getIssuerDN(signercert);
                String infoMsg = intres.getLocalizedMessage("ocsp.infosigner", signer);
                log.info(infoMsg);
                verifyOK = true;
                // Also check that the signer certificate can be verified by one of the CA-certificates
                // that we answer for
                X509Certificate signerca = cacerts.findLatestBySubjectDN(HashID.getFromIssuerDN(certs[i]));
                String subject = signer;
                String issuer = signerissuer;
                if (signerca != null) {
                    try {
                        signercert.verify(signerca.getPublicKey());
                        if (log.isDebugEnabled()) {
                            log.debug("Checking validity. Now: "+now+", signerNotAfter: "+signercert.getNotAfter());                  
                        }
                        CertTools.checkValidity(signercert, now);
                        // Move the error message string to the CA cert
                        subject = CertTools.getSubjectDN(signerca);
                        issuer = CertTools.getIssuerDN(signerca);
                        CertTools.checkValidity(signerca, now);
                    } catch (SignatureException e) {
                        infoMsg = intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", subject, issuer, e.getMessage());
                        log.info(infoMsg);
                        verifyOK = false;
                    } catch (InvalidKeyException e) {
                        infoMsg = intres.getLocalizedMessage("ocsp.infosigner.invalidcertsignature", subject, issuer, e.getMessage());
                        log.info(infoMsg);
                        verifyOK = false;
                    } catch (CertificateNotYetValidException e) {
                        infoMsg = intres.getLocalizedMessage("ocsp.infosigner.certnotyetvalid", subject, issuer, e.getMessage());
                        log.info(infoMsg);
                        verifyOK = false;
                    } catch (CertificateExpiredException e) {
                        infoMsg = intres.getLocalizedMessage("ocsp.infosigner.certexpired", subject, issuer, e.getMessage());
                        log.info(infoMsg);
                        verifyOK = false;
                    }                               
                } else {
                    infoMsg = intres.getLocalizedMessage("ocsp.infosigner.nocacert", signer, signerissuer);
                    log.info(infoMsg);
                    verifyOK = false;
                }
                break;
            }
        }
        if (!verifyOK) {
            String errMsg = intres.getLocalizedMessage("ocsp.errorinvalidsignature", signer);
            log.info(errMsg);
            throw new SignRequestSignatureException(errMsg);
        }
        
        return signercert;
    }
    
}
