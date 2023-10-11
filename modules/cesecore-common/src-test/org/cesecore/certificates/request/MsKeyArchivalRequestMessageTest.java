/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.request;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.asn1.cmc.CMCObjectIdentifiers;
import org.bouncycastle.asn1.cmc.CMCStatus;
import org.bouncycastle.asn1.cmc.CMCStatusInfoBuilder;
import org.bouncycastle.asn1.cmc.PKIResponse;
import org.bouncycastle.asn1.cmc.TaggedAttribute;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.PKCS7ProcessableObject;
import org.bouncycastle.cms.SimpleAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.request.MsKeyArchivalRequestMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.keys.KeyPairWrapper;
import com.keyfactor.util.keys.KeyTools;

public class MsKeyArchivalRequestMessageTest {
    
    private static final String SAMPLE_REQUEST = "308208a906092a864886f70d010702a082089a30820896020103310b300906052b0e0"
            + "3021a0500308203e506082b06010505070c02a08203d7048203d3308203cf3081a030819d020102060a2b0601040182370a0a013"
            + "1818b3081880201003003020101317e302306092b0601040182371515311604147746e7e66bb597a67d08bf6e059c79e16dd66b8"
            + "3305706092b0601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f6"
            + "6742e636f6d0c154a444f4d4353435c61646d696e6973747261746f720c076365727472657130820324a08203200201013082031"
            + "9308202820201003023310f300d0603550403130654657374434e3110300e060355040a1307546573744f726730819f300d06092"
            + "a864886f70d010101050003818d0030818902818100dab2cc813700c9c8a0903da0f6b7a76880bf43441962fd9b713249c0b0a34"
            + "554d1e524c1cde3e6458a2de53fefcd7eebbc68de7488117661f37765c69c54ee546df9e59bc7ec8215bd6b15889793ec0d0aefa"
            + "85ede0ce794e07de73d44a4771dbdd803dfbfb489a1883c8572e336967ce07fe4ac848a696e02690be453fb2c950203010001a08"
            + "201b4301a060a2b0601040182370d0203310c160a362e302e353336312e323042060a2b0601040182370d0201313430321e26004"
            + "3006500720074006900660069006300610074006500540065006d0070006c0061007400651e080055007300650072305706092b0"
            + "601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f66742e636f6d0"
            + "c154a444f4d4353435c61646d696e6973747261746f720c07636572747265713074060a2b0601040182370d02023166306402010"
            + "11e5c004d006900630072006f0073006f0066007400200045006e00680061006e006300650064002000430072007900700074006"
            + "f0067007200610070006800690063002000500072006f00760069006400650072002000760031002e003003010030818206092a8"
            + "64886f70d01090e31753073301706092b0601040182371402040a1e08005500730065007230290603551d2504223020060a2b060"
            + "1040182370a030406082b0601050507030406082b06010505070302300e0603551d0f0101ff0404030205a0301d0603551d0e041"
            + "6041415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300d06092a864886f70d0101050500038181006ac9bc0cf7675e9161c78"
            + "ce7df37dc5fcc59cb38c071e61748cbf1d615f28161a330a8242f5d661094d3813445dffa3963ffc617a84ae545f9e814e2aaf4e"
            + "50cde845cf279c5e4419180b975d50c0df708c2adc790be8ff51f9d47e4b750ffaf40b6e21a9986d864dce2d4e41d82c66eab458"
            + "c7be3b5dcd8feaf9978cb1b7086300030003182049930820495020103801415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300"
            + "906052b0e03021a0500a03e301706092a864886f70d010903310a06082b06010505070c02302306092a864886f70d01090431160"
            + "414e088afba3f9bde527ff0887fced97debfa363f72300d06092a864886f70d01010105000481804505b61926013cc202172d9e1"
            + "d194df8ff4358e5544a24525b93e636005bbaaebfbc70d9c7f5d149e9e36ebdb7ac33c9147a81b59eb1a97c2287588b9028874f8"
            + "65b016ecb6fde4a6689e6e5bcaed259b5882381a552a071f0b0d457b8ac64fca03b7bbd8a5e571a711c4705708f27bc7a25beda7"
            + "910d083e08ac3f8d1ff513aa182039b3082039706092b060104018237150d318203883082038406092a864886f70d010703a0820"
            + "375308203710201003181ea3081e70201003050304231123010060355040a13094d6963726f736f6674312c302a0603550403132"
            + "34a444f4d435343204c6f6e67686f726e20456e746572707269736520526f6f74204341020a488a9b22000000000a39300d06092"
            + "a864886f70d0101010500048180960b583191d1fdd1ee45ccfa7a368ca09fb52df2a07def463b1a33a3bf861f00fb3b237cdb504"
            + "e5303e9c147a0186e4bba4a63df419395e6d56b03b117363adba12870f814c45d9e5e4414ae4947e22f357c9e8d9245c9fbe0bc3"
            + "8c9d674cdd93eaf70664476b9943c980b717a5a363ba72d45aa3d816eaf42a89631b1a76d263082027d06092a864886f70d01070"
            + "1301406082a864886f70d030704086cd44389e15a7fc380820258fae61aa513fcae9caefc78fe0b8f0698dcc5f3fd71e29a17488"
            + "65f30edcc4631a90ebead68ff6cfe7ecf6bfdeb647cde6eafe1a9956782388e0c9011f0fb976489701fdd38b3fddf73bf90e39f2"
            + "b11d664798ec3571264fea37c47958860c2193f454cbb48273f1db3b45c800161a4b677b27e22039418181b38e86ef01379c219f"
            + "54e43f5131ea035a9a9fdf2cf14ab2ab41618c0b6fd43d8a9672ee1a7d587a27d8460ecfe441c74cc2c7a9c2272a5d944d154185"
            + "bfc6bfef08bfd09dbe76100fe2abb421c549099df83f1915d22076fcc908445206fc3ed97b243adae5eabdcab69f857aefbb37b4"
            + "e1381b134a0171774e921d1a76870d6f69639924fe26f88ca6d318db267043e39234d1eefcbc8ef34ded1a02a95c3aec792ee136"
            + "cdeeb72e02cbb7b721d03df60c5bfae61bbf7742a0f1855c1c83652cfbf2c5b7704d7615524b85ce13851dd909d6bfd55644d7bf"
            + "045b660f998f1026a74841b4f9016945924988c84c0459f9bea120ebff3ac629f254e1281f5b5f9a0fb3add3883b87753672104b"
            + "6b2bf580cdf64b9da6cd51391a1e4dc007a527e9e6be1ee8ab4eb6349babc605a5de21f62949ee1e7773e12c607d0cb5bd4e33b6"
            + "5ac0ce0cd413af1072f3b8dea07fbe9bdcde0ba1f93767cac5276f48224eaddf8b4cff3a8cdbfe8d7fa9281bc549486533edd218"
            + "5344660ddc0af797887e2a322e52d6cb250211482260b369a0bd0897c93f763671e72ea2470916c68902fb6e687f4e7f0d1eec87"
            + "c1b15a5a978d24d10362ad4e67494c267d02f987815e735ac1e723101baae7e6e7c5154693c5cbd023289392fffdb58644971dfc"
            + "7f8fb";
    
    private static final String USER_ENROLL_REQ = "MIILxgYJKoZIhvcNAQcCoIILtzCCC7MCAQMxCzAJBgUrDgMCGgUAMIID5AYIKwYBBQUHDAKgggPW\n"
            + "BIID0jCCA84wRDBCAgECBgorBgEEAYI3CgoBMTEwLwIBADADAgEBMSUwIwYJKwYBBAGCNxUVMRYE\n"
            + "FHTq+BCMi8bi+6comXW0QM4pPQN/MIIDgKCCA3wCAQEwggN1MIICXQIBADAAMIIBIjANBgkqhkiG\n"
            + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyefeFHvL2mMbgWOxaK1AzOWZJxD7uHRxjShFfqPg2YrLF2O\n"
            + "QtAPHDw+qlpPIVpS2UWMKM3vdi379Khq8kQUqjREZN+Z74e8M9SY6gHatWRvIruuVqvwTf6j5NR9\n"
            + "iATJq/SkvYD9myciGMkBkDRW9GF+wyXyIZKKr1/wwkpV/Fy0cScM1FeHUYRNBbha9Z4AY9ss22rT\n"
            + "ud5zd1zOxH9L4ORU2VKLLkEkAbyhYrw+MQ+2qTuxa4/HFsEQkZYHOaWAkdTgGxxIZlWToVx7Iixw\n"
            + "TxJ2dJMvv7erL7X32WTFPae4gnT9SAYXJlG3Y8E6qwWjW9g9vFDmfwtrs967U1Gz+QIDAQABoIIB\n"
            + "LjCCASoGCSqGSIb3DQEJDjGCARswggEXMD4GCSsGAQQBgjcVBwQxMC8GJisGAQQBgjcVCIWfoX+C\n"
            + "gJ5Kg6WFGYXI6iaE/JsggQCF9M9h7O17AgFkAgIAhzApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYB\n"
            + "BQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYB\n"
            + "BQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3\n"
            + "DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFIT2\n"
            + "cd3X4rhRDxPdRi2c7VyUqvIuMA0GCSqGSIb3DQEBBQUAA4IBAQC9qxJGCaLa1AzsprRYeAYfHNac\n"
            + "pyYBaKpQ2PfMENWJrasFveiVWznnZ97xr3TIEy7ameqKFjIcBuVxfs6wYOceYc3336dlfgtja5AQ\n"
            + "YxITfcS5jQnuBm/It7B+HUk7HhtnAJYvMoDd9a6hTMK2FTjwNGGnqiOKio77AV2frGOcoJMThFrG\n"
            + "shmmxs6RfGHs3sGrV2PkV6wP9/kW+PqxAExATwdnyAYiDnMYnaYJ0TU/DNlfAYTKYtHEMeAvNs3/\n"
            + "oAWHqyNip3je77YwGBFpNOxIGZj3HHjq/+iDuUKhyMJQWblRPlyBDZaDF8nrcly0UwhJ4F23X+CL\n"
            + "zBAAPCkr3KleMAAwADGCB7cwggezAgEDgBSE9nHd1+K4UQ8T3UYtnO1clKryLjAJBgUrDgMCGgUA\n"
            + "oD4wFwYJKoZIhvcNAQkDMQoGCCsGAQUFBwwCMCMGCSqGSIb3DQEJBDEWBBQzyRIZsqNBxOo6TnRN\n"
            + "a0UZOTccCjANBgkqhkiG9w0BAQEFAASCAQA2oKo1eN4a6AhBK1L/+hEuylnhd5XuPywyPTRNL/6Y\n"
            + "YFSkDLuju3s8mdhKubjBywLrcYmaIEkA+993p5fIgLDZMga6dgjR4lWdIIKUiM8emgGkXEUaNY0/\n"
            + "WbJa7Oy0LkAPk0RZLCx1jx5SWRuEdGd09lXQj4300QR+WA/9m/YAS7sTYbAWq+GHJjEyq8FeSTC/\n"
            + "K6Ya2hadsNsPbjo6fxYln1wPQCilCGPBvd02gywzHytpUr2aSih32Lqc8BgKjAfQsU9/f/TwYDzv\n"
            + "rpDQ/dnmjqKrhsO7zGZEabNREnzg/ByWb51hOyiMbOaW1ziACZIxlcQevb0aXZhVownZZGEzoYIG\n"
            + "ODCCBjQGCSsGAQQBgjcVDTGCBiUwggYhBgkqhkiG9w0BBwOgggYSMIIGDgIBADGCAUYwggFCAgEA\n"
            + "MCowEjEQMA4GA1UEAwwHSXNzdWVyMgIUV94OYm2LhjYpuvwHNneFoeIxlzcwDQYJKoZIhvcNAQEB\n"
            + "BQAEggEACrB20EQZHUFzmCa8dTjeOu4UQmqqxoMPYBmhfVRbo4TOg1M9skACm0t8GCz4BZOFLhLt\n"
            + "3YRtKaqtsRruX/8BoiXgPE2ZHIafxuAlV/lE87n3QmONPyDHa4Oxpi/nr1uRPZunsQtQabdwg/iI\n"
            + "Dnfj5IE88j/eFsR/9ASqvXydxc1yDdy3w+uRdKCFpUpVN4r5AJbBnTtv5Qi/af7WYpAd3R9VHD9x\n"
            + "HEkVr4QMxUQdKFyKttsh2Eazwp8DqxdAwpLZbX6owsjjKRmfEh0NJ5/mYgSHn54oIR0mkh0OV2eX\n"
            + "b2Ldc8HtzfdM5PB+VjMCaVGbfA/OQ1dZ0XhGCItJswvvUjCCBL0GCSqGSIb3DQEHATAUBggqhkiG\n"
            + "9w0DBwQIhFSQv9FSE4+AggSYAFS2f2KP/is70pDZ/FkMdgA4gOn9ytWg4PxnO3A3XPnOcaz7o2d3\n"
            + "Rsm+wYkjMrh40X1uF3iPbJ+Rq90UHaAiP2EX/5d8KZxWW5crLc2FC3IPmW2LhoF2Ev6wGDA+VDVy\n"
            + "47r2SbOLF8od9L0Hi42We/cBrWzKSkKIWXcA5Nml06TCT3N+8FAjMB5YsnMTTK7gpQFFaJc9xma5\n"
            + "tLxTtYhN7SVK/EvpiRn2HMVQHv5fU61q9YJzCPENOIBSMf4jqMBw4dzpEZ8uzLz2osiC3KQLzdhF\n"
            + "Hkhe1spVe2aSlhdTb05JM0gHOA8MV5X8D6ViGGwX96zE8bI+dPZQMy10rL01KcwUgStAWAOu4uK2\n"
            + "N7j60uFXPYWgoaxF/BN5T6dQkbrnjJCQ98ppMbvo489e+WQKHmSKiLurrPo/E6zlZIJjOd2ALGfc\n"
            + "aODFOnNyh0PLp4W7WYKTCNxC8sKs1BDyVXm7B1Jwls1eG38+g6uzRPGDqZ/Ya8SMNX5ar3Q8MY4m\n"
            + "LxY7daxkxMa9FaOuprHVVW+VUtw2/YiBeHMwjevD2K8jjpV1BZ61TOMsddpoKNZj5fKmnQZXc+9H\n"
            + "zLX5gAko7oAQLuIfvYKCSvfzA+uAes6TFnTRipOa35xTygHK+aReAZrF3m+Jo85R2WfhV1ExnIUi\n"
            + "0DHEgEaKO+IxegAIjvun7zb0VvCeGcxvhGBwxPQ09bO13l5/L8LwIIUlW0+gd2aCfCXrwXl2eu9J\n"
            + "wodCnxd2XyEwmYTgbYJcnmpWH0STBIfUFy0VZxyOOaKJcF716LtddeZLw4M1P4tgv9ncT2kU+VpB\n"
            + "PmndzanSActIuFUln3TyFHtv/dugBS2KW2XbbboPlbLhE/yoNU0VYhd/j5jMfxeLiRDEKJe0ZcEt\n"
            + "yANHV0GCLoWc0o6kI3eTvKyl8D2FVurHHer8MCBHtrVxdf31/VHyfn03DJkylpwyBzP6ZOOSH3Uy\n"
            + "lKlD6B7S7ZdzZvMOfh/PCEKDFuVSOdbk2m+E6MoXwFWpPZ8t0m9WDwKPMa/Lp8jZprhhiMOVKp4V\n"
            + "mNxRVg9qnsnNO8WC1IjD/18XHWnNACK4IezQpIJt7cbV1Fd7LJG6RrbsEW5BZUK6FSErUXVM6LX5\n"
            + "KRRHyzrEUMOZag2ZH9RZU8KuolaOoXYjlHrPTD6ve7NSb4vkqfd7z7kqmqIC2wYEInzUV7kUU9Cz\n"
            + "M9BiFokCz+OI6xQlj7beZADYx8P+DIwS9EYHYYeDIbflkDAsMctRBePup/VdLp0c6CusfB2wxzpj\n"
            + "cPQTEJUYX4y2vV/pEbB7Q2dceA857Drk4pJLuEfxqzD8rIA1ldVkB7tXH4Fxdp7ldiHajBOzSgsc\n"
            + "PsCyKZy+nrKAClmcW6s6IIFEvOSKEAhfqZjwJT6mJe1Eib+XZZXnfwaxmlJdSuVaEeGevBwcWOd3\n"
            + "90q7jQ8J8cUntumeRHzf6zupN1d2dtofzfmaK/b8NGuJykPmbCTESRGEVvvi0p4i368rjt6Khapn\n"
            + "uIgC30ELUt0UuRV+igTa9fWviHv4D+cFkdJ7mEAG+Z64sN1rfzaBQyj9/qSXK1yTfqfqR7jW";
    
    private static final String COMPUTER_ENROLL = "MIILZQYJKoZIhvcNAQcCoIILVjCCC1ICAQMxCzAJBgUrDgMCGgUAMIIDgAYIKwYBBQUHDAKgggNy\n"
            + "BIIDbjCCA2owRDBCAgECBgorBgEEAYI3CgoBMTEwLwIBADADAgEBMSUwIwYJKwYBBAGCNxUVMRYE\n"
            + "FEfFGGTPflFnpDNk8dqpgdFmAQKBMIIDHKCCAxgCAQEwggMRMIIB+QIBADAAMIIBIjANBgkqhkiG\n"
            + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqSIUwK3Y9NgBbE4e4nerw7TTSc5qdWs+SxmGXpWUXce2GTQw\n"
            + "d77HOCv3iBd8tAGTZGnFs4LvSF3q75iCFzwdhBYU0Fupzdgta3WOHRdJ2VK0VFAkJF2khVdLhwMP\n"
            + "5wyq5fnB3NrlNS6TgKOY1NDSyO4a0Z22gb2reu0CbYVVP3O0RNlbywsi7ID7cp5TWpTl26500h5G\n"
            + "rZ2exqGC7O/Tjjz68Bo1HOpSBOW4Wdc8mhFsFRidvRO5XH4WvGTL2ALGt8iXJHXp4LI9teFvaFEw\n"
            + "+WK/p43Cd6Ei2SMOWScPXGDS0dtcXnU5cDoSBLj43isqAwhNUp84XoqKE2BB4rTPOQIDAQABoIHL\n"
            + "MIHIBgkqhkiG9w0BCQ4xgbowgbcwPgYJKwYBBAGCNxUHBDEwLwYnKwYBBAGCNxUIhZ+hf4KAnkqD\n"
            + "pYUZhcjqJoT8myCBAIK/vTWDw41NAgFkAgEzMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD\n"
            + "AjAOBgNVHQ8BAf8EBAMCBaAwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDATAKBggrBgEFBQcD\n"
            + "AjAdBgNVHQ4EFgQUSUk3M1EU+mxI67SaBMbmyS9bIFUwDQYJKoZIhvcNAQEFBQADggEBACMW4Ezf\n"
            + "SFGTN/tecE+QcBIeNJ6Gmpz2LMeS/4bkqwanGy1NQlMubC4jbjIiqOeOYB0oTTAHccd9EVNuxAMg\n"
            + "rI5nuyKeWoIkGaTMqSJzlCXWmP9Etgf3K2HNTkuQaTpiLx3Fu4Zj3pw0boavUd8mfIX0I8zmNrzl\n"
            + "+MTK1HT+lf4zf/oxBXKgqOFS2kBcz2Wa86egdNEQWkRqtoK6n/wdRxChQwHaGEAgV/ORYDgsBNzB\n"
            + "rYpffQT63+efcJfKvoqtgsd15f9RRne2KNWWSaQFg8NdeX4eFdR0oQC6zdlHgqVWHCzLlvQ3nNkK\n"
            + "ZwH0bzPRNiYzcpTpSVMHa1XkIa+tzfowADAAMYIHujCCB7YCAQOAFElJNzNRFPpsSOu0mgTG5skv\n"
            + "WyBVMAkGBSsOAwIaBQCgPjAXBgkqhkiG9w0BCQMxCgYIKwYBBQUHDAIwIwYJKoZIhvcNAQkEMRYE\n"
            + "FPSRuBANVthuex9d1Ry+BTyossTMMA0GCSqGSIb3DQEBAQUABIIBAEnjQkNj0yseulisiSERtE8A\n"
            + "2a4BAeGtfi/Ia7ilvsUKXB7FMvEoDhFFX+6mZg2SSOz5yqBb1aMvJ8eOYTm+fEuO/wTYeThOvf8Q\n"
            + "Cef9dKy6IPCHUsMWgfpWZUHtqP5k4kiHlpjFz+08QovPcqWjdsFFYk61ezg24HijM/lQ+KY2/MKi\n"
            + "83XxHS0jvuYK7TEWCJTRd72M/QMBbAKwzwAo0Qy5BRUCgw5NfnWHzbe1zNDmzs00h4R/7SchXo7E\n"
            + "+Vpw28jwOpdfp2tulEDNsXQgrgN4BjHSkspBzAluP/aPQ1csykEf8nZsN7uVfCvMQAjVlIuswVc0\n"
            + "+5uUjWhL58yAi8WhggY7MIIGNwYJKwYBBAGCNxUNMYIGKDCCBiQGCSqGSIb3DQEHA6CCBhUwggYR\n"
            + "AgEAMYIBSTCCAUUCAQAwLTAVMRMwEQYDVQQDDApJc3N1aW5nIENBAhRQR0Bz0aGO/vQaBQxh3o3h\n"
            + "B1//6DANBgkqhkiG9w0BAQEFAASCAQAw4verjebXkVdC9txVLCERE5VqilTq0H+IjT5gYkDEEGDg\n"
            + "dyeuGmn4bqmgcuHaDHD0LbG3iD9qU+igOkzMJjD7tk6acR1ESt8/hVqCxUCMIY/i1aIMR/BSPy6g\n"
            + "Xk12HKWD5nkw6jlTpgbcEXulrwz6JlnkwSfCOkAajZ4DKt/DqrNhYuf/CsIT3Vpfzu7a1ysO5DY+\n"
            + "DQa2edoOXtuJqowdBp5Q5r00Rvfy62YCuSFkdRmgPWFhUUyErSiH+ER57Z0rX+RRzet0V1D8lxmW\n"
            + "1YjZdnJjOEqJ17DOznpXX0p/ZZUy0yAcOd0n5wa9wUWo+SCq9lfjVSbwXnOV+89tIvOoMIIEvQYJ\n"
            + "KoZIhvcNAQcBMBQGCCqGSIb3DQMHBAhqdCcixIfZUYCCBJheN5hux3Xy/62umvALFB7seVN1Nr4H\n"
            + "gxowMm2mUFGEt45Y3hDpe9zkxAplG49vUGdzO+I+UVAUUtzk7fccmu2z1sAUP5RuZUvpYvBJICNj\n"
            + "z2L2P4RsYtHvrXlLOsRU/GBxki31t2feD9fbmKdXyJskVios76dPTr3WKTpREIbDCqottIhjla+3\n"
            + "NyfRqEJh6cHlFZut54ixOAOKv1lwko6r1Lqcf/PeXGeNSJNsf7fs62BsZLUJNjrqdrSepwtHgA0Z\n"
            + "D6x/auaYefmWUe2R1YQA4Nn20bGmsM+zlFR5ybH+XxSlqgXNmmJerQtYmA4Qy+/NejGjUcPqCSh/\n"
            + "gtkEvg8AN6nOtopAQmOAn4MmFQW/yFpBdZ7adNXkX87hcwqCQJmKVo9uDZ0QKCGW2hjqFl5MdP5v\n"
            + "DFdeVLdu/axilRDd4Pa7lcSl+hzHfXzWvn0HMB2U7R52Xni0dApomaQF1zmhVuVzJWP3gHvFd7CD\n"
            + "gwuP6MOpT845mVgnYl0001he+QxyUH1JQKZT9VVOD6nDk6FTbGhnJX/5gHWjPiyHQKkUweJhEF51\n"
            + "MoMlfxBCuzeXb1fXq49G1UF3ws2AmBmR6XVraT+Pg7sb1+WiCByVXdQ3Np1Dk0/RHcihkw7VD+Ka\n"
            + "7rc7x2NSPT4CnEOAxLLpmPZKXoD0rWdTR4GeGnZyq8k1vWLW25NPRg6SBbH221u0PB+tOt1gXrPr\n"
            + "gUFlAUBVLSlfrNV5rLxBb6Qcr16XYfUmDq5APCPG7A3X0YuKjINY/SqR7EG7mwPmC4jPbUXQtDnm\n"
            + "/9jGfCkeixl+3j6A1EJFnhC3p/+g1LSPXWlrV4BSh3cVWE5iZfgsmE6Az6A+xdTulwkdCYbDrwGU\n"
            + "aS+IOYRmm8fdUcyh4/ZvrQ/vBSpqgKBGhnbRwE5N4bed1JsARfPoKKGtwLx2+/PmQaWVxilq0Mb1\n"
            + "h8sbEPa9h4y9VqccVOuQ+qZaRnmR3Zpjns4HCFay6fjlKBjWblIafETZMiI3SHQc3ZmNGfWPLVDz\n"
            + "jNjgLzw4uF8Grf5pr0MsztrCGW+hnD3iGsaG2xgGDT8hY0EQZYpu4PPrW6HNKipmKZJbj/fCLqO4\n"
            + "QkUTbIpY0pUJCcKar77pWQO5BBwfPDtCzVd9Qx8a0SJoA8080oRDleVurbTDdpXr0baOvOb6Ue1L\n"
            + "N2bUo3sHm0XcH8S/J4OECqliU9om7NDs4B62ylYNaecVaN+VZyV8fg8wjgFuNHsq+2PRSgGVYdpS\n"
            + "Eqz/Gg7CAxB1Y6DWlSV1V8iSyogVdmbunSYRwEXDgGcdhM/hKL2i5o94MnuV02As4bPAAk+sOo2w\n"
            + "5RvaUirK2HSDfP8PIiElE8g9PPWvn1ZODIas74kQ2syGJvSfoC1KXsNAeH9K7leLSY3CQ2IlntqQ\n"
            + "hXtvEuO2Ioj2fkvZznsz92VwfCI6nDNvU6oA6Bgo/QzM+sPIFdxBK5HP7U5Y9ABG85rLlGBEM8+W\n"
            + "qgR2/glGMTrq+FKcWO/BTBtNuAHGvVzfhrB2YsMsuLsVjoehX7DZ9CuPHdKu1qkRcpP1/T2QUZfN\n"
            + "D1/FmUj+I+nmHMF/kF4=";
    
    private static final String CA_XCHG_PRIV_KEY = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRTiJtDwsRgozw\n"
            + "atZb4/X/HNB/xaOdiSukZRkJ5tNVOEuWV5fjYxALQcnuSW+uUHkwYyniZWO527Ct\n"
            + "lDEJ55TsI/PSXLJ7kFJCiAD4IpkaUyZ7XXpkmWd6SA7jp2EACIc8UIBJaMTuLpmL\n"
            + "ElgrDnu58Rwz652lbqPKqOYLFjkNr/y+JEtrOog8Lk+UPhsUPmXlx940RvWTkfHT\n"
            + "+K7FQC/tFO+4D5boonrH1VtJFd51ZDxsFDhrl2v3yuV8M3AAar516Td8DGe6Tqb6\n"
            + "88LYI4wTVcEBNFkR4ITC8d6721vR5rkihuzvB+XtYGZVlCekEySuM7dA6PcxZ5O6\n"
            + "evmhMGBHAgMBAAECggEAQ4kVJaB9f0xjIq4udZ8EQKlxA1Fn3kyk9toiLqY62Zwd\n"
            + "E6k22smboy46tHcgoJvZxsmweZsihxWCmDehbSM608k0AtQjSSiDynDs8yPix/I9\n"
            + "j//VHsG6+GNo3n8jFuopjMYi5sz2Ai6qH4wvQ9FcDd7lLUGg8ADXu+wssjYc+bOS\n"
            + "NyY9M7tn2oxj6cZkJW5sVgV7EekkAg21o2XB7EJ4NCudKtXmPrqI55G7f6/g1ekK\n"
            + "/+5G09dNqpRLFcWJphZVuU2n526EG6qIySLniFClwgvod/qK8hqgqINAGSOouDIO\n"
            + "OW3zKUlnBvWq4rn8nWFzt+UjdO42byRcUU0h9U13tQKBgQD4UvvXkzl9ASsuZUTD\n"
            + "P++NDLRNiAy+wx2Ch6k2ak4wR/8VfiJPK9HWofGMWSk0bpJjDgX1yf6u7fl0i+mD\n"
            + "+7+odrwaWG5xbGgSKKYJDwcBHRBRMuH1EIs0drydv0qW0HtTffzLplOx0ehyHk+9\n"
            + "OpXEaPlGxrgxdlXWAEsoCyAhqwKBgQDXxmO5s7DVmfTxG8UpOSmU3HfkhsTRI7Yb\n"
            + "jB3RyEB7fmvCPSJYk1MD8RNgzbuE/aagKSSa2K1tct/rALu5vxheiM4UO+1JTpnj\n"
            + "6HeqPSIovMilzmTzOUY4Z53+aropaJoULnYckmeUqqZy8vXna6NERu/crI45+Xpz\n"
            + "4OutQ0oX1QKBgFxpXWmDU4COn8g7TZSvxXEjSjIUMFIJgIDkBXfHpeNX17ji4Ne/\n"
            + "we5zA9YsFCZ8A6QzQsqOamYlD5Fsw/EnDdMepK/VOvyg0DX5xJhYbE3gyAK/wdEW\n"
            + "YAedLGI0Hwjy+wI+P4Z2Fm11ZWCaoSgVlkiqnCHXsBJQLG9gWpfDVCjTAoGAZ0r8\n"
            + "gHBpzcc2v5lIp/RKWI22AzsUyv1qdwN7XuqbG8MoOMLlRzu3eOKWITg7dW2rr24i\n"
            + "rNHfK87bLHecZk35j3+0D3GkpPwwpS6q4l8DlDbTYrRMFTcsy2Gm+50B40LEx7Z6\n"
            + "KjFXzo5mwg5W82LOtKe0uZINP+mS2hgpGjdlJ8UCgYBrkGcASe18yKscrWis02bx\n"
            + "3d+ror5tdATqmuJDJR31g/lSpC3w+sBvOleHcXkX36LSxZUqZyaHJowNoXYathbs\n"
            + "tgNgD2tp2hDBEHdJOcx5Vo7HGHRSAbJjeSBtjc8kJuSVmEvUNBST5Tt5DWzcOloJ\n"
            + "SSPpWa3QgFphkWUYxVi2Gw==";
    
    static PrivateKey exchangePrivKey = null;
    
    @BeforeClass
    public static void init() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            exchangePrivKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(CA_XCHG_PRIV_KEY)));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    @Test
    public void testSmoke() throws Exception {
        
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Hex.decode(SAMPLE_REQUEST));
        assertTrue(msg.verify());
        assertEquals("CN=TestCN,O=TestOrg", msg.getRequestDN());
    }
    
    @Test
    public void testComputerEnroll() throws Exception {
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Base64.decode(COMPUTER_ENROLL));
        assertTrue(msg.verify());
        assertEquals("", msg.getRequestDN()); // AD look up
        assertNotNull(msg.getRequestPublicKey()); 
    }
    
    @Test
    public void testUserEnroll() throws Exception {
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Base64.decode(USER_ENROLL_REQ));
        assertTrue(msg.verify());
        assertEquals("", msg.getRequestDN());
        assertNotNull(msg.getRequestPublicKey()); 
                
        msg.decryptPrivateKey("BC", exchangePrivKey);
        assertNotNull(msg.getKeyPairToArchive()); 
        
        try {
            // this works
            KeyFactory kf = KeyFactory.getInstance("RSA");
            kf.generatePrivate(new PKCS8EncodedKeySpec(msg.getKeyPairToArchive().getPrivate().getEncoded()));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        EJBTools.unwrap(EJBTools.wrap(msg.getKeyPairToArchive())); // this fails
    }
    
    @Test
    public void testParseUserEnrollKeyArchivalAsPkcs10() throws Exception { 
        try {
            // fails as expected
            new PKCS10RequestMessage(Base64.decode(USER_ENROLL_REQ));
            fail("should have failed to parse CMC request as PKCS10");
        } catch (Exception e) {
            
        }        
    }
    
    
    @Test
    public void testUserEnroll2() throws Exception {
        String req = "MIILxgYJKoZIhvcNAQcCoIILtzCCC7MCAQMxCzAJBgUrDgMCGgUAMIID5AYIKwYBBQUHDAKgggPW\n"
                + "BIID0jCCA84wRDBCAgECBgorBgEEAYI3CgoBMTEwLwIBADADAgEBMSUwIwYJKwYBBAGCNxUVMRYE\n"
                + "FBYE22NS12CLiwSf5eL79Yz29qI8MIIDgKCCA3wCAQEwggN1MIICXQIBADAAMIIBIjANBgkqhkiG\n"
                + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuVy89AFwirYURzt8VdSSooOa2QG81SN3xjLToXGjLBcjNVaa\n"
                + "hNeZsBD9XqE3dHlSJMXD77RctbjZL0wEieSq9vKmKX5bCHBpzo/QRC55YC/OVSL+a7nk7KlhrMfc\n"
                + "yB6du1xc1uiPVnVaYEqZbKMQTKYilDRvoAD+tcJYJfPM9VlGLJeVMDXnmD7D7hPeccod50UTUfRq\n"
                + "fL918aaMCvLno8t9Z+/Qy4NMAOVdkubnKyGER+IBCB/Ga6cdZinJYCbeNEg4Q0JwlRxruNZSOiYu\n"
                + "3RIAQKDqPwrKSS+9UiUCYGSFyT9RaLYtVQQaxhV/jIDquqhP4aE6KlB/tHvvzt/W2QIDAQABoIIB\n"
                + "LjCCASoGCSqGSIb3DQEJDjGCARswggEXMD4GCSsGAQQBgjcVBwQxMC8GJisGAQQBgjcVCIWfoX+C\n"
                + "gJ5Kg6WFGYXI6iaE/JsggQCF9M9h7O17AgFkAgIAhzApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYB\n"
                + "BQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYB\n"
                + "BQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3\n"
                + "DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFPvG\n"
                + "uKgyoHjfZ/95zdNIcBTK4ivSMA0GCSqGSIb3DQEBBQUAA4IBAQB5J6DJZ2Yo8aGtaOoqQxr6W/PX\n"
                + "ZqXsr8ZVjX7s9yo4YBNAVNFBNBcmAMOhu/wRvxbc4wdek9lUBVuL4om1oEzlALp7KpTg/FphJwbv\n"
                + "eC42kPNvkT5AzogGCPqaRf/tW4asdXfHI5ecwbv4iOqqgHZ4JlrII39g8YgCp6uXOk21hyBi6a8D\n"
                + "OIgTpYxixeQl2F/k4gsA335OnKLBbOec83tTA4tE52kZk3xsrs17CI5JwV0k4AWTroo7N28pzqig\n"
                + "P7UWiBnUadUyU4IEFNLFiRIFJSR0wOURZN451bAieyPZFVI3hZQknI5T/sBiDOXH8dfuOJ8S4hmr\n"
                + "gc22gRB4Ku12MAAwADGCB7cwggezAgEDgBT7xrioMqB432f/ec3TSHAUyuIr0jAJBgUrDgMCGgUA\n"
                + "oD4wFwYJKoZIhvcNAQkDMQoGCCsGAQUFBwwCMCMGCSqGSIb3DQEJBDEWBBTEg+311TyznpoNYbkI\n"
                + "ZW5vT21Z7TANBgkqhkiG9w0BAQEFAASCAQB38UAJfK/eepfR2gEroK6jyk4ByXIqBD0hf7aDGPHf\n"
                + "xJY/+4E8/tiQY33kjgtpgr5WsUbCdlzdYTCXT+afbh2fw9hjEHhxFHVdZNHABW8h7pkEPRY4nHiC\n"
                + "+CMqVLnoufvJcivy1mdeAE6Wj7l0a8Hi50fXbwP1x87bROgnCYCAsR7+Xt8Ewlf21QHleBIeMBfX\n"
                + "MyVuHwFqPmELJgp8D16yF4e04krk7fIiFW65d86Qh5ACbi/6u8Yuvt1k69+jyKrzJ2tdI0Wb5BgT\n"
                + "ilLlQ2OSCRI2lI91CLNXuRUlvsls+oMBI0+VTp5I1vtw4YgeupXx2/seywZfibSrIDUIh3KyoYIG\n"
                + "ODCCBjQGCSsGAQQBgjcVDTGCBiUwggYhBgkqhkiG9w0BBwOgggYSMIIGDgIBADGCAUYwggFCAgEA\n"
                + "MCowEjEQMA4GA1UEAwwHSXNzdWVyMgIUV94OYm2LhjYpuvwHNneFoeIxlzcwDQYJKoZIhvcNAQEB\n"
                + "BQAEggEAg/GXI9UYEkUVM+BTSHzaFZHGdg/37fBazUL1KHzFXouLyHUO5rB4OEs3GmOx02ptarPo\n"
                + "3WwiOc9O6ojkonCJ3urKixqEFwjOHHFe4/49DMpecVdHU785kruOwTsfc0NHoAVeRwxvmeiyQxzO\n"
                + "iKJdY8OTL9mY0M8Vi5J111S5hqC6x8s+SJPbuycwOgCL7EHzXW6XcNPwCk1HQW5zOITmV/vdXfV6\n"
                + "81ZA3YIqKDAodnNGWUiUoQBkqFa+D7o1P00/1t9pBdd6nARFu2ZCI0nOJmtzvKhTfEuDmKTiLxty\n"
                + "4nzcvzBRw1R07titPNb1CRgwKVuDOT9AuVvHqfsqEK3D+TCCBL0GCSqGSIb3DQEHATAUBggqhkiG\n"
                + "9w0DBwQItZ5bG17Tga+AggSY+u8A39Z4a3TEX8KwVbH4SoxV6jknd6TKkyfZml7ifPTl9WVmmBIj\n"
                + "xUdovdPGkRkVgMfM4tIflnyjP8rQjJ9bPg4B1QuSZiPfTc/63obRy3oC69CnKIu5b3S2IfF+4Bgi\n"
                + "i7jGeaigyoBS+V8hBtGzi+jiJf5NHr2Lg1au+Mtkiz6ql13MYljh4UZpaW1ee/8QmXH8T2vHJTql\n"
                + "RQHyQlZKl0TK/jCiZkyAJNBDq0s/Xakn4TOVmGueT+UpEpe90sWp+75t+PW1u2H34kltjMr6Gt3k\n"
                + "KRKA/aY/YTzLzX7OF3tpvE9X0ecfU8JK8N1dgLA7dYlNgzmhCjwH35/kcs6LYdFlutLeGTTiUe2Z\n"
                + "x2j3wdOk1t3Po/q6MvlUvKLP5bUVrfIhsQA071GQg/vsE+nZam949VJBWtNNwvYSp7CKtaQVEZVr\n"
                + "04854A4KQEI26LgtkYStT5ZTO3KmHc14hnaV9o2Azt25E3bLK3iSzIREXYe45pGWsEGHDT+BAjwd\n"
                + "ChmiQxnXVuyTPPZ10IPoHREhqVMipxacDT7UQNPXu+z3W9VPrazVkf//JSSxxIEZ2x6/a+N0Rf5B\n"
                + "KQt3lFZHEk1hctuq8ofmVlaviy6PwhsEJwFsDtnviZeF6WL8G11L8kyIz1Rce4AVlaACAzyCEOkY\n"
                + "V223MNe7U5Ei64QPwGJkEei496Hl8an9ihkEhtF4z/jkWtfrGBx9amLYNRao09dluxvSXjnGgCMA\n"
                + "vWzOfZUxiN8UNqEczx06/b2pON4g/LWiBzIXdUgGH45G5Da9+VHtfLeLUwK8OZh08pAyi3MgWJgO\n"
                + "oApTiJ4YUT1rZvwRoQJJDQk2VMuyxbH5aKT3Lj0EY3lAksImnBlqpuojQ0AJed6U3+G3mHjCo6Uh\n"
                + "h1kxG/UB8Ko7TdF2TpUIk4Kb20MIqqGIZTwrWEqzZ1QhQC7hd7wbhHEIRIJOCptEVEIC0e4ySdhT\n"
                + "m/DlYfZWp9OnmGaZhYOVMaVe896nqz7+6uMZ8Xkz+oo+vaBM/7KYt0b0zTqd64j8CDQY4f0zK+lG\n"
                + "9F7R/aI+EJhFilScwgexDfFoYLBZbiIs9qbuGaDuqTuFFovKkcsqSUCJBDu6+H3YvljZmLxVtnAA\n"
                + "czKdW/Phn1sbCrMYSPdWO7sH3Lu3ujCgHfQJHI5dlJj3m630V9e14RzwpVHHfoS9D5Ot/HWeSq2a\n"
                + "a4U/lJxEKSdAqco/5aEVtZ5qT2mYmIPo6lQXrTl+0sEjbM9EMUeBmfLulQ2w8Ww9lAPq6yc+Fk/d\n"
                + "TJsaDF8ID6/l0sq2c2YrydqSYlDyV4m5Ddnxhoyw3oeYzEws5EYNLt0Mftfkc9mZR8i1oJuyJ3Fd\n"
                + "BLNetPuFu/VFINYjeAjuoi1f/9eV2eYTmv80Zu2jX77PTBvU3wvSZLX+rkTnYQEpwirvuFii6YNO\n"
                + "m//6NgftNoez8xLht9QT0Le1VuEc5ip9Wl2sr/vDs6FKxNANZV9ZAYfv7+Os8RumRZFFXK6Zyy26\n"
                + "jSW1vbvIPtm72DY6vyokDy8bRdtonZcBqWp6y0bBgm9eSo0XV9FOMQg65KkAteQMpJfchBEd"; 
        
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Base64.decode(req));
        assertTrue(msg.verify());
        assertEquals("", msg.getRequestDN()); // ?? AD look up
        assertNotNull(msg.getRequestPublicKey());
        
        msg.decryptPrivateKey("BC", exchangePrivKey);
        assertNotNull(msg.getKeyPairToArchive()); 
                
    }
    
    @Test
    public void testUserEnroll4() throws Exception {
        String req = "MIILxgYJKoZIhvcNAQcCoIILtzCCC7MCAQMxCzAJBgUrDgMCGgUAMIID5AYIKwYBBQUHDAKgggPW\n"
                + "BIID0jCCA84wRDBCAgECBgorBgEEAYI3CgoBMTEwLwIBADADAgEBMSUwIwYJKwYBBAGCNxUVMRYE\n"
                + "FNRIME9F+o9LkKj3d6u+lWGmdCSbMIIDgKCCA3wCAQEwggN1MIICXQIBADAAMIIBIjANBgkqhkiG\n"
                + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Un6dClmpqqD0FpgBf5qZwH6PWEqJMHDPYl3YKzUoquab0qj\n"
                + "35MTlghH4oHODR1SgHu75lNXUcro/YdIsblrRRjjmT0Gd1Q/dpzCeWfzAcsyesUKRJm8SwiLMLJk\n"
                + "8WbnqEAOV9s19UUSn8ekcP2sXjHLINpfQXbw+TSeDboeR7Huadu1OfJIKyOe9clJRa524TS8JIvF\n"
                + "HxTMeoBjuFZPv5GjlqEfGM+52td8ln9DouXz9staCgQQ12gvurYQ348hPkm0rzFzS30XHBZL3Uge\n"
                + "A2FGtiUMoirT3WX4seYTRvn02ezfXnuOh224cNumd37m2zonP520pQglbY34G4KbPQIDAQABoIIB\n"
                + "LjCCASoGCSqGSIb3DQEJDjGCARswggEXMD4GCSsGAQQBgjcVBwQxMC8GJisGAQQBgjcVCIWfoX+C\n"
                + "gJ5Kg6WFGYXI6iaE/JsggQCF9M9h7O17AgFkAgIAiTApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYB\n"
                + "BQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYB\n"
                + "BQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3\n"
                + "DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFDPM\n"
                + "TguKAAswxs12xAj7OYrvOk4jMA0GCSqGSIb3DQEBBQUAA4IBAQBOlM1cn368oyXgC7nUocEfB7Nj\n"
                + "m8xXDLjk1+9ocpu/FKtAceGFl/kO9SxAPC2pzhWkGVFM76KgNFsct1179o5vfBUz3CihMmwrtbK1\n"
                + "co3XbmBZaulVbyC2RgDi3LqkJs4vfoRwXWVsFl6NyvWYfK7WFFPKMluYIhAM64nEepJg6RnodHD8\n"
                + "F7TKqMcIi9xOkQexwJlK+xyxFr+YK3SDWHmJKl4Pzv5XbeQgrTQlaCYmGZGJH+2/euX/TL+ojpUN\n"
                + "bGlfxfIWzpRzsJd5vGDIkKoudQ7Lg8GxE8IUqwoblEjbVtV9AreJ8Ch8oywgg9D280eYFAQ8iu6D\n"
                + "3IK0fEdkvVBmMAAwADGCB7cwggezAgEDgBQzzE4LigALMMbNdsQI+zmK7zpOIzAJBgUrDgMCGgUA\n"
                + "oD4wFwYJKoZIhvcNAQkDMQoGCCsGAQUFBwwCMCMGCSqGSIb3DQEJBDEWBBTNyex1ZHnjSqEA+lQN\n"
                + "FeUkafPqFTANBgkqhkiG9w0BAQEFAASCAQC6yO9WUnd9/VPyzzedw62CYdPVFf0NXQGryEWI5frb\n"
                + "bWuWVLYH/gFeIvK/28ShsFw+dzKYtF17TTxIEnWJM/XkQH22HNdVsWvQTCDRJbGtOjQWQkMrmFUH\n"
                + "h9IuB2xdDSqZK7h0EWA8KjZQl2ATRvInPap2HrkPE8nPf11vAE6f4x4WN7De4BX5XgV7tqz65v4h\n"
                + "kNEdpN2/+RfoxW6/LTxsBYDbWyzbUzKX4yKY7BFqe/heT5PvBw5zxhWSXwRm9dZIVRpr6CFtUiZX\n"
                + "45k43t9DX4Ji3xTlQbMObj3caeCpE8rjqJ6OTV+EfnyLnDKuB7YpV/aoO4POdxldlMRel5LnoYIG\n"
                + "ODCCBjQGCSsGAQQBgjcVDTGCBiUwggYhBgkqhkiG9w0BBwOgggYSMIIGDgIBADGCAUYwggFCAgEA\n"
                + "MCowEjEQMA4GA1UEAwwHbXNhZV9jYQIUZM9YAz3u1w6mZkA4kpTseLWFz/gwDQYJKoZIhvcNAQEB\n"
                + "BQAEggEAPKdCDgnnyRuyznJD2bH6H5K01lsVNC1xXou5OgHvWdmk+qm9A+ZaLwzK4+dSRr1VkvI8\n"
                + "6Sb4o/p27wG4tuhuxCUR6PsGfZ0plSTFvlOhzQmIeT0oV+pvPpZjMNWkq7T2ZT+nBv9BEWVdg+yF\n"
                + "WHP0siBvjXDjBnVGjszy6gIjWQzlu0iUUoWU8A1t3eFNweRRCZAh/8hS7D6Tk5V9nm1ev+zQvPkt\n"
                + "brqdkwOPZkkLk8DobITxvht+rt6ipIOyQG+iYX5MlKTv3ZdDlwiwAxfvmf3OZo6HNPc7OCwFIDlU\n"
                + "eR3jlDt0npqW5xh604cDtGQRqJ5veGpC37otcfN4rX0pnTCCBL0GCSqGSIb3DQEHATAUBggqhkiG\n"
                + "9w0DBwQIN4uuW6VRQdSAggSY2MQIxBuDHhWnB0NNL4VtuWIcAxBFdGOdg4rwts/+a1Q/iWq2zbxP\n"
                + "foU2J1jzmwlojtqVzBEYWfgbD8xkjzrdRpd41rBQDosT2OhFzAaSKZs6UehiXOAyiF6Jn96csy0M\n"
                + "4qMiv4gD2ExP0XORMIsQPwY4DfxNlKZr56345m+4gcKjzLfKT6bi3kbk6kl9DyEAZc4TP5UuvQgs\n"
                + "wzY9w5eQfVbCpGfH76SdbPEBdkyd26OCqAX15oTRpP1Rut4JfjIu0D9VL6s5y6RVHB6dqpTXT7lk\n"
                + "FBggB7Kr9rPdsLGsrMo+1BeYLut6EcdA+d9exi7wPl/nkizBSLpXLA0/jnABUF3tGej7iH9kDgTU\n"
                + "nHoBkJvxJ2tvYslvZjn+87h9bBjMqkjdT3TArYxnjPR6Z8tHPD33ZhiSzl3xzQluO7vL6E40ctD6\n"
                + "JVxxecAFxmOfzaSBZvxVxSC5inoA4wKZ991fPyajsCuMmE+PXRtc+rlZ5UQKDMYVeYjJAHqYj9S/\n"
                + "R8XV29bzmYt+R9eZlyMtwoxDRbW/AvyZtT+g/Zf5kxdXB1y+bIlnBGaed7tc5BYXpagQRrkG91ei\n"
                + "5JoMBmAXqyCF10VfHt7EOqhs1vDvKby/pj/cmv3km/Z8zgfi/vuPWud3RPeDneotZI5xfL1OUqOK\n"
                + "wuTdAiFeZfVBAL6DrrGAhSBAtHAj078WvtOHUb0dj6DTVjzpzdaGX9BZKu2dJ21H1WVWEfWgad2U\n"
                + "DzbWaZcfXBnL7Oc+16NWDZE5Ptk88YlIXrWpCASk2kuAO/ADjjUOS4P6lhRsZCoEDu6CTrJFAsDG\n"
                + "uquYBGGrtuRdZZO9Ezsp8EF0FoQ/8eN0ibGwBQvLonyrLqO9NMcaCHhFPm7cRHCqIdLseJpzHfJo\n"
                + "Lo0BgmC6T6JCgUfsvKdMHfdEAmQ63h3XPXM3As4YcQNCSyYlHe86kdogFDyqJjus8tc/pRzUMhd7\n"
                + "DY9/bxLryJKbjA6naZs38NTcSqHVFHosth+7SWV6BGJN4nUA4QU96YiEplebC3DMUltui5yeY7wa\n"
                + "p1ET/u7XPQDdM05Ieixe2Xp0qxuN2dOexuTNO5CL9YfNtLdDIgY7pp6y7cgbsZ/teu/h8C14S6Ac\n"
                + "Mfn5BNwR0hLstoWVzwRIKUj6cX0iuDPp9sXTNGUuGiv7NUWtnxxZ3WoCMhwU3NLC7fC7MAeIC1Gk\n"
                + "swshL6T6OUGryGwDCEsXVW3zITr3PRfbMKCJOdesRtOqUItSxkW9hvkqqOmRv7jk+5TG+5lzq8Gp\n"
                + "JLAPQTxrx96UX/Zo6lhyQY7rv10F8cDI32shDfamusk/VkNQQFHIjycMTdq3ZZeZU/2/a89yXg2O\n"
                + "g6JmFWNWZrkQvy53YbrGi6WzM5WuJAJeiL1Q/a9WuufkJCjeqd/ovvX6sI0ZkS5CyyYhLp+0LSa4\n"
                + "wHj8ZmEq2yTG/vjvpCtg1rXpLARZQIThkAK0Pcnd7c7JsJr65VCqCL/N01xhvwWqOXHrQErQlqxi\n"
                + "xGe+iRAXJfal89fMlkeib1ZSIUZaGf2bw+N57lgF2riFqyqdk1+uFdhFFvkzju93naLNTwA1";
        
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Base64.decode(req));
        assertTrue(msg.verify());
        assertEquals("", msg.getRequestDN());
        assertNotNull(msg.getRequestPublicKey());
        
    }
    
    @Test
    public void testUserEnroll3() throws Exception {
        String req = "MIILxgYJKoZIhvcNAQcCoIILtzCCC7MCAQMxCzAJBgUrDgMCGgUAMIID5AYIKwYBBQUHDAKgggPW\n"
                + "BIID0jCCA84wRDBCAgECBgorBgEEAYI3CgoBMTEwLwIBADADAgEBMSUwIwYJKwYBBAGCNxUVMRYE\n"
                + "FBh5CuTtWoMxyQdaDeJxI4Zuiu54MIIDgKCCA3wCAQEwggN1MIICXQIBADAAMIIBIjANBgkqhkiG\n"
                + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyK0fMIdNY1trJfKX9fgt7MNcgXxdfhUopro9bZnX/UlL2wo4\n"
                + "ZGZsNxlyblvij0SjqGqVyqQcORVqSxH5apH/S5fWMhNpOLITTTlD5Z0q8b7RLjd5KS3fCO0gF6oK\n"
                + "XBTBKpG1Ucks4hx6w1Ay4be9t97P8Wx0/2ci8Vv1Q4bhSxzKzcPJ8OuqwV2G381HIOFpPdcFYXOK\n"
                + "2NZQWg0rJzWpjfuwKoAHHhFgPhsPbUWNKiMNU4DJQ44cY52FK8ah8OnY7jBwX/bR+nj3uxDSFeJ4\n"
                + "V+Vcjl/DBSZv+lcisfAC4AAIM5GhbHsS4tgu5iaLD2m0xBjWlu5xAH/F5WygCpuJsQIDAQABoIIB\n"
                + "LjCCASoGCSqGSIb3DQEJDjGCARswggEXMD4GCSsGAQQBgjcVBwQxMC8GJisGAQQBgjcVCIWfoX+C\n"
                + "gJ5Kg6WFGYXI6iaE/JsggQCF9M9h7O17AgFkAgIAhzApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYB\n"
                + "BQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYB\n"
                + "BQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3\n"
                + "DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFPMX\n"
                + "lU6fPYohQXxFtrbBKDl/8DsmMA0GCSqGSIb3DQEBBQUAA4IBAQB4LSkpvAFxoY7I0dxgQE1YsOzp\n"
                + "hnWAJd0je+9/nKPaOSwZN3zSRgGCn9bBJ6wVHsRfRrQle3m69GZ9MH9tq2+PS+dcyIs7mREjBD2e\n"
                + "xOzoxYmRHsbEjKV9/GAfwCXIbxRxcI9Oof+kkUCeLm4vtoSjOx24nchVPoeYUyKzeSDGO0tUeIkr\n"
                + "aadWGKHrw/goWHODuhfRMGgQgltmH0EXuJDnS44zeYeM2UhTDZDZtIEsYiits0QllCxt5W0hIWZd\n"
                + "HYHXiFjBamUkvlokeox7dAx10P2L0FmXqxtBvkR80f1mtuvwZ1kSLjJ6KIRJeaQQJIYnwAZ7P/jA\n"
                + "avxwcvk9ggK9MAAwADGCB7cwggezAgEDgBTzF5VOnz2KIUF8Rba2wSg5f/A7JjAJBgUrDgMCGgUA\n"
                + "oD4wFwYJKoZIhvcNAQkDMQoGCCsGAQUFBwwCMCMGCSqGSIb3DQEJBDEWBBS3DJyorp/OeaVtc0fS\n"
                + "24FxZi9BdjANBgkqhkiG9w0BAQEFAASCAQBFZkIsO8Zn5czDdVmhYucuyl6VVF+XrHzKuM78Hdnr\n"
                + "GUghIz+OS+YRRvSVcqEVGzUugn8e0X/RJ1gpK6M/JIuaPXcY7Kz3oYg22O2Xn6subIsdKCb6y1AC\n"
                + "EVRu3+T4Zuu7yJcQS49VBUmDHddZ9+lwkvotzUYAD8Y91l6hN0qr+5zt0Kqmm7Dty3YfTci19lm7\n"
                + "bq3yFZl/WNCA/3p3k7QSZDPh1CLZ16VviMjUArjHO01Ud0YPMfdZoD3tHnqNfdzCZp5BSCMCd2bo\n"
                + "SLpePIwnD/vkZF8w7tnVsuf4UlYHMcW9d6lQMkbf0d1Qj1wQVSNahLpFCkJJfxOyNdI1RUlwoYIG\n"
                + "ODCCBjQGCSsGAQQBgjcVDTGCBiUwggYhBgkqhkiG9w0BBwOgggYSMIIGDgIBADGCAUYwggFCAgEA\n"
                + "MCowEjEQMA4GA1UEAwwHSXNzdWVyMgIUV94OYm2LhjYpuvwHNneFoeIxlzcwDQYJKoZIhvcNAQEB\n"
                + "BQAEggEAvqN1mtJfL75b1IWYAscSixLzmXjf1RB4mFte/ckrXXX20ErYvFBIJEkjQWeWNPoR4G4/\n"
                + "fMfjMgLw3yrllhvsCyJljPRxqRpyPkhExqMF+lvWP1orub9MzHSA5S76End9P2aBT/zIVRDrZBTa\n"
                + "p25WpB7QdDCbnih1YpLtIjdmbxUg2nUkoZOxEfmmUdizWixbOie5SZwjHh3yLd8L0GKTiPbr2AMB\n"
                + "bMjsHb8Afz4merl2GgKdPzX16EYXPjYJoxIRPQMK2noZp8Zd1kGgoHFB5PTfQ9jKU2f8VivnaT4R\n"
                + "cyTwHy4vylkSq+GeQDzsEqnXBMl1lYM01p5PUvO3MT/1YDCCBL0GCSqGSIb3DQEHATAUBggqhkiG\n"
                + "9w0DBwQIrYaQAb3JQR6AggSYS1BwsbMi+EdeyLOgunBs7SGtrrkr6fkueCEbMxk0zFvlr6CxnXWI\n"
                + "00NAcQanFhV/++/pJpWYj4thPdNhtqxtlNbCMLogrT6ozrANni50zjL9j7a2HlEARsaZYIBWopga\n"
                + "a2YK78Jd4pymzfty/L/DC4BKHBVJcAkOx33G/n+b6RmRqufFzv3Gri7UTlSrUvg68BnzH1w2i8sU\n"
                + "BfrA15LJom/hUSZ2nAX/A4njQzW68V9yfY+S/2Xa1JBw/EfhugH7IL/KCj519rGmkUcPgH3GYa0y\n"
                + "QjBUC8HtPhHkU3qWmoPOU1zwFJnocp8M5X7GlXmisOwSwfQRq9SPyspnKLUmAU1IFok8ATy+CqeQ\n"
                + "w2/X48H2rfE+XbZ+udkS1NTbOzABS69JLwM0FNF9JJvXvUwWnW4R6zT6GFQqPxuHLRZX8fhKwwLS\n"
                + "/aajNgRo/Z5oAl4TRMN1fAon6FECCBhV14ITqvlwKy6Wo5l4CdyvBUpWxopJFDRWpcCwYadCgsCM\n"
                + "+ZiUOxu+WsePNmdpfujw1YA1KTG7/LTALKVsVFxLu7ADzhldjKxpyBOMl7vHCL3VQ+8v5FI/WWTF\n"
                + "jqCwcT1V64D11ZoIREOUNIJxDktJw4tTEB+ZDE9+MqZEbLb/jaKzd1ZvyKBiZ58cIIDDUIWUMTL0\n"
                + "TCq3lY0Iz7iOD8jsqiwm/XsZLsdxownMuKgt3bXNs9wOf5htzcfuxYlLFVxYSxFoLnirZzx3d0EM\n"
                + "BRMFG1Yytzq4pqE37t8vVcUInunsTUraWFsC1WV7TIDVezoQWOThVs42inYC4v4NitGqbiEEDD6b\n"
                + "NkJiDNjwDwZyhtVvuZrGX2xSD2g4sgPXjWFjfmtifZqeFVGvmNkMLhJZkjaArm4KA5irwaZRbspb\n"
                + "Q7FIJapMloEZA+XGYTGMkpFIFyJql+/e3ENNziAkaxNiCwoMbvoFfqxZI4PDeC5hXRc2A0NAB2wW\n"
                + "9YVTYbpDbOh+n3MhjcVkx9o/h0oXLMaBW6UopiKUJfbcqEneUdDi1yGf8JvwZF0lf1alOROj4jd3\n"
                + "S/1ZkD0MYauIlfZNHWY74ER3hOm3YeC3Z11T4ysB1pZdNEE8dB547QGVQlkvRQIgIsWQz3XIJFp9\n"
                + "4efAnaX3BpLX6BpHO/9bYOvZoHezVPp+6tHHAnkpPtIAw8rSYB81Yx5tvnEske/7YfF2+wDkwHcL\n"
                + "vfGOPFoaRNKEVwuSd0KCmmREKCBNJvxsbE0DwBTfV3Zp0f4WvoJ1b29infzIP5VvR/FiIP1sFA8I\n"
                + "B4HxtpG8kkx7NLqS7tNs7qcleG3JgoJFXvHoTTMxDnXi7pg5No2n2/BLmrtqvVQL8knXyBAScVUH\n"
                + "7V/Ur07Ekqx1S7aIzMbpbyGwfJTwxDKXEyCtUtv5P5p+lQAnu50oBXCK6ka5fLxhHDZzSyAgrqEA\n"
                + "Ye4HWVs/JsrXDNaspxnFlADu41ZwPJjLOoE6JKUDD9JF1WRmZV0lieLgECkOFUk+/oXxJGTCMRhL\n"
                + "F4I+HeAnnlxbAlon6VZz0082/4Qaqmlvr5INujdyEr/9XhD7YKveJ4aIE1CuQhfxhm970c3W";
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Base64.decode(req));
        assertTrue(msg.verify());
        assertEquals("", msg.getRequestDN());
        assertNotNull(msg.getRequestPublicKey());
        
        msg.decryptPrivateKey("BC", exchangePrivKey);
        assertNotNull(msg.getKeyPairToArchive()); 
                                
    }
    
    @Test
    public void createResponse() throws Exception {
        
        CMCStatusInfoBuilder cmcStatusInfoBuilder = new CMCStatusInfoBuilder(CMCStatus.success, new BodyPartID(0x01));
        cmcStatusInfoBuilder.setStatusString("Issued"); // TODO: human readable
        
        TaggedAttribute taggedAttribute1 = new TaggedAttribute(new BodyPartID(0x01),
                CMCObjectIdentifiers.id_cmc_statusInfo,
                new DERSet(cmcStatusInfoBuilder.build()));
        
        String szOID_ISSUED_CERT_HASH =  "1.3.6.1.4.1.311.21.17";
        Attribute certHash;
            certHash = new Attribute(new ASN1ObjectIdentifier(szOID_ISSUED_CERT_HASH), 
                                    new DERSet(new DEROctetString(Hex.decode("3B4938CC150F9B2BDD48533BB9EFA1B072A3B7A8"))));

        
        Attribute encryptedKeyHash = new Attribute(MsKeyArchivalRequestMessage.szOID_ENCRYPTED_KEY_HASH, 
                new DERSet(new DEROctetString(Hex.decode("69E3FB7F2416E07779034EC64EE7DF7E68A9C581")))); // TODO: from request message

        ASN1Encodable wrappedAttributes = new DERSequence(
                new ASN1Encodable[]{new ASN1Integer(0),  
                        new DERSequence(new ASN1Integer(1)), new DERSet(new ASN1Encodable[]{certHash, encryptedKeyHash})});
        
        String szOID_CMC_ADD_ATTRIBUTES = "1.3.6.1.4.1.311.10.10.1"; // TODO: find place to collect oids
        TaggedAttribute taggedAttribute2 = new TaggedAttribute(new BodyPartID(0x02),
                new ASN1ObjectIdentifier(szOID_CMC_ADD_ATTRIBUTES),
                new DERSet(wrappedAttributes)); 
        
        DERSequence payload = new DERSequence(new ASN1Encodable[]{taggedAttribute1, taggedAttribute2});
        DERSequence pkiRespAsSequence = new DERSequence(
                        new ASN1Encodable[]{payload, new DERSequence(), new DERSequence()});
        PKIResponse pkiResponse = PKIResponse.getInstance(pkiRespAsSequence); // grab beta release or use ASN1Sequence and then getInstance
        System.out.println( pkiResponse.getControlSequence().size());
        System.out.println(Hex.toHexString(pkiResponse.getControlSequence().getObjectAt(0).toASN1Primitive().getEncoded()));
        //ContentInfo encapInfo = new ContentInfo(CMCObjectIdentifiers.id_cct_PKIResponse, pkiResponse);
         
        try {
            byte[] encapInfoEncoded = pkiResponse.getEncoded();
            System.out.println("encapInfoEncoded: " + Hex.toHexString(encapInfoEncoded));
            byte[] payloadHash = CertTools.generateSHA256Fingerprint(payload.getEncoded());// TODO: parametrize
            
            // signerInfo
            JcaSignerInfoGeneratorBuilder signerInfobuilder = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider("BC").build());
            
            String szOID_PKCS_9_CONTENT_TYPE = "1.2.840.113549.1.9.3";
            Attribute contentTypeAttribute = new Attribute(new ASN1ObjectIdentifier(szOID_PKCS_9_CONTENT_TYPE), 
                                                        new DERSet(CMCObjectIdentifiers.id_cct_PKIResponse));
            String szOID_PKCS_9_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
            Attribute contentHashAttribute = new Attribute(new ASN1ObjectIdentifier(szOID_PKCS_9_MESSAGE_DIGEST), 
                    new DERSet(new DEROctetString(payloadHash)));
    
            AttributeTable attrTable = new AttributeTable(new DERSet(
                    new ASN1Encodable[]{ contentTypeAttribute.toASN1Primitive(), 
                contentHashAttribute.toASN1Primitive()}));
            //attrTable.add(new ASN1ObjectIdentifier(szOID_PKCS_9_MESSAGE_DIGEST), new DERSet(new DEROctetString(encapInfoHash)));
            signerInfobuilder.setSignedAttributeGenerator(new SimpleAttributeTableGenerator(attrTable));
            
            final KeyPair caEncKeyPair = KeyTools.genKeys("2048", "RSA");
            String encCertSubjectDn = "CN=IssuerCa-Xchg";
            X509Certificate encCertificate = CertTools.genSelfCert(encCertSubjectDn, 10L, "1.1.1.1", caEncKeyPair.getPrivate(),
                    caEncKeyPair.getPublic(), "SHA256WithRSA", false);
            
            ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA1WithRSA")
                                                        .setProvider("BC").build(caEncKeyPair.getPrivate());
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSignerInfoGenerator(signerInfobuilder.build(sha256Signer, (X509Certificate) encCertificate)); // used subjectKeyIdentifier
            
            // add certificate chain
            List<X509CertificateHolder> certChain = new ArrayList<>();
            certChain.add(new X509CertificateHolder(encCertificate.getEncoded()));
            CollectionStore<X509CertificateHolder> store = new CollectionStore<>(certChain);
            gen.addCertificates(store); // include full chain
            
//            gen.addCRL(null); // may be multiple - MS compatible CA??
            
            ASN1Sequence.getInstance(pkiResponse);
            
            CMSTypedData data = new CMSProcessableByteArray(CMCObjectIdentifiers.id_cct_PKIResponse, 
                                                pkiResponse.getEncoded());
            CMSSignedData cmsResponse = gen.generate(data, true);
            byte[] resp = cmsResponse.getEncoded();
            System.out.println(Hex.toHexString(resp));
            
            System.out.println(SignedData.getInstance(ContentInfo.getInstance(resp).getContent()).getCertificates().getObjectAt(0));
            X509CertificateHolder x = new X509CertificateHolder(SignedData.getInstance(ContentInfo.getInstance(resp)
                    .getContent()).getCertificates().getObjectAt(0).toASN1Primitive().getEncoded());
            System.out.println(x.getIssuer().equals(x.getSubject()));

            System.out.println(CertTools.isCA(CertTools.getCertfromByteArray(x.toASN1Structure().getEncoded())));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
}
