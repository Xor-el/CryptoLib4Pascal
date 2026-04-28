{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIPkcsAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  // Forward declarations
  IAttributePkcs = interface;
  ICertBag = interface;
  ICertificationRequest = interface;
  ICertificationRequestInfo = interface;
  IPkcsEncryptedData = interface;
  IEncryptedPrivateKeyInfo = interface;
  IEncryptionScheme = interface;
  IPbeParameter = interface;
  IPbeS2Parameters = interface;
  IPkcs12PbeParams = interface;
  IPkcsContentInfo = interface;
  IPbkdf2Params = interface;
  IKeyDerivationFunc = interface;
  IPrivateKeyInfo = interface;
  IPkcsSignedData = interface;
  IAuthenticatedSafe = interface;
  ISafeBag = interface;
  IMacData = interface;
  IPfx = interface;

  /// <summary>
  /// Interface for EncryptedPrivateKeyInfo (PKCS#8).
  /// </summary>
  IEncryptedPrivateKeyInfo = interface(IAsn1Encodable)
    ['{85782A45-F11C-474E-A2FA-531969A7D577}']

    function GetEncryptionAlgorithm: IAlgorithmIdentifier;
    function GetEncryptedData: IAsn1OctetString;
    function GetEncryptedDataBytes: TCryptoLibByteArray;

    property EncryptionAlgorithm: IAlgorithmIdentifier read GetEncryptionAlgorithm;
    property EncryptedData: IAsn1OctetString read GetEncryptedData;
  end;

  /// <summary>
  /// Interface for KeyDerivationFunc (PKCS#5 Scheme 2).
  /// </summary>
  IKeyDerivationFunc = interface(IAlgorithmIdentifier)
    ['{A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D}']

  end;

  /// <summary>
  /// Interface for EncryptionScheme (PKCS#5 Scheme 2).
  /// </summary>
  IEncryptionScheme = interface(IAlgorithmIdentifier)
    ['{B2C3D4E5-F6A7-5B6C-9D0E-1F2A3B4C5D6E}']

    function GetParametersAsn1Object: IAsn1Object;
    property ParametersAsn1Object: IAsn1Object read GetParametersAsn1Object;
  end;

  /// <summary>
  /// Interface for PbeParameter (PKCS5 S1).
  /// </summary>
  IPbeParameter = interface(IAsn1Encodable)
    ['{C3D4E5F6-A7B8-6C7D-0E1F-2A3B4C5D6E7F}']

    function GetSalt: IAsn1OctetString;
    function GetIterationCountObject: IDerInteger;
    function GetSaltBytes: TCryptoLibByteArray;

    property Salt: IAsn1OctetString read GetSalt;
    property IterationCountObject: IDerInteger read GetIterationCountObject;
  end;

  /// <summary>
  /// Interface for PbeS2Parameters (PKCS#5 Scheme 2).
  /// </summary>
  IPbeS2Parameters = interface(IAsn1Encodable)
    ['{D4E5F6A7-B8C9-7D8E-1F2A-3B4C5D6E7F8A}']

    function GetKeyDerivationFunc: IKeyDerivationFunc;
    function GetEncryptionScheme: IEncryptionScheme;

    property KeyDerivationFunc: IKeyDerivationFunc read GetKeyDerivationFunc;
    property EncryptionScheme: IEncryptionScheme read GetEncryptionScheme;
  end;

  /// <summary>
  /// Interface for Pbkdf2Params.
  /// </summary>
  IPbkdf2Params = interface(IAsn1Encodable)
    ['{E5F6A7B8-C9D0-8E9F-2A3B-4C5D6E7F8A9B}']

    function GetSalt: IAsn1OctetString;
    function GetIterationCountObject: IDerInteger;
    function GetKeyLengthObject: IDerInteger;
    function GetPrf: IAlgorithmIdentifier;
    function GetSaltBytes: TCryptoLibByteArray;
    function GetIterationCount: TBigInteger;
    function GetKeyLength: TBigInteger;
    function GetIsDefaultPrf: Boolean;

    property Salt: IAsn1OctetString read GetSalt;
    property IterationCountObject: IDerInteger read GetIterationCountObject;
    property IterationCount: TBigInteger read GetIterationCount;
    property KeyLengthObject: IDerInteger read GetKeyLengthObject;
    property Prf: IAlgorithmIdentifier read GetPrf;
    property IsDefaultPrf: Boolean read GetIsDefaultPrf;
  end;

  /// <summary>
  /// Interface for Pkcs12PbeParams.
  /// </summary>
  IPkcs12PbeParams = interface(IAsn1Encodable)
    ['{F6A7B8C9-D0E1-9FA0-3B4C-5D6E7F8A9B0C}']

    function GetIV: IAsn1OctetString;
    function GetIterationsObject: IDerInteger;
    function GetIVBytes: TCryptoLibByteArray;
    function GetIterations: TBigInteger;

    property IV: IAsn1OctetString read GetIV;
    property IterationsObject: IDerInteger read GetIterationsObject;
  end;

  /// <summary>
  /// Interface for AttributePkcs.
  /// </summary>
  IAttributePkcs = interface(IAsn1Encodable)
    ['{6F46BA6D-376C-4DB9-A85F-88A443FA3666}']

    function GetAttrType: IDerObjectIdentifier;
    function GetAttrValues: IAsn1Set;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property AttrValues: IAsn1Set read GetAttrValues;
  end;

  /// <summary>
  /// Interface for CertificationRequest.
  /// </summary>
  ICertificationRequest = interface(IAsn1Encodable)
    ['{2FD51313-14E1-414E-A648-2AD4BCBA997F}']

    function GetCertificationRequestInfo: ICertificationRequestInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;

    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
  end;

  /// <summary>
  /// Interface for CertificationRequestInfo.
  /// </summary>
  ICertificationRequestInfo = interface(IAsn1Encodable)
    ['{4405808E-2B24-4F6A-BFC6-92212D567D29}']

    function GetVersion: IDerInteger;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetAttributes: IAsn1Set;

    property Version: IDerInteger read GetVersion;
    property Subject: IX509Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
    property Attributes: IAsn1Set read GetAttributes;
  end;

  /// <summary>
  /// Interface for PrivateKeyInfo.
  /// </summary>
  IPrivateKeyInfo = interface(IAsn1Encodable)
    ['{B118BDBB-DDA9-446F-A2FC-E8350620E054}']

    function GetVersion: IDerInteger;
    function GetPrivateKeyAlgorithm: IAlgorithmIdentifier;
    function GetPrivateKey: IAsn1OctetString;
    function GetPrivateKeyLength: Int32;
    function GetAttributes: IAsn1Set;
    function GetPublicKey: IDerBitString;
    function HasPublicKey: Boolean;
    function ParsePrivateKey: IAsn1Object;
    function ParsePublicKey: IAsn1Object;

    property Version: IDerInteger read GetVersion;
    property PrivateKeyAlgorithm: IAlgorithmIdentifier read GetPrivateKeyAlgorithm;
    property PrivateKey: IAsn1OctetString read GetPrivateKey;
    property PrivateKeyLength: Int32 read GetPrivateKeyLength;
    property Attributes: IAsn1Set read GetAttributes;
    property PublicKey: IDerBitString read GetPublicKey;
  end;

  /// <summary>
  /// Interface for PkcsContentInfo.
  /// </summary>
  IPkcsContentInfo = interface(IAsn1Encodable)
    ['{B9C0D1E2-F3A4-5678-9012-3456789ABCDE}']

    function GetContentType: IDerObjectIdentifier;
    function GetContent: IAsn1Encodable;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property Content: IAsn1Encodable read GetContent;
  end;

  /// <summary>
  /// Interface for PkcsSignedData (PKCS#7).
  /// </summary>
  IPkcsSignedData = interface(IAsn1Encodable)
    ['{C0D1E2F3-A4B5-6789-0123-456789ABCDEF}']

    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1Set;
    function GetContentInfo: IPkcsContentInfo;
    function GetCertificates: IAsn1Set;
    function GetCrls: IAsn1Set;
    function GetSignerInfos: IAsn1Set;

    property Version: IDerInteger read GetVersion;
    property DigestAlgorithms: IAsn1Set read GetDigestAlgorithms;
    property ContentInfo: IPkcsContentInfo read GetContentInfo;
    property Certificates: IAsn1Set read GetCertificates;
    property Crls: IAsn1Set read GetCrls;
    property SignerInfos: IAsn1Set read GetSignerInfos;
  end;

  /// <summary>
  /// Interface for MacData (PKCS#12).
  /// </summary>
  IMacData = interface(IAsn1Encodable)
    ['{1E2F3A4B-5C6D-7E8F-9A0B-1C2D3E4F5A6B}']

    function GetMac: IDigestInfo;
    function GetSalt: TCryptoLibByteArray;
    function GetIterationCount: TBigInteger;
    function GetIterations: IDerInteger;
    function GetMacSalt: IAsn1OctetString;

    property Mac: IDigestInfo read GetMac;
    property IterationCount: TBigInteger read GetIterationCount;
    property Iterations: IDerInteger read GetIterations;
    property MacSalt: IAsn1OctetString read GetMacSalt;
  end;

  /// <summary>
  /// Interface for Pfx (PKCS#12).
  /// </summary>
  IPfx = interface(IAsn1Encodable)
    ['{2F3A4B5C-6D7E-8F9A-0B1C-2D3E4F5A6B7C}']

    function GetAuthSafe: IPkcsContentInfo;
    function GetMacData: IMacData;

    property AuthSafe: IPkcsContentInfo read GetAuthSafe;
    property MacData: IMacData read GetMacData;
  end;

  /// <summary>
  /// Interface for SafeBag (PKCS#12).
  /// </summary>
  ISafeBag = interface(IAsn1Encodable)
    ['{A1B8C2D9-E4F5-4A6B-9C8D-7E0F1A2B3C4D}']

    function GetBagID: IDerObjectIdentifier;
    function GetBagValue: IAsn1Object;
    function GetBagValueEncodable: IAsn1Encodable;
    function GetBagAttributes: IAsn1Set;

    property BagID: IDerObjectIdentifier read GetBagID;
    property BagValue: IAsn1Object read GetBagValue;
    property BagValueEncodable: IAsn1Encodable read GetBagValueEncodable;
    property BagAttributes: IAsn1Set read GetBagAttributes;
  end;

  /// <summary>
  /// Interface for CertBag (PKCS#12).
  /// </summary>
  ICertBag = interface(IAsn1Encodable)
    ['{B2C9D3E0-F5A6-4B7C-0D9E-8F1A2B3C4D5E}']

    function GetCertID: IDerObjectIdentifier;
    function GetCertValue: IAsn1Object;
    function GetCertValueEncodable: IAsn1Encodable;

    property CertID: IDerObjectIdentifier read GetCertID;
    property CertValue: IAsn1Object read GetCertValue;
    property CertValueEncodable: IAsn1Encodable read GetCertValueEncodable;
  end;

  /// <summary>
  /// Interface for AuthenticatedSafe (PKCS#12).
  /// </summary>
  IAuthenticatedSafe = interface(IAsn1Encodable)
    ['{C3D0E4F1-A6B7-4C8D-1E0F-9A2B3C4D5E6F}']

    function GetContentInfo: TCryptoLibGenericArray<IPkcsContentInfo>;
  end;

  /// <summary>
  /// Interface for EncryptedData (PKCS#7).
  /// </summary>
  IPkcsEncryptedData = interface(IAsn1Encodable)
    ['{D4E1F5A2-B7C8-4D9E-2F0A-1B3C4D5E6F7A}']

    function GetContentType: IDerObjectIdentifier;
    function GetEncryptionAlgorithm: IAlgorithmIdentifier;
    function GetContent: IAsn1OctetString;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property EncryptionAlgorithm: IAlgorithmIdentifier read GetEncryptionAlgorithm;
    property Content: IAsn1OctetString read GetContent;
  end;

implementation

end.
