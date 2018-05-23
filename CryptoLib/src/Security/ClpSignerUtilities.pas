{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpSignerUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpIDigest,
  ClpDigestUtilities,
  ClpDsaDigestSigner,
  ClpECSchnorrSigner,
  ClpX9ObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpISigner,
  ClpIDerObjectIdentifier;

resourcestring
  SMechanismNil = 'Mechanism Cannot be Nil';
  SAlgorithmNil = 'Algorithm Cannot be Nil';
  SUnRecognizedAlgorithm = 'Signer " %s " not recognised.';

type

  /// <summary>
  /// Signer Utility class contains methods that can not be specifically
  /// grouped into other classes.
  /// </summary>
  TSignerUtilities = class sealed(TObject)

  strict private

  class var

    Falgorithms: TDictionary<String, String>;
    Foids: TDictionary<String, IDerObjectIdentifier>;

    class function GetAlgorithms: TCryptoLibStringArray; static; inline;

    class constructor CreateSignerUtilities();
    class destructor DestroySignerUtilities();

  public

    /// <summary>
    /// Returns an ObjectIdentifier for a given encoding.
    /// </summary>
    /// <param name="mechanism">A string representation of the encoding.</param>
    /// <returns>A DerObjectIdentifier, null if the OID is not available.</returns>
    // TODO Don't really want to support this
    class function GetObjectIdentifier(mechanism: String): IDerObjectIdentifier;
      static; inline;

    class function GetEncodingName(const oid: IDerObjectIdentifier): String;
      static; inline;

    class function GetSigner(const id: IDerObjectIdentifier): ISigner; overload;
      static; inline;

    class function GetSigner(algorithm: String): ISigner; overload; static;

    class property Algorithms: TCryptoLibStringArray read GetAlgorithms;

  end;

implementation

{ TSignerUtilities }

class constructor TSignerUtilities.CreateSignerUtilities;
begin
  Falgorithms := TDictionary<String, String>.Create();
  Foids := TDictionary<String, IDerObjectIdentifier>.Create();

  TX9ObjectIdentifiers.Boot;
  TTeleTrusTObjectIdentifiers.Boot;
  TCryptoProObjectIdentifiers.Boot;

  Falgorithms.Add('NONEWITHECDSA', 'NONEwithECDSA');
  Falgorithms.Add('ECDSAWITHNONE', 'NONEwithECDSA');

  Falgorithms.Add('ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA1/ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA-1/ECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('ECDSAWITHSHA1', 'SHA-1withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-1', 'SHA-1withECDSA');
  Falgorithms.Add('SHA1WITHECDSA', 'SHA-1withECDSA');
  Falgorithms.Add('SHA-1WITHECDSA', 'SHA-1withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha1.id, 'SHA-1withECDSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.ECSignWithSha1.id,
    'SHA-1withECDSA');

  Falgorithms.Add('SHA224/ECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('SHA-224/ECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('ECDSAWITHSHA224', 'SHA-224withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-224', 'SHA-224withECDSA');
  Falgorithms.Add('SHA224WITHECDSA', 'SHA-224withECDSA');
  Falgorithms.Add('SHA-224WITHECDSA', 'SHA-224withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha224.id, 'SHA-224withECDSA');

  Falgorithms.Add('SHA256/ECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('SHA-256/ECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('ECDSAWITHSHA256', 'SHA-256withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-256', 'SHA-256withECDSA');
  Falgorithms.Add('SHA256WITHECDSA', 'SHA-256withECDSA');
  Falgorithms.Add('SHA-256WITHECDSA', 'SHA-256withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha256.id, 'SHA-256withECDSA');

  Falgorithms.Add('SHA384/ECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('SHA-384/ECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('ECDSAWITHSHA384', 'SHA-384withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-384', 'SHA-384withECDSA');
  Falgorithms.Add('SHA384WITHECDSA', 'SHA-384withECDSA');
  Falgorithms.Add('SHA-384WITHECDSA', 'SHA-384withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha384.id, 'SHA-384withECDSA');

  Falgorithms.Add('SHA512/ECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('SHA-512/ECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('ECDSAWITHSHA512', 'SHA-512withECDSA');
  Falgorithms.Add('ECDSAWITHSHA-512', 'SHA-512withECDSA');
  Falgorithms.Add('SHA512WITHECDSA', 'SHA-512withECDSA');
  Falgorithms.Add('SHA-512WITHECDSA', 'SHA-512withECDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.ECDsaWithSha512.id, 'SHA-512withECDSA');

  Falgorithms.Add('RIPEMD160/ECDSA', 'RIPEMD160withECDSA');
  Falgorithms.Add('ECDSAWITHRIPEMD160', 'RIPEMD160withECDSA');
  Falgorithms.Add('RIPEMD160WITHECDSA', 'RIPEMD160withECDSA');
  Falgorithms.Add(TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160.id,
    'RIPEMD160withECDSA');

  // Falgorithms.Add('GOST-3410', 'GOST3410');
  // Falgorithms.Add('GOST-3410-94', 'GOST3410');
  // Falgorithms.Add('GOST3411WITHGOST3410', 'GOST3410');
  // Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94.id,
  // 'GOST3410');

  // Falgorithms.Add('ECGOST-3410', 'ECGOST3410');
  // Falgorithms.Add('ECGOST-3410-2001', 'ECGOST3410');
  // Falgorithms.Add('GOST3411WITHECGOST3410', 'ECGOST3410');
  // Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001.id,
  // 'ECGOST3410');

  Foids.Add('SHA-1withECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
  Foids.Add('SHA-224withECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
  Foids.Add('SHA-256withECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
  Foids.Add('SHA-384withECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
  Foids.Add('SHA-512withECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);

  // Foids.Add('GOST3410',
  // TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94);
  //
  // Foids.Add('ECGOST3410',
  // TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001);

  // ECSCHNORR BSI

  Falgorithms.Add('SHA1/ECSCHNORR/BSI', 'SHA-1withECSCHNORRBSI');
  Falgorithms.Add('SHA-1/ECSCHNORR/BSI', 'SHA-1withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA1', 'SHA-1withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA-1', 'SHA-1withECSCHNORRBSI');
  Falgorithms.Add('SHA1WITHECSCHNORRBSI', 'SHA-1withECSCHNORRBSI');
  Falgorithms.Add('SHA-1WITHECSCHNORRBSI', 'SHA-1withECSCHNORRBSI');

  Falgorithms.Add('SHA224/ECSCHNORR/BSI', 'SHA-224withECSCHNORRBSI');
  Falgorithms.Add('SHA-224/ECSCHNORR/BSI', 'SHA-224withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA224', 'SHA-224withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA-224', 'SHA-224withECSCHNORRBSI');
  Falgorithms.Add('SHA224WITHECSCHNORRBSI', 'SHA-224withECSCHNORRBSI');
  Falgorithms.Add('SHA-224WITHECSCHNORRBSI', 'SHA-224withECSCHNORRBSI');

  Falgorithms.Add('SHA256/ECSCHNORR/BSI', 'SHA-256withECSCHNORRBSI');
  Falgorithms.Add('SHA-256/ECSCHNORR/BSI', 'SHA-256withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA256', 'SHA-256withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA-256', 'SHA-256withECSCHNORRBSI');
  Falgorithms.Add('SHA256WITHECSCHNORRBSI', 'SHA-256withECSCHNORRBSI');
  Falgorithms.Add('SHA-256WITHECSCHNORRBSI', 'SHA-256withECSCHNORRBSI');

  Falgorithms.Add('SHA384/ECSCHNORR/BSI', 'SHA-384withECSCHNORRBSI');
  Falgorithms.Add('SHA-384/ECSCHNORR/BSI', 'SHA-384withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA384', 'SHA-384withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA-384', 'SHA-384withECSCHNORRBSI');
  Falgorithms.Add('SHA384WITHECSCHNORRBSI', 'SHA-384withECSCHNORRBSI');
  Falgorithms.Add('SHA-384WITHECSCHNORRBSI', 'SHA-384withECSCHNORRBSI');

  Falgorithms.Add('SHA512/ECSCHNORR/BSI', 'SHA-512withECSCHNORRBSI');
  Falgorithms.Add('SHA-512/ECSCHNORR/BSI', 'SHA-512withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA512', 'SHA-512withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHSHA-512', 'SHA-512withECSCHNORRBSI');
  Falgorithms.Add('SHA512WITHECSCHNORRBSI', 'SHA-512withECSCHNORRBSI');
  Falgorithms.Add('SHA-512WITHECSCHNORRBSI', 'SHA-512withECSCHNORRBSI');

  Falgorithms.Add('RIPEMD160/ECSCHNORR/BSI', 'RIPEMD160withECSCHNORRBSI');
  Falgorithms.Add('ECSCHNORRBSIWITHRIPEMD160', 'RIPEMD160withECSCHNORRBSI');
  Falgorithms.Add('RIPEMD160WITHECSCHNORRBSI', 'RIPEMD160withECSCHNORRBSI');

  // ECSCHNORR ISO

  Falgorithms.Add('SHA1/ECSCHNORR/ISO', 'SHA-1withECSCHNORRISO');
  Falgorithms.Add('SHA-1/ECSCHNORR/ISO', 'SHA-1withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA1', 'SHA-1withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA-1', 'SHA-1withECSCHNORRISO');
  Falgorithms.Add('SHA1WITHECSCHNORRISO', 'SHA-1withECSCHNORRISO');
  Falgorithms.Add('SHA-1WITHECSCHNORRISO', 'SHA-1withECSCHNORRISO');

  Falgorithms.Add('SHA224/ECSCHNORR/ISO', 'SHA-224withECSCHNORRISO');
  Falgorithms.Add('SHA-224/ECSCHNORR/ISO', 'SHA-224withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA224', 'SHA-224withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA-224', 'SHA-224withECSCHNORRISO');
  Falgorithms.Add('SHA224WITHECSCHNORRISO', 'SHA-224withECSCHNORRISO');
  Falgorithms.Add('SHA-224WITHECSCHNORRISO', 'SHA-224withECSCHNORRISO');

  Falgorithms.Add('SHA256/ECSCHNORR/ISO', 'SHA-256withECSCHNORRISO');
  Falgorithms.Add('SHA-256/ECSCHNORR/ISO', 'SHA-256withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA256', 'SHA-256withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA-256', 'SHA-256withECSCHNORRISO');
  Falgorithms.Add('SHA256WITHECSCHNORRISO', 'SHA-256withECSCHNORRISO');
  Falgorithms.Add('SHA-256WITHECSCHNORRISO', 'SHA-256withECSCHNORRISO');

  Falgorithms.Add('SHA384/ECSCHNORR/ISO', 'SHA-384withECSCHNORRISO');
  Falgorithms.Add('SHA-384/ECSCHNORR/ISO', 'SHA-384withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA384', 'SHA-384withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA-384', 'SHA-384withECSCHNORRISO');
  Falgorithms.Add('SHA384WITHECSCHNORRISO', 'SHA-384withECSCHNORRISO');
  Falgorithms.Add('SHA-384WITHECSCHNORRISO', 'SHA-384withECSCHNORRISO');

  Falgorithms.Add('SHA512/ECSCHNORR/ISO', 'SHA-512withECSCHNORRISO');
  Falgorithms.Add('SHA-512/ECSCHNORR/ISO', 'SHA-512withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA512', 'SHA-512withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHSHA-512', 'SHA-512withECSCHNORRISO');
  Falgorithms.Add('SHA512WITHECSCHNORRISO', 'SHA-512withECSCHNORRISO');
  Falgorithms.Add('SHA-512WITHECSCHNORRISO', 'SHA-512withECSCHNORRISO');

  Falgorithms.Add('RIPEMD160/ECSCHNORR/ISO', 'RIPEMD160withECSCHNORRISO');
  Falgorithms.Add('ECSCHNORRISOWITHRIPEMD160', 'RIPEMD160withECSCHNORRISO');
  Falgorithms.Add('RIPEMD160WITHECSCHNORRISO', 'RIPEMD160withECSCHNORRISO');

  // ECSCHNORR ISOx

  Falgorithms.Add('SHA1/ECSCHNORR/ISOx', 'SHA-1withECSCHNORRISOx');
  Falgorithms.Add('SHA-1/ECSCHNORR/ISOx', 'SHA-1withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA1', 'SHA-1withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA-1', 'SHA-1withECSCHNORRISOx');
  Falgorithms.Add('SHA1WITHECSCHNORRISOx', 'SHA-1withECSCHNORRISOx');
  Falgorithms.Add('SHA-1WITHECSCHNORRISOx', 'SHA-1withECSCHNORRISOx');

  Falgorithms.Add('SHA224/ECSCHNORR/ISOx', 'SHA-224withECSCHNORRISOx');
  Falgorithms.Add('SHA-224/ECSCHNORR/ISOx', 'SHA-224withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA224', 'SHA-224withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA-224', 'SHA-224withECSCHNORRISOx');
  Falgorithms.Add('SHA224WITHECSCHNORRISOx', 'SHA-224withECSCHNORRISOx');
  Falgorithms.Add('SHA-224WITHECSCHNORRISOx', 'SHA-224withECSCHNORRISOx');

  Falgorithms.Add('SHA256/ECSCHNORR/ISOx', 'SHA-256withECSCHNORRISOx');
  Falgorithms.Add('SHA-256/ECSCHNORR/ISOx', 'SHA-256withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA256', 'SHA-256withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA-256', 'SHA-256withECSCHNORRISOx');
  Falgorithms.Add('SHA256WITHECSCHNORRISOx', 'SHA-256withECSCHNORRISOx');
  Falgorithms.Add('SHA-256WITHECSCHNORRISOx', 'SHA-256withECSCHNORRISOx');

  Falgorithms.Add('SHA384/ECSCHNORR/ISOx', 'SHA-384withECSCHNORRISOx');
  Falgorithms.Add('SHA-384/ECSCHNORR/ISOx', 'SHA-384withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA384', 'SHA-384withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA-384', 'SHA-384withECSCHNORRISOx');
  Falgorithms.Add('SHA384WITHECSCHNORRISOx', 'SHA-384withECSCHNORRISOx');
  Falgorithms.Add('SHA-384WITHECSCHNORRISOx', 'SHA-384withECSCHNORRISOx');

  Falgorithms.Add('SHA512/ECSCHNORR/ISOx', 'SHA-512withECSCHNORRISOx');
  Falgorithms.Add('SHA-512/ECSCHNORR/ISOx', 'SHA-512withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA512', 'SHA-512withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHSHA-512', 'SHA-512withECSCHNORRISOx');
  Falgorithms.Add('SHA512WITHECSCHNORRISOx', 'SHA-512withECSCHNORRISOx');
  Falgorithms.Add('SHA-512WITHECSCHNORRISOx', 'SHA-512withECSCHNORRISOx');

  Falgorithms.Add('RIPEMD160/ECSCHNORR/ISOx', 'RIPEMD160withECSCHNORRISOx');
  Falgorithms.Add('ECSCHNORRISOxWITHRIPEMD160', 'RIPEMD160withECSCHNORRISOx');
  Falgorithms.Add('RIPEMD160WITHECSCHNORRISOx', 'RIPEMD160withECSCHNORRISOx');


  // ECSCHNORR LIBSECP

  Falgorithms.Add('SHA1/ECSCHNORR/LIBSECP', 'SHA-1withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-1/ECSCHNORR/LIBSECP', 'SHA-1withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA1', 'SHA-1withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA-1', 'SHA-1withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA1WITHECSCHNORRLIBSECP', 'SHA-1withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-1WITHECSCHNORRLIBSECP', 'SHA-1withECSCHNORRLIBSECP');

  Falgorithms.Add('SHA224/ECSCHNORR/LIBSECP', 'SHA-224withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-224/ECSCHNORR/LIBSECP', 'SHA-224withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA224', 'SHA-224withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA-224', 'SHA-224withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA224WITHECSCHNORRLIBSECP', 'SHA-224withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-224WITHECSCHNORRLIBSECP', 'SHA-224withECSCHNORRLIBSECP');

  Falgorithms.Add('SHA256/ECSCHNORR/LIBSECP', 'SHA-256withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-256/ECSCHNORR/LIBSECP', 'SHA-256withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA256', 'SHA-256withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA-256', 'SHA-256withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA256WITHECSCHNORRLIBSECP', 'SHA-256withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-256WITHECSCHNORRLIBSECP', 'SHA-256withECSCHNORRLIBSECP');

  Falgorithms.Add('SHA384/ECSCHNORR/LIBSECP', 'SHA-384withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-384/ECSCHNORR/LIBSECP', 'SHA-384withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA384', 'SHA-384withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA-384', 'SHA-384withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA384WITHECSCHNORRLIBSECP', 'SHA-384withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-384WITHECSCHNORRLIBSECP', 'SHA-384withECSCHNORRLIBSECP');

  Falgorithms.Add('SHA512/ECSCHNORR/LIBSECP', 'SHA-512withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-512/ECSCHNORR/LIBSECP', 'SHA-512withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA512', 'SHA-512withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHSHA-512', 'SHA-512withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA512WITHECSCHNORRLIBSECP', 'SHA-512withECSCHNORRLIBSECP');
  Falgorithms.Add('SHA-512WITHECSCHNORRLIBSECP', 'SHA-512withECSCHNORRLIBSECP');

  Falgorithms.Add('RIPEMD160/ECSCHNORR/LIBSECP',
    'RIPEMD160withECSCHNORRLIBSECP');
  Falgorithms.Add('ECSCHNORRLIBSECPWITHRIPEMD160',
    'RIPEMD160withECSCHNORRLIBSECP');
  Falgorithms.Add('RIPEMD160WITHECSCHNORRLIBSECP',
    'RIPEMD160withECSCHNORRLIBSECP');

end;

class destructor TSignerUtilities.DestroySignerUtilities;
begin
  Falgorithms.Free;
  Foids.Free;
end;

class function TSignerUtilities.GetAlgorithms: TCryptoLibStringArray;
begin
  Result := Foids.Keys.ToArray;
end;

class function TSignerUtilities.GetEncodingName
  (const oid: IDerObjectIdentifier): String;
begin
  Falgorithms.TryGetValue(oid.id, Result);
end;

class function TSignerUtilities.GetObjectIdentifier(mechanism: String)
  : IDerObjectIdentifier;
var
  aliased: string;
begin
  if (mechanism = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SMechanismNil);
  end;

  mechanism := UpperCase(mechanism);
  if (Falgorithms.TryGetValue(mechanism, aliased)) then
  begin
    mechanism := aliased;
  end;

  Foids.TryGetValue(mechanism, Result);
end;

class function TSignerUtilities.GetSigner
  (const id: IDerObjectIdentifier): ISigner;
begin
  Result := GetSigner(id.id);
end;

class function TSignerUtilities.GetSigner(algorithm: String): ISigner;
var
  mechanism: string;
  DigestInstance: IDigest;
begin
  if (algorithm = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SAlgorithmNil);
  end;

  algorithm := UpperCase(algorithm);

  if (not Falgorithms.TryGetValue(algorithm, mechanism)) then
  begin
    mechanism := algorithm;
  end;

  if (mechanism = 'NONEwithECDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('NULL');

    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;
  if (mechanism = 'SHA-1withECDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;
  if (mechanism = 'SHA-224withECDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;
  if (mechanism = 'SHA-256withECDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;
  if (mechanism = 'SHA-384withECDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;
  if (mechanism = 'SHA-512withECDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := (TDsaDigestSigner.Create(TECDsaSigner.Create() as IECDsaSigner,
      DigestInstance));
    Exit;
  end;


  //

  if (mechanism = 'SHA-1withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(DigestInstance, 'BSI');
    Exit;
  end;
  if (mechanism = 'SHA-224withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(DigestInstance, 'BSI');
    Exit;
  end;
  if (mechanism = 'SHA-256withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(DigestInstance, 'BSI');
    Exit;
  end;
  if (mechanism = 'SHA-384withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(DigestInstance, 'BSI');
    Exit;
  end;
  if (mechanism = 'SHA-512withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(DigestInstance, 'BSI');
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(DigestInstance, 'BSI');
    Exit;
  end;

  //

  if (mechanism = 'SHA-1withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISO');
    Exit;
  end;
  if (mechanism = 'SHA-224withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISO');
    Exit;
  end;
  if (mechanism = 'SHA-256withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISO');
    Exit;
  end;
  if (mechanism = 'SHA-384withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISO');
    Exit;
  end;
  if (mechanism = 'SHA-512withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISO');
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISO');
    Exit;
  end;

  //

  if (CompareText(mechanism, 'SHA-1withECSCHNORRISOx') = 0) then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISOx');
    Exit;
  end;
  if (CompareText(mechanism, 'SHA-224withECSCHNORRISOx') = 0) then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISOx');
    Exit;
  end;
  if (CompareText(mechanism, 'SHA-256withECSCHNORRISOx') = 0) then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISOx');
    Exit;
  end;
  if (CompareText(mechanism, 'SHA-384withECSCHNORRISOx') = 0) then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISOx');
    Exit;
  end;
  if (CompareText(mechanism, 'SHA-512withECSCHNORRISOx') = 0) then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISOx');
    Exit;
  end;

  if (CompareText(mechanism, 'RIPEMD160withECSCHNORRISOx') = 0) then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(DigestInstance, 'ISOx');
    Exit;
  end;

  //

  if (mechanism = 'SHA-1withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(DigestInstance, 'LIBSECP');
    Exit;
  end;
  if (mechanism = 'SHA-224withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(DigestInstance, 'LIBSECP');
    Exit;
  end;
  if (mechanism = 'SHA-256withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(DigestInstance, 'LIBSECP');
    Exit;
  end;
  if (mechanism = 'SHA-384withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(DigestInstance, 'LIBSECP');
    Exit;
  end;
  if (mechanism = 'SHA-512withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(DigestInstance, 'LIBSECP');
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(DigestInstance, 'LIBSECP');
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedAlgorithm,
    [algorithm]);

end;

end.
