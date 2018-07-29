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
  ClpECNRSigner,
  ClpIECNRSigner,
  ClpIDigest,
  ClpDigestUtilities,
  ClpDsaDigestSigner,
  ClpECSchnorrSigner,
  ClpECSchnorrBSISigner,
  ClpIECSchnorrBSISigner,
  ClpECSchnorrISOSigner,
  ClpIECSchnorrISOSigner,
  ClpECSchnorrISOXSigner,
  ClpIECSchnorrISOXSigner,
  ClpECSchnorrLIBSECPSigner,
  ClpIECSchnorrLIBSECPSigner,
  ClpX9ObjectIdentifiers,
  ClpTeleTrusTObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpCryptoProObjectIdentifiers,
  ClpDsaSigner,
  ClpIDsaSigner,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpISigner,
  ClpIDerObjectIdentifier,
  ClpCryptoLibTypes;

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

 // TX9ObjectIdentifiers.Boot;
 // TOiwObjectIdentifiers.Boot;
 // TNistObjectIdentifiers.Boot;
 // TTeleTrusTObjectIdentifiers.Boot;
 // TCryptoProObjectIdentifiers.Boot;

  Falgorithms.Add('NONEWITHDSA', 'NONEwithDSA');
  Falgorithms.Add('DSAWITHNONE', 'NONEwithDSA');
  Falgorithms.Add('RAWDSA', 'NONEwithDSA');

  Falgorithms.Add('DSA', 'SHA-1withDSA');
  Falgorithms.Add('DSAWITHSHA1', 'SHA-1withDSA');
  Falgorithms.Add('DSAWITHSHA-1', 'SHA-1withDSA');
  Falgorithms.Add('SHA/DSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA1/DSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA-1/DSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA1WITHDSA', 'SHA-1withDSA');
  Falgorithms.Add('SHA-1WITHDSA', 'SHA-1withDSA');
  Falgorithms.Add(TX9ObjectIdentifiers.IdDsaWithSha1.id, 'SHA-1withDSA');
  Falgorithms.Add(TOiwObjectIdentifiers.DsaWithSha1.id, 'SHA-1withDSA');

  Falgorithms.Add('DSAWITHSHA224', 'SHA-224withDSA');
  Falgorithms.Add('DSAWITHSHA-224', 'SHA-224withDSA');
  Falgorithms.Add('SHA224/DSA', 'SHA-224withDSA');
  Falgorithms.Add('SHA-224/DSA', 'SHA-224withDSA');
  Falgorithms.Add('SHA224WITHDSA', 'SHA-224withDSA');
  Falgorithms.Add('SHA-224WITHDSA', 'SHA-224withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha224.id, 'SHA-224withDSA');

  Falgorithms.Add('DSAWITHSHA256', 'SHA-256withDSA');
  Falgorithms.Add('DSAWITHSHA-256', 'SHA-256withDSA');
  Falgorithms.Add('SHA256/DSA', 'SHA-256withDSA');
  Falgorithms.Add('SHA-256/DSA', 'SHA-256withDSA');
  Falgorithms.Add('SHA256WITHDSA', 'SHA-256withDSA');
  Falgorithms.Add('SHA-256WITHDSA', 'SHA-256withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha256.id, 'SHA-256withDSA');

  Falgorithms.Add('DSAWITHSHA384', 'SHA-384withDSA');
  Falgorithms.Add('DSAWITHSHA-384', 'SHA-384withDSA');
  Falgorithms.Add('SHA384/DSA', 'SHA-384withDSA');
  Falgorithms.Add('SHA-384/DSA', 'SHA-384withDSA');
  Falgorithms.Add('SHA384WITHDSA', 'SHA-384withDSA');
  Falgorithms.Add('SHA-384WITHDSA', 'SHA-384withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha384.id, 'SHA-384withDSA');

  Falgorithms.Add('DSAWITHSHA512', 'SHA-512withDSA');
  Falgorithms.Add('DSAWITHSHA-512', 'SHA-512withDSA');
  Falgorithms.Add('SHA512/DSA', 'SHA-512withDSA');
  Falgorithms.Add('SHA-512/DSA', 'SHA-512withDSA');
  Falgorithms.Add('SHA512WITHDSA', 'SHA-512withDSA');
  Falgorithms.Add('SHA-512WITHDSA', 'SHA-512withDSA');
  Falgorithms.Add(TNistObjectIdentifiers.DsaWithSha512.id, 'SHA-512withDSA');

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

//   Falgorithms.Add('GOST-3410', 'GOST3410');
//   Falgorithms.Add('GOST-3410-94', 'GOST3410');
//   Falgorithms.Add('GOST3411WITHGOST3410', 'GOST3410');
//   Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x94.id,
//   'GOST3410');

  // Falgorithms.Add('ECGOST-3410', 'ECGOST3410');
  // Falgorithms.Add('ECGOST-3410-2001', 'ECGOST3410');
  // Falgorithms.Add('GOST3411WITHECGOST3410', 'ECGOST3410');
  // Falgorithms.Add(TCryptoProObjectIdentifiers.GostR3411x94WithGostR3410x2001.id,
  // 'ECGOST3410');

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

  // ECSCHNORR ISOX

  Falgorithms.Add('SHA1/ECSCHNORR/ISOX', 'SHA-1withECSCHNORRISOX');
  Falgorithms.Add('SHA-1/ECSCHNORR/ISOX', 'SHA-1withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA1', 'SHA-1withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA-1', 'SHA-1withECSCHNORRISOX');
  Falgorithms.Add('SHA1WITHECSCHNORRISOX', 'SHA-1withECSCHNORRISOX');
  Falgorithms.Add('SHA-1WITHECSCHNORRISOX', 'SHA-1withECSCHNORRISOX');

  Falgorithms.Add('SHA224/ECSCHNORR/ISOX', 'SHA-224withECSCHNORRISOX');
  Falgorithms.Add('SHA-224/ECSCHNORR/ISOX', 'SHA-224withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA224', 'SHA-224withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA-224', 'SHA-224withECSCHNORRISOX');
  Falgorithms.Add('SHA224WITHECSCHNORRISOX', 'SHA-224withECSCHNORRISOX');
  Falgorithms.Add('SHA-224WITHECSCHNORRISOX', 'SHA-224withECSCHNORRISOX');

  Falgorithms.Add('SHA256/ECSCHNORR/ISOX', 'SHA-256withECSCHNORRISOX');
  Falgorithms.Add('SHA-256/ECSCHNORR/ISOX', 'SHA-256withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA256', 'SHA-256withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA-256', 'SHA-256withECSCHNORRISOX');
  Falgorithms.Add('SHA256WITHECSCHNORRISOX', 'SHA-256withECSCHNORRISOX');
  Falgorithms.Add('SHA-256WITHECSCHNORRISOX', 'SHA-256withECSCHNORRISOX');

  Falgorithms.Add('SHA384/ECSCHNORR/ISOX', 'SHA-384withECSCHNORRISOX');
  Falgorithms.Add('SHA-384/ECSCHNORR/ISOX', 'SHA-384withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA384', 'SHA-384withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA-384', 'SHA-384withECSCHNORRISOX');
  Falgorithms.Add('SHA384WITHECSCHNORRISOX', 'SHA-384withECSCHNORRISOX');
  Falgorithms.Add('SHA-384WITHECSCHNORRISOX', 'SHA-384withECSCHNORRISOX');

  Falgorithms.Add('SHA512/ECSCHNORR/ISOX', 'SHA-512withECSCHNORRISOX');
  Falgorithms.Add('SHA-512/ECSCHNORR/ISOX', 'SHA-512withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA512', 'SHA-512withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHSHA-512', 'SHA-512withECSCHNORRISOX');
  Falgorithms.Add('SHA512WITHECSCHNORRISOX', 'SHA-512withECSCHNORRISOX');
  Falgorithms.Add('SHA-512WITHECSCHNORRISOX', 'SHA-512withECSCHNORRISOX');

  Falgorithms.Add('RIPEMD160/ECSCHNORR/ISOX', 'RIPEMD160withECSCHNORRISOX');
  Falgorithms.Add('ECSCHNORRISOXWITHRIPEMD160', 'RIPEMD160withECSCHNORRISOX');
  Falgorithms.Add('RIPEMD160WITHECSCHNORRISOX', 'RIPEMD160withECSCHNORRISOX');


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

  Foids.Add('SHA-1withDSA', TX9ObjectIdentifiers.IdDsaWithSha1);

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

  if (mechanism = 'NONEwithDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('NULL');

    Result := (TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA-1withDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := (TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA-224withDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := (TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA-256withDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := (TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA-384withDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := (TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA-512withDSA') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := (TDsaDigestSigner.Create(TDsaSigner.Create() as IDsaSigner,
      DigestInstance));
    Exit;
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

  if (mechanism = 'SHA1WITHECNR') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := (TDsaDigestSigner.Create(TECNRSigner.Create() as IECNRSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA224WITHECNR') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := (TDsaDigestSigner.Create(TECNRSigner.Create() as IECNRSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA256WITHECNR') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := (TDsaDigestSigner.Create(TECNRSigner.Create() as IECNRSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA384WITHECNR') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := (TDsaDigestSigner.Create(TECNRSigner.Create() as IECNRSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA512WITHECNR') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := (TDsaDigestSigner.Create(TECNRSigner.Create() as IECNRSigner,
      DigestInstance));
    Exit;
  end;

  if (mechanism = 'SHA-1withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(TECSchnorrBSISigner.Create()
      as IECSchnorrBSISigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-224withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(TECSchnorrBSISigner.Create()
      as IECSchnorrBSISigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-256withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(TECSchnorrBSISigner.Create()
      as IECSchnorrBSISigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-384withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(TECSchnorrBSISigner.Create()
      as IECSchnorrBSISigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-512withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(TECSchnorrBSISigner.Create()
      as IECSchnorrBSISigner, DigestInstance);
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECSCHNORRBSI') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(TECSchnorrBSISigner.Create()
      as IECSchnorrBSISigner, DigestInstance);
    Exit;
  end;

  //

  if (mechanism = 'SHA-1withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(TECSchnorrISOSigner.Create()
      as IECSchnorrISOSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-224withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(TECSchnorrISOSigner.Create()
      as IECSchnorrISOSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-256withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(TECSchnorrISOSigner.Create()
      as IECSchnorrISOSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-384withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(TECSchnorrISOSigner.Create()
      as IECSchnorrISOSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-512withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(TECSchnorrISOSigner.Create()
      as IECSchnorrISOSigner, DigestInstance);
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECSCHNORRISO') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(TECSchnorrISOSigner.Create()
      as IECSchnorrISOSigner, DigestInstance);
    Exit;
  end;

  //

  if (mechanism = 'SHA-1withECSCHNORRISOX') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(TECSchnorrISOXSigner.Create()
      as IECSchnorrISOXSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-224withECSCHNORRISOX') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(TECSchnorrISOXSigner.Create()
      as IECSchnorrISOXSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-256withECSCHNORRISOX') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(TECSchnorrISOXSigner.Create()
      as IECSchnorrISOXSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-384withECSCHNORRISOX') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(TECSchnorrISOXSigner.Create()
      as IECSchnorrISOXSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-512withECSCHNORRISOX') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(TECSchnorrISOXSigner.Create()
      as IECSchnorrISOXSigner, DigestInstance);
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECSCHNORRISOX') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(TECSchnorrISOXSigner.Create()
      as IECSchnorrISOXSigner, DigestInstance);
    Exit;
  end;

  //

  if (mechanism = 'SHA-1withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-1');

    Result := TECSchnorrSigner.Create(TECSchnorrLIBSECPSigner.Create()
      as IECSchnorrLIBSECPSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-224withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-224');

    Result := TECSchnorrSigner.Create(TECSchnorrLIBSECPSigner.Create()
      as IECSchnorrLIBSECPSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-256withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-256');

    Result := TECSchnorrSigner.Create(TECSchnorrLIBSECPSigner.Create()
      as IECSchnorrLIBSECPSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-384withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-384');

    Result := TECSchnorrSigner.Create(TECSchnorrLIBSECPSigner.Create()
      as IECSchnorrLIBSECPSigner, DigestInstance);
    Exit;
  end;
  if (mechanism = 'SHA-512withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('SHA-512');

    Result := TECSchnorrSigner.Create(TECSchnorrLIBSECPSigner.Create()
      as IECSchnorrLIBSECPSigner, DigestInstance);
    Exit;
  end;

  if (mechanism = 'RIPEMD160withECSCHNORRLIBSECP') then
  begin
    DigestInstance := TDigestUtilities.GetDigest('RIPEMD-160');

    Result := TECSchnorrSigner.Create(TECSchnorrLIBSECPSigner.Create()
      as IECSchnorrLIBSECPSigner, DigestInstance);
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SUnRecognizedAlgorithm,
    [algorithm]);

end;

end.
