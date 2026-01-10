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

unit ClpTeleTrusTObjectIdentifiers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpIAsn1Objects;

type
  TTeleTrusTObjectIdentifiers = class sealed(TObject)

  strict private

  class var

    FIsBooted: Boolean;
    FTeleTrusT, FAlgorithm, FEncryptionAlgorithm, FHashAlgorithm,
      FSignatureAlgorithm, FSignatureScheme,
      FRipeMD160, FRipeMD128, FRipeMD256,
      FRsaSignature, FRsaSignatureWithRipeMD160, FRsaSignatureWithRipeMD128,
      FRsaSignatureWithRipeMD256,
      FECSign, FECSignWithSha1, FECSignWithRipeMD160, FECSignWithMD2,
      FECSignWithMD5, FTttEcg, FEcStdCurvesAndGeneration,
      FEccBrainpool, FEllipticCurve,
      FVersionOne, FBrainpoolP160R1, FBrainpoolP160T1, FBrainpoolP192R1,
      FBrainpoolP192T1, FBrainpoolP224R1, FBrainpoolP224T1, FBrainpoolP256R1,
      FBrainpoolP256T1, FBrainpoolP320R1, FBrainpoolP320T1, FBrainpoolP384R1,
      FBrainpoolP384T1, FBrainpoolP512R1, FBrainpoolP512T1
      : IDerObjectIdentifier;

    class function GetTeleTrusT: IDerObjectIdentifier; static; inline;
    class function GetAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetTeleTrusTAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetEncryptionAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetHashAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetSignatureAlgorithm: IDerObjectIdentifier; static; inline;
    class function GetSignatureScheme: IDerObjectIdentifier; static; inline;
    class function GetRipeMD128: IDerObjectIdentifier; static; inline;
    class function GetRipeMD160: IDerObjectIdentifier; static; inline;
    class function GetRipeMD256: IDerObjectIdentifier; static; inline;
    class function GetRsaSignature: IDerObjectIdentifier; static; inline;
    class function GetRsaSignatureWithRipeMD160: IDerObjectIdentifier; static; inline;
    class function GetRsaSignatureWithRipeMD128: IDerObjectIdentifier; static; inline;
    class function GetRsaSignatureWithRipeMD256: IDerObjectIdentifier; static; inline;
    class function GetECSign: IDerObjectIdentifier; static; inline;
    class function GetECSignWithSha1: IDerObjectIdentifier; static; inline;
    class function GetECSignWithRipeMD160: IDerObjectIdentifier; static; inline;
    class function GetECSignWithMD2: IDerObjectIdentifier; static; inline;
    class function GetECSignWithMD5: IDerObjectIdentifier; static; inline;
    class function GetTttEcg: IDerObjectIdentifier; static; inline;
    class function GetEcStdCurvesAndGeneration: IDerObjectIdentifier; static; inline;

    class function GetBrainpoolP160R1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP160T1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP192R1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP192T1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP224R1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP224T1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP256R1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP256T1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP320R1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP320T1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP384R1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP384T1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP512R1: IDerObjectIdentifier; static; inline;
    class function GetBrainpoolP512T1: IDerObjectIdentifier; static; inline;
    class function GetEccBrainpool: IDerObjectIdentifier; static; inline;
    class function GetEllipticCurve: IDerObjectIdentifier; static; inline;
    class function GetVersionOne: IDerObjectIdentifier; static; inline;

    class constructor TeleTrusTObjectIdentifiers();

  public

    class property TeleTrusT: IDerObjectIdentifier read GetTeleTrusT;
    class property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    class property TeleTrusTAlgorithm: IDerObjectIdentifier read GetTeleTrusTAlgorithm;
    class property EncryptionAlgorithm: IDerObjectIdentifier read GetEncryptionAlgorithm;
    class property HashAlgorithm: IDerObjectIdentifier read GetHashAlgorithm;
    class property SignatureAlgorithm: IDerObjectIdentifier read GetSignatureAlgorithm;
    class property SignatureScheme: IDerObjectIdentifier read GetSignatureScheme;
    class property RipeMD160: IDerObjectIdentifier read GetRipeMD160;
    class property RipeMD128: IDerObjectIdentifier read GetRipeMD128;
    class property RipeMD256: IDerObjectIdentifier read GetRipeMD256;
    class property RsaSignature: IDerObjectIdentifier read GetRsaSignature;
    class property RsaSignatureWithRipeMD160: IDerObjectIdentifier read GetRsaSignatureWithRipeMD160;
    class property RsaSignatureWithRipeMD128: IDerObjectIdentifier read GetRsaSignatureWithRipeMD128;
    class property RsaSignatureWithRipeMD256: IDerObjectIdentifier read GetRsaSignatureWithRipeMD256;
    class property ECSign: IDerObjectIdentifier read GetECSign;
    class property ECSignWithSha1: IDerObjectIdentifier read GetECSignWithSha1;
    class property ECSignWithRipeMD160: IDerObjectIdentifier read GetECSignWithRipeMD160;
    class property ECSignWithMD2: IDerObjectIdentifier read GetECSignWithMD2;
    class property ECSignWithMD5: IDerObjectIdentifier read GetECSignWithMD5;
    class property TttEcg: IDerObjectIdentifier read GetTttEcg;
    class property EcStdCurvesAndGeneration: IDerObjectIdentifier read GetEcStdCurvesAndGeneration;

    class property EccBrainpool: IDerObjectIdentifier read GetEccBrainpool;
    class property EllipticCurve: IDerObjectIdentifier read GetEllipticCurve;
    class property VersionOne: IDerObjectIdentifier read GetVersionOne;
    class property BrainpoolP160R1: IDerObjectIdentifier
      read GetBrainpoolP160R1;
    class property BrainpoolP160T1: IDerObjectIdentifier
      read GetBrainpoolP160T1;
    class property BrainpoolP192R1: IDerObjectIdentifier
      read GetBrainpoolP192R1;
    class property BrainpoolP192T1: IDerObjectIdentifier
      read GetBrainpoolP192T1;
    class property BrainpoolP224R1: IDerObjectIdentifier
      read GetBrainpoolP224R1;
    class property BrainpoolP224T1: IDerObjectIdentifier
      read GetBrainpoolP224T1;
    class property BrainpoolP256R1: IDerObjectIdentifier
      read GetBrainpoolP256R1;
    class property BrainpoolP256T1: IDerObjectIdentifier
      read GetBrainpoolP256T1;
    class property BrainpoolP320R1: IDerObjectIdentifier
      read GetBrainpoolP320R1;
    class property BrainpoolP320T1: IDerObjectIdentifier
      read GetBrainpoolP320T1;
    class property BrainpoolP384R1: IDerObjectIdentifier
      read GetBrainpoolP384R1;
    class property BrainpoolP384T1: IDerObjectIdentifier
      read GetBrainpoolP384T1;
    class property BrainpoolP512R1: IDerObjectIdentifier
      read GetBrainpoolP512R1;
    class property BrainpoolP512T1: IDerObjectIdentifier
      read GetBrainpoolP512T1;

    class procedure Boot(); static;

  end;

implementation

{ TTeleTrusTObjectIdentifiers }

class function TTeleTrusTObjectIdentifiers.GetTeleTrusT: IDerObjectIdentifier;
begin
  result := FTeleTrusT;
end;

class function TTeleTrusTObjectIdentifiers.GetAlgorithm: IDerObjectIdentifier;
begin
  result := FAlgorithm;
end;

class function TTeleTrusTObjectIdentifiers.GetTeleTrusTAlgorithm: IDerObjectIdentifier;
begin
  result := FAlgorithm;
end;

class function TTeleTrusTObjectIdentifiers.GetEncryptionAlgorithm: IDerObjectIdentifier;
begin
  result := FEncryptionAlgorithm;
end;

class function TTeleTrusTObjectIdentifiers.GetHashAlgorithm: IDerObjectIdentifier;
begin
  result := FHashAlgorithm;
end;

class function TTeleTrusTObjectIdentifiers.GetSignatureAlgorithm: IDerObjectIdentifier;
begin
  result := FSignatureAlgorithm;
end;

class function TTeleTrusTObjectIdentifiers.GetSignatureScheme: IDerObjectIdentifier;
begin
  result := FSignatureScheme;
end;

class function TTeleTrusTObjectIdentifiers.GetRipeMD128: IDerObjectIdentifier;
begin
  result := FRipeMD128;
end;

class function TTeleTrusTObjectIdentifiers.GetRipeMD160: IDerObjectIdentifier;
begin
  result := FRipeMD160;
end;

class function TTeleTrusTObjectIdentifiers.GetRipeMD256: IDerObjectIdentifier;
begin
  result := FRipeMD256;
end;

class function TTeleTrusTObjectIdentifiers.GetRsaSignature: IDerObjectIdentifier;
begin
  result := FRsaSignature;
end;

class function TTeleTrusTObjectIdentifiers.GetRsaSignatureWithRipeMD160: IDerObjectIdentifier;
begin
  result := FRsaSignatureWithRipeMD160;
end;

class function TTeleTrusTObjectIdentifiers.GetRsaSignatureWithRipeMD128: IDerObjectIdentifier;
begin
  result := FRsaSignatureWithRipeMD128;
end;

class function TTeleTrusTObjectIdentifiers.GetRsaSignatureWithRipeMD256: IDerObjectIdentifier;
begin
  result := FRsaSignatureWithRipeMD256;
end;

class function TTeleTrusTObjectIdentifiers.GetECSign: IDerObjectIdentifier;
begin
  result := FECSign;
end;

class function TTeleTrusTObjectIdentifiers.GetECSignWithSha1: IDerObjectIdentifier;
begin
  result := FECSignWithSha1;
end;

class function TTeleTrusTObjectIdentifiers.GetECSignWithRipeMD160: IDerObjectIdentifier;
begin
  result := FECSignWithRipeMD160;
end;

class function TTeleTrusTObjectIdentifiers.GetECSignWithMD2: IDerObjectIdentifier;
begin
  result := FECSignWithMD2;
end;

class function TTeleTrusTObjectIdentifiers.GetECSignWithMD5: IDerObjectIdentifier;
begin
  result := FECSignWithMD5;
end;

class function TTeleTrusTObjectIdentifiers.GetTttEcg: IDerObjectIdentifier;
begin
  result := FTttEcg;
end;

class function TTeleTrusTObjectIdentifiers.GetEcStdCurvesAndGeneration: IDerObjectIdentifier;
begin
  result := FEcStdCurvesAndGeneration;
end;

class function TTeleTrusTObjectIdentifiers.GetEccBrainpool: IDerObjectIdentifier;
begin
  result := FEccBrainpool;
end;

class function TTeleTrusTObjectIdentifiers.GetVersionOne: IDerObjectIdentifier;
begin
  result := FVersionOne;
end;

class function TTeleTrusTObjectIdentifiers.GetEllipticCurve: IDerObjectIdentifier;
begin
  result := FEllipticCurve;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP160R1: IDerObjectIdentifier;
begin
  result := FBrainpoolP160R1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP160T1: IDerObjectIdentifier;
begin
  result := FBrainpoolP160T1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP192R1: IDerObjectIdentifier;
begin
  result := FBrainpoolP192R1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP192T1: IDerObjectIdentifier;
begin
  result := FBrainpoolP192T1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP224R1: IDerObjectIdentifier;
begin
  result := FBrainpoolP224R1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP224T1: IDerObjectIdentifier;
begin
  result := FBrainpoolP224T1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP256R1: IDerObjectIdentifier;
begin
  result := FBrainpoolP256R1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP256T1: IDerObjectIdentifier;
begin
  result := FBrainpoolP256T1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP320R1: IDerObjectIdentifier;
begin
  result := FBrainpoolP320R1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP320T1: IDerObjectIdentifier;
begin
  result := FBrainpoolP320T1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP384R1: IDerObjectIdentifier;
begin
  result := FBrainpoolP384R1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP384T1: IDerObjectIdentifier;
begin
  result := FBrainpoolP384T1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP512R1: IDerObjectIdentifier;
begin
  result := FBrainpoolP512R1;
end;

class function TTeleTrusTObjectIdentifiers.GetBrainpoolP512T1: IDerObjectIdentifier;
begin
  result := FBrainpoolP512T1;
end;

class procedure TTeleTrusTObjectIdentifiers.Boot;
begin
  if not FIsBooted then
  begin
    // Base OID: 1.3.36
    FTeleTrusT := TDerObjectIdentifier.Create('1.3.36');
    FAlgorithm := FTeleTrusT.Branch('3');

    // Algorithm sub-branches
    FEncryptionAlgorithm := FAlgorithm.Branch('1');
    FHashAlgorithm := FAlgorithm.Branch('2');
    FSignatureAlgorithm := FAlgorithm.Branch('3');
    FSignatureScheme := FAlgorithm.Branch('4');

    // Hash algorithms
    FRipeMD160 := FHashAlgorithm.Branch('1');
    FRipeMD128 := FHashAlgorithm.Branch('2');
    FRipeMD256 := FHashAlgorithm.Branch('3');

    // RSA Signatures
    FRsaSignature := FSignatureAlgorithm.Branch('1');
    FRsaSignatureWithRipeMD160 := FRsaSignature.Branch('2');
    FRsaSignatureWithRipeMD128 := FRsaSignature.Branch('3');
    FRsaSignatureWithRipeMD256 := FRsaSignature.Branch('4');

    // EC Signatures
    FECSign := FSignatureAlgorithm.Branch('2');
    FECSignWithSha1 := FECSign.Branch('1');
    FECSignWithRipeMD160 := FECSign.Branch('2');
    FECSignWithMD2 := FECSign.Branch('3');
    FECSignWithMD5 := FECSign.Branch('4');
    FTttEcg := FECSign.Branch('5');
    FEcStdCurvesAndGeneration := FECSign.Branch('8');

    // Brainpool curves
    FEccBrainpool := FEcStdCurvesAndGeneration;
    FEllipticCurve := FEccBrainpool.Branch('1');
    FVersionOne := FEllipticCurve.Branch('1');

    FBrainpoolP160R1 := FVersionOne.Branch('1');
    FBrainpoolP160T1 := FVersionOne.Branch('2');
    FBrainpoolP192R1 := FVersionOne.Branch('3');
    FBrainpoolP192T1 := FVersionOne.Branch('4');
    FBrainpoolP224R1 := FVersionOne.Branch('5');
    FBrainpoolP224T1 := FVersionOne.Branch('6');
    FBrainpoolP256R1 := FVersionOne.Branch('7');
    FBrainpoolP256T1 := FVersionOne.Branch('8');
    FBrainpoolP320R1 := FVersionOne.Branch('9');
    FBrainpoolP320T1 := FVersionOne.Branch('10');
    FBrainpoolP384R1 := FVersionOne.Branch('11');
    FBrainpoolP384T1 := FVersionOne.Branch('12');
    FBrainpoolP512R1 := FVersionOne.Branch('13');
    FBrainpoolP512T1 := FVersionOne.Branch('14');

    FIsBooted := True;
  end;
end;

class constructor TTeleTrusTObjectIdentifiers.TeleTrusTObjectIdentifiers;
begin
  TTeleTrusTObjectIdentifiers.Boot;
end;

end.

