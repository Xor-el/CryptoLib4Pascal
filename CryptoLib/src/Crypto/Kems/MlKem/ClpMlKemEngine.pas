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

unit ClpMlKemEngine;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpMlKemCore,
  ClpIMlKemCore,
  ClpIMlKemEngine,
  ClpDigestUtilities,
  ClpIDigest,
  ClpIXof,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes;

resourcestring
  SUnsupportedMlKemK = 'K: %d is not supported for ML-KEM';

type
  TMlKemEngine = class(TInterfacedObject, IMlKemEngine)
  public
    const
      N = MlKemN;
      Q = MlKemQ;
      QInv = MlKemQInv;
      SymBytes = MlKemSymBytes;
      SharedSecretBytes = 32;
      PolyBytes = MlKemPolyBytes;
      Eta2 = 2;
      SeedBytes = MlKemSymBytes * 2;
  strict private
  var
    FK: Int32;
    FPolyVecBytes: Int32;
    FPolyCompressedBytes: Int32;
    FPolyVecCompressedBytes: Int32;
    FEta1: Int32;
    FIndCpaPublicKeyBytes: Int32;
    FIndCpaSecretKeyBytes: Int32;
    FSecretKeyBytes: Int32;
    FCipherTextBytes: Int32;
    FIndCpa: IMlKemIndCpa;
    class procedure G(const AInput: TCryptoLibByteArray;
      const AOutput: TCryptoLibByteArray); static;
    class procedure H(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32); static;
    class procedure ImplDigest(const ADigest: IDigest; const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32); static;
    class procedure CMov(var ABuf: TCryptoLibByteArray; const AX: TCryptoLibByteArray;
      AXLen, ACond: Int32); static;
    class function FixedTimeEquals(ALen: Int32; const AA: TCryptoLibByteArray; AAOff: Int32;
      const AB: TCryptoLibByteArray; ABOff: Int32): Int32; static;
  public
    constructor Create(AK: Int32);

    function GetK: Int32;
    function GetPolyVecBytes: Int32;
    function GetPolyCompressedBytes: Int32;
    function GetPolyVecCompressedBytes: Int32;
    function GetEta1: Int32;
    function GetIndCpaPublicKeyBytes: Int32;
    function GetIndCpaSecretKeyBytes: Int32;
    function GetPublicKeyBytes: Int32;
    function GetSecretKeyBytes: Int32;
    function GetCipherTextBytes: Int32;

    function CheckDecapKeyHash(const ADecapKey: TCryptoLibByteArray): Boolean;
    function CheckEncapKeyModulus(const AEncapKey: TCryptoLibByteArray): Boolean;
    function CopyEncapKey(const ADecapKey: TCryptoLibByteArray): TCryptoLibByteArray;

    procedure GenerateKemKeyPair(const ARandom: ISecureRandom;
      out ASeed, AEncoding: TCryptoLibByteArray);
    procedure GenerateKemKeyPairFromSeed(const ASeed: TCryptoLibByteArray;
      out AEncoding: TCryptoLibByteArray);

    procedure KemDecrypt(const ADecapKey, AEncBuf: TCryptoLibByteArray; AEncOff: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff: Int32);
    procedure KemEncrypt(const AEncapKey, ARandBytes: TCryptoLibByteArray;
      const AEncBuf: TCryptoLibByteArray; AEncOff: Int32;
      const ASecBuf: TCryptoLibByteArray; ASecOff: Int32);
  end;

implementation

{ TMlKemEngine }

constructor TMlKemEngine.Create(AK: Int32);
begin
  inherited Create;
  FK := AK;
  case AK of
    2:
      begin
        FEta1 := 3;
        FPolyCompressedBytes := 128;
        FPolyVecCompressedBytes := AK * 320;
      end;
    3:
      begin
        FEta1 := 2;
        FPolyCompressedBytes := 128;
        FPolyVecCompressedBytes := AK * 320;
      end;
    4:
      begin
        FEta1 := 2;
        FPolyCompressedBytes := 160;
        FPolyVecCompressedBytes := AK * 352;
      end;
  else
    raise EArgumentCryptoLibException.CreateResFmt(@SUnsupportedMlKemK, [AK]);
  end;
  FPolyVecBytes := AK * PolyBytes;
  FIndCpaPublicKeyBytes := FPolyVecBytes + SymBytes;
  FIndCpaSecretKeyBytes := FPolyVecBytes;
  FCipherTextBytes := FPolyVecCompressedBytes + FPolyCompressedBytes;
  FSecretKeyBytes := FIndCpaSecretKeyBytes + FIndCpaPublicKeyBytes + 2 * SymBytes;
  FIndCpa := TMlKemIndCpa.Create(Self as IMlKemEngine);
end;

function TMlKemEngine.GetK: Int32;
begin
  Result := FK;
end;

function TMlKemEngine.GetPolyVecBytes: Int32;
begin
  Result := FPolyVecBytes;
end;

function TMlKemEngine.GetPolyCompressedBytes: Int32;
begin
  Result := FPolyCompressedBytes;
end;

function TMlKemEngine.GetPolyVecCompressedBytes: Int32;
begin
  Result := FPolyVecCompressedBytes;
end;

function TMlKemEngine.GetEta1: Int32;
begin
  Result := FEta1;
end;

function TMlKemEngine.GetIndCpaPublicKeyBytes: Int32;
begin
  Result := FIndCpaPublicKeyBytes;
end;

function TMlKemEngine.GetIndCpaSecretKeyBytes: Int32;
begin
  Result := FIndCpaSecretKeyBytes;
end;

function TMlKemEngine.GetPublicKeyBytes: Int32;
begin
  Result := FIndCpaPublicKeyBytes;
end;

function TMlKemEngine.GetSecretKeyBytes: Int32;
begin
  Result := FSecretKeyBytes;
end;

function TMlKemEngine.GetCipherTextBytes: Int32;
begin
  Result := FCipherTextBytes;
end;

function TMlKemEngine.CheckDecapKeyHash(const ADecapKey: TCryptoLibByteArray): Boolean;
var
  LK, LK384, LK768: Int32;
  LKH: TCryptoLibByteArray;
begin
  LK := FK;
  LK384 := LK * 384;
  LK768 := LK * 768;
  System.SetLength(LKH, SymBytes);
  H(ADecapKey, LK384, LK384 + 32, LKH, 0);
  Result := TArrayUtilities.FixedTimeEquals(SymBytes, LKH, 0, ADecapKey, LK768 + 32);
end;

function TMlKemEngine.CheckEncapKeyModulus(const AEncapKey: TCryptoLibByteArray): Boolean;
begin
  Result := TMlKemPolyVec.CheckModulus(FK, AEncapKey) < 0;
end;

function TMlKemEngine.CopyEncapKey(const ADecapKey: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(ADecapKey, FIndCpaSecretKeyBytes,
    FIndCpaSecretKeyBytes + FIndCpaPublicKeyBytes);
end;

procedure TMlKemEngine.GenerateKemKeyPair(const ARandom: ISecureRandom;
  out ASeed, AEncoding: TCryptoLibByteArray);
begin
  ASeed := TSecureRandom.GetNextBytes(ARandom, SymBytes * 2);
  GenerateKemKeyPairFromSeed(ASeed, AEncoding);
end;

procedure TMlKemEngine.GenerateKemKeyPairFromSeed(const ASeed: TCryptoLibByteArray;
  out AEncoding: TCryptoLibByteArray);
begin
  System.SetLength(AEncoding, FSecretKeyBytes);
  FIndCpa.GenerateKeyPair(ASeed, AEncoding);
  H(AEncoding, FIndCpaSecretKeyBytes, FIndCpaPublicKeyBytes, AEncoding,
    FSecretKeyBytes - SymBytes * 2);
  System.Move(ASeed[SymBytes], AEncoding[FSecretKeyBytes - SymBytes], SymBytes);
end;

class procedure TMlKemEngine.G(const AInput: TCryptoLibByteArray;
  const AOutput: TCryptoLibByteArray);
begin
  ImplDigest(TDigestUtilities.GetDigest('SHA3-512'), AInput, 0, System.Length(AInput), AOutput, 0);
end;

class procedure TMlKemEngine.H(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32);
begin
  ImplDigest(TDigestUtilities.GetDigest('SHA3-256'), AInput, AInOff, AInLen, AOutput, AOutOff);
end;

class procedure TMlKemEngine.ImplDigest(const ADigest: IDigest;
  const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32);
begin
  ADigest.BlockUpdate(AInput, AInOff, AInLen);
  ADigest.DoFinal(AOutput, AOutOff);
end;

class procedure TMlKemEngine.CMov(var ABuf: TCryptoLibByteArray;
  const AX: TCryptoLibByteArray; AXLen, ACond: Int32);
var
  LI, LRi, LDiff: Int32;
begin
  for LI := 0 to AXLen - 1 do
  begin
    LRi := ABuf[LI];
    LDiff := LRi xor AX[LI];
    LRi := LRi xor (LDiff and ACond);
    ABuf[LI] := Byte(LRi);
  end;
end;

class function TMlKemEngine.FixedTimeEquals(ALen: Int32; const AA: TCryptoLibByteArray;
  AAOff: Int32; const AB: TCryptoLibByteArray; ABOff: Int32): Int32;
var
  LI, LD: Int32;
begin
  LD := 0;
  for LI := 0 to ALen - 1 do
    LD := LD or (AA[AAOff + LI] xor AB[ABOff + LI]);
  LD := LD or (LD shr 16);
  LD := LD and $FFFF;
  Result := TBitOperations.Asr32(LD - 1, 31);
end;

procedure TMlKemEngine.KemDecrypt(const ADecapKey, AEncBuf: TCryptoLibByteArray; AEncOff: Int32;
  const ASecBuf: TCryptoLibByteArray; ASecOff: Int32);
var
  LBuf, LKr, LCmp, LImplicitRejection: TCryptoLibByteArray;
  LFail: Int32;
  LXof: IXof;
begin
  System.SetLength(LBuf, 2 * SymBytes);
  FIndCpa.Decrypt(AEncBuf, ADecapKey, AEncOff, 0, LBuf);
  System.Move(ADecapKey[FSecretKeyBytes - 2 * SymBytes], LBuf[SymBytes], SymBytes);
  System.SetLength(LKr, 2 * SymBytes);
  G(LBuf, LKr);
  System.SetLength(LCmp, FCipherTextBytes);
  FIndCpa.Encrypt(ADecapKey, LBuf, LKr, FIndCpaSecretKeyBytes, 0, SymBytes, LCmp, 0);
  LFail := FixedTimeEquals(FCipherTextBytes, LCmp, 0, AEncBuf, AEncOff) xor -1;
  System.SetLength(LImplicitRejection, SharedSecretBytes);
  LXof := TDigestUtilities.GetDigest('SHAKE256-512') as IXof;
  LXof.BlockUpdate(ADecapKey, FSecretKeyBytes - SymBytes, SymBytes);
  LXof.BlockUpdate(AEncBuf, AEncOff, FCipherTextBytes);
  LXof.OutputFinal(LImplicitRejection, 0, SharedSecretBytes);
  CMov(LKr, LImplicitRejection, SharedSecretBytes, LFail);
  System.Move(LKr[0], ASecBuf[ASecOff], SharedSecretBytes);
end;

procedure TMlKemEngine.KemEncrypt(const AEncapKey, ARandBytes: TCryptoLibByteArray;
  const AEncBuf: TCryptoLibByteArray; AEncOff: Int32;
  const ASecBuf: TCryptoLibByteArray; ASecOff: Int32);
var
  LBuf, LKr: TCryptoLibByteArray;
begin
  System.SetLength(LBuf, 2 * SymBytes);
  System.SetLength(LKr, 2 * SymBytes);
  System.Move(ARandBytes[0], LBuf[0], SymBytes);
  H(AEncapKey, 0, FIndCpaPublicKeyBytes, LBuf, SymBytes);
  G(LBuf, LKr);
  FIndCpa.Encrypt(AEncapKey, LBuf, LKr, 0, 0, SymBytes, AEncBuf, AEncOff);
  System.Move(LKr[0], ASecBuf[ASecOff], SharedSecretBytes);
end;

end.
