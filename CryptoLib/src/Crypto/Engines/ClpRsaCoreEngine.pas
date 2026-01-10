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

unit ClpRsaCoreEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpIRsaKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpIRsa,
  ClpIRsaCoreEngine,
  ClpCryptoLibTypes;

resourcestring
  SRsaEngineNotInitialised = 'RSA engine not initialised';
  SInputTooLargeForRsa = 'input too large for RSA cipher.';
  SInputTooSmallForRsa = 'input too small for RSA cipher.';
  SFaultyDecryption = 'RSA engine faulty decryption/signing detected';

type
  /// <summary>
  /// The basic RSA algorithm.
  /// </summary>
  TRsaCoreEngine = class(TInterfacedObject, IRsa, IRsaCoreEngine)

  strict private
  var
    FKey: IRsaKeyParameters;
    FForEncryption: Boolean;
    FBitSize: Int32;

    procedure CheckInitialised;

  strict protected
    function GetInputBlockSize: Int32; virtual;
    function GetOutputBlockSize: Int32; virtual;

  public
    constructor Create();

    procedure Init(forEncryption: Boolean;
      const parameters: ICipherParameters); virtual;

    function ConvertInput(const buf: TCryptoLibByteArray; off, len: Int32): TBigInteger;
    function ConvertOutput(const res: TBigInteger): TCryptoLibByteArray;
    function ProcessBlock(const input: TBigInteger): TBigInteger;

    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;

  end;

implementation

{ TRsaCoreEngine }

constructor TRsaCoreEngine.Create;
begin
  inherited Create();
  FKey := nil;
end;

procedure TRsaCoreEngine.CheckInitialised;
begin
  if FKey = nil then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SRsaEngineNotInitialised);
  end;
end;

procedure TRsaCoreEngine.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  LParameters: ICipherParameters;
begin
  LParameters := parameters;
  LParameters := TParameterUtilities.IgnoreRandom(LParameters);

  FKey := LParameters as IRsaKeyParameters;
  FForEncryption := forEncryption;
  FBitSize := FKey.Modulus.BitLength;
end;

function TRsaCoreEngine.GetInputBlockSize: Int32;
begin
  CheckInitialised;

  if FForEncryption then
  begin
    Result := (FBitSize - 1) div 8;
  end
  else
  begin
    Result := (FBitSize + 7) div 8;
  end;
end;

function TRsaCoreEngine.GetOutputBlockSize: Int32;
begin
  CheckInitialised;

  if FForEncryption then
  begin
    Result := (FBitSize + 7) div 8;
  end
  else
  begin
    Result := (FBitSize - 1) div 8;
  end;
end;

function TRsaCoreEngine.ConvertInput(const buf: TCryptoLibByteArray;
  off, len: Int32): TBigInteger;
var
  maxLength: Int32;
begin
  CheckInitialised;

  maxLength := (FBitSize + 7) div 8;

  if len > maxLength then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooLargeForRsa);
  end;

  Result := TBigInteger.Create(1, buf, off, len);

  if Result.CompareTo(TBigInteger.One) <= 0 then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooSmallForRsa);
  end;

  if Result.CompareTo(FKey.Modulus.Subtract(TBigInteger.One)) >= 0 then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooLargeForRsa);
  end;
end;

function TRsaCoreEngine.ConvertOutput(const res: TBigInteger): TCryptoLibByteArray;
begin
  CheckInitialised;

  if FForEncryption then
  begin
    Result := TBigIntegers.AsUnsignedByteArray(GetOutputBlockSize, res);
  end
  else
  begin
    Result := TBigIntegers.AsUnsignedByteArray(res);
  end;
end;

function TRsaCoreEngine.ProcessBlock(const input: TBigInteger): TBigInteger;
var
  crtKey: IRsaPrivateCrtKeyParameters;
  p, q, dP, dQ, qInv: TBigInteger;
  mP, mQ, h, m, check: TBigInteger;
begin
  CheckInitialised;

  // Check if we have CRT parameters for private key operations
  if not Supports(FKey, IRsaPrivateCrtKeyParameters, crtKey) then
  begin
    Result := input.ModPow(FKey.Exponent, FKey.Modulus);
    Exit;
  end;

  // Use Chinese Remainder Theorem for faster decryption
  p := crtKey.P;
  q := crtKey.Q;
  dP := crtKey.DP;
  dQ := crtKey.DQ;
  qInv := crtKey.QInv;

  // mP = ((input Mod p) ^ dP) Mod p
  mP := input.Remainder(p).ModPow(dP, p);

  // mQ = ((input Mod q) ^ dQ) Mod q
  mQ := input.Remainder(q).ModPow(dQ, q);

  // h = qInv * (mP - mQ) Mod p
  h := mP.Subtract(mQ).Multiply(qInv).&Mod(p);

  // m = h * q + mQ
  m := h.Multiply(q).Add(mQ);

  // Defence against Arjen Lenstra's CRT attack
  check := m.ModPow(crtKey.PublicExponent, crtKey.Modulus);
  if not check.Equals(input) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SFaultyDecryption);
  end;

  Result := m;
end;

end.
