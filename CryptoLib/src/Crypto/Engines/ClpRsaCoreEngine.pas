{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
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
  ClpBigIntegerUtilities,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpIRsaParameters,
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

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); virtual;

    function ConvertInput(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): TBigInteger;
    function ConvertOutput(const ARes: TBigInteger): TCryptoLibByteArray;
    function ProcessBlock(const AInput: TBigInteger): TBigInteger;

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

procedure TRsaCoreEngine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
begin
  LParameters := AParameters;
  LParameters := TParameterUtilities.IgnoreRandom(LParameters);

  FKey := LParameters as IRsaKeyParameters;
  FForEncryption := AForEncryption;
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

function TRsaCoreEngine.ConvertInput(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32): TBigInteger;
var
  LMaxLength: Int32;
begin
  CheckInitialised;

  LMaxLength := (FBitSize + 7) div 8;

  if ALen > LMaxLength then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooLargeForRsa);
  end;

  Result := TBigInteger.Create(1, ABuf, AOff, ALen);

  if Result.CompareTo(TBigInteger.One) <= 0 then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooSmallForRsa);
  end;

  if Result.CompareTo(FKey.Modulus.Subtract(TBigInteger.One)) >= 0 then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SInputTooLargeForRsa);
  end;
end;

function TRsaCoreEngine.ConvertOutput(const ARes: TBigInteger): TCryptoLibByteArray;
begin
  CheckInitialised;

  if FForEncryption then
  begin
    Result := TBigIntegerUtilities.AsUnsignedByteArray(GetOutputBlockSize, ARes);
  end
  else
  begin
    Result := TBigIntegerUtilities.AsUnsignedByteArray(ARes);
  end;
end;

function TRsaCoreEngine.ProcessBlock(const AInput: TBigInteger): TBigInteger;
var
  LCrtKey: IRsaPrivateCrtKeyParameters;
  LP, LQ, LDP, LDQ, LQInv: TBigInteger;
  LMP, LMQ, LH, LM, LCheck: TBigInteger;
begin
  CheckInitialised;

  // Check if we have CRT parameters for private key operations
  if not Supports(FKey, IRsaPrivateCrtKeyParameters, LCrtKey) then
  begin
    Result := AInput.ModPow(FKey.Exponent, FKey.Modulus);
    Exit;
  end;

  // Use Chinese Remainder Theorem for faster decryption
  LP := LCrtKey.P;
  LQ := LCrtKey.Q;
  LDP := LCrtKey.DP;
  LDQ := LCrtKey.DQ;
  LQInv := LCrtKey.QInv;

  // mP = ((input Mod p) ^ dP) Mod p
  LMP := AInput.Remainder(LP).ModPow(LDP, LP);

  // mQ = ((input Mod q) ^ dQ) Mod q
  LMQ := AInput.Remainder(LQ).ModPow(LDQ, LQ);

  // h = qInv * (mP - mQ) Mod p
  LH := LMP.Subtract(LMQ).Multiply(LQInv).&Mod(LP);

  // m = h * q + mQ
  LM := LH.Multiply(LQ).Add(LMQ);

  // Defence against Arjen Lenstra's CRT attack
  LCheck := LM.ModPow(LCrtKey.PublicExponent, LCrtKey.Modulus);
  if not LCheck.Equals(AInput) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SFaultyDecryption);
  end;

  Result := LM;
end;

end.
