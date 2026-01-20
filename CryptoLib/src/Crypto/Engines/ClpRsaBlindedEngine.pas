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

unit ClpRsaBlindedEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpICipherParameters,
  ClpIRsaKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpIRsa,
  ClpIAsymmetricBlockCipher,
  ClpIRsaBlindedEngine,
  ClpRsaCoreEngine,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpParameterUtilities,
  ClpCryptoLibTypes;

resourcestring
  SRsaEngineNotInitialised = 'RSA engine not initialised';

type
  /// <summary>
  /// RSA engine with blinding to protect against side-channel attacks.
  /// Implements IAsymmetricBlockCipher, wrapping an IRsa implementation.
  /// </summary>
  TRsaBlindedEngine = class(TInterfacedObject, IAsymmetricBlockCipher, IRsaBlindedEngine)

  strict private
  var
    FCore: IRsa;
    FKey: IRsaKeyParameters;
    FRandom: ISecureRandom;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;
    function InitSecureRandom(needed: Boolean; const provided: ISecureRandom): ISecureRandom; virtual;

  public
    constructor Create(); overload;
    constructor Create(const rsa: IRsa); overload;

    procedure Init(forEncryption: Boolean;
      const parameters: ICipherParameters);

    function ProcessBlock(const inBuf: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;

  end;

implementation

{ TRsaBlindedEngine }

constructor TRsaBlindedEngine.Create;
begin
  Create(TRsaCoreEngine.Create() as IRsa);
end;

constructor TRsaBlindedEngine.Create(const rsa: IRsa);
begin
  inherited Create();
  FCore := rsa;
end;

function TRsaBlindedEngine.GetAlgorithmName: String;
begin
  Result := 'RSA';
end;

function TRsaBlindedEngine.InitSecureRandom(needed: Boolean;
  const provided: ISecureRandom): ISecureRandom;
begin
  if needed then
  begin
    if provided <> nil then
      Result := provided
    else
      Result := TSecureRandom.Create();
  end
  else
    Result := nil;
end;

procedure TRsaBlindedEngine.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  providedRandom: ISecureRandom;
begin
  LParameters := TParameterUtilities.GetRandom(parameters, providedRandom);

  FCore.Init(forEncryption, LParameters);

  FKey := LParameters as IRsaKeyParameters;
  FRandom := InitSecureRandom(Supports(FKey, IRsaPrivateCrtKeyParameters), providedRandom);
end;

function TRsaBlindedEngine.GetInputBlockSize: Int32;
begin
  Result := FCore.InputBlockSize;
end;

function TRsaBlindedEngine.GetOutputBlockSize: Int32;
begin
  Result := FCore.OutputBlockSize;
end;

function TRsaBlindedEngine.ProcessBlock(const inBuf: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  input, output: TBigInteger;
  crtKey: IRsaPrivateCrtKeyParameters;
  e, m: TBigInteger;
  r, blind, unblind: TBigInteger;
  blindedInput, blindedResult: TBigInteger;
begin
  if FKey = nil then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SRsaEngineNotInitialised);
  end;

  input := FCore.ConvertInput(inBuf, inOff, inLen);

  // Only apply blinding for private CRT key operations
  if Supports(FKey, IRsaPrivateCrtKeyParameters, crtKey) then
  begin
    e := crtKey.PublicExponent;
    m := crtKey.Modulus;

    // Generate random r in range [1, m-1]
    r := TBigIntegers.CreateRandomInRange(TBigInteger.One, m.Subtract(TBigInteger.One), FRandom);

    // blind = r^e mod m
    blind := r.ModPow(e, m);
    // unblind = r^(-1) mod m
    unblind := TBigIntegers.ModOddInverse(m, r);

    // Blind the input: blindedInput = blind * input mod m
    blindedInput := blind.Multiply(input).&Mod(m);

    // Process the blinded input through the core engine
    blindedResult := FCore.ProcessBlock(blindedInput);

    // Unblind: output = unblind * blindedResult mod m
    output := unblind.Multiply(blindedResult).&Mod(m);
  end
  else
  begin
    // Public key operation or non-CRT private key - no blinding
    output := FCore.ProcessBlock(input);
  end;

  Result := FCore.ConvertOutput(output);
end;

end.
