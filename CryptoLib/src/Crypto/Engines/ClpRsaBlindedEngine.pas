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

unit ClpRsaBlindedEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpICipherParameters,
  ClpIRsaParameters,
  ClpIRsa,
  ClpIAsymmetricBlockCipher,
  ClpIRsaBlindedEngine,
  ClpIRsaBlinding,
  ClpRsaBlindingTypes,
  ClpRsaCoreEngine,
  ClpISecureRandom,
  ClpCryptoServicesRegistrar,
  ClpParameterUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SRsaEngineNotInitialised = 'RSA engine not initialized';

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
    function InitSecureRandom(ANeeded: Boolean; const AProvided: ISecureRandom): ISecureRandom; virtual;

  public
    constructor Create(); overload;
    constructor Create(const ARsa: IRsa); overload;

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters);

    function ProcessBlock(const AInBuf: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

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

constructor TRsaBlindedEngine.Create(const ARsa: IRsa);
begin
  inherited Create();
  FCore := ARsa;
end;

function TRsaBlindedEngine.GetAlgorithmName: String;
begin
  Result := 'RSA';
end;

function TRsaBlindedEngine.InitSecureRandom(ANeeded: Boolean;
  const AProvided: ISecureRandom): ISecureRandom;
begin
  if ANeeded then
    Result := TCryptoServicesRegistrar.GetSecureRandom(AProvided)
  else
    Result := nil;
end;

procedure TRsaBlindedEngine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LProvidedRandom: ISecureRandom;
begin
  LParameters := TParameterUtilities.GetRandom(AParameters, LProvidedRandom);

  FCore.Init(AForEncryption, LParameters);

  FKey := LParameters as IRsaKeyParameters;
  FRandom := InitSecureRandom(Supports(FKey, IRsaPrivateCrtKeyParameters), LProvidedRandom);
end;

function TRsaBlindedEngine.GetInputBlockSize: Int32;
begin
  Result := FCore.InputBlockSize;
end;

function TRsaBlindedEngine.GetOutputBlockSize: Int32;
begin
  Result := FCore.OutputBlockSize;
end;

function TRsaBlindedEngine.ProcessBlock(const AInBuf: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LInput, LOutput: TBigInteger;
  LCrtKey: IRsaPrivateCrtKeyParameters;
  LBlinding: IRsaBlinding;
  LPair: TRsaBlindingPair;
  LBlindedInput, LBlindedResult: TBigInteger;
begin
  if FKey = nil then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SRsaEngineNotInitialised);
  end;

  LInput := FCore.ConvertInput(AInBuf, AInOff, AInLen);

  // Only apply blinding for private CRT key operations
  if Supports(FKey, IRsaPrivateCrtKeyParameters, LCrtKey) then
  begin
    LBlinding := LCrtKey.GetBlinding(FRandom);
    // advance-and-snapshot under the cache lock, then blind/sign/unblind on the
    // snapshot outside it, so concurrent signatures never share or corrupt a pair
    LBlinding.Acquire(LPair);
    LBlindedInput := LBlinding.Blind(LPair, LInput);
    LBlindedResult := FCore.ProcessBlock(LBlindedInput);
    LOutput := LBlinding.Unblind(LPair, LBlindedResult);
  end
  else
  begin
    // Public key operation or non-CRT private key - no blinding
    LOutput := FCore.ProcessBlock(LInput);
  end;

  Result := FCore.ConvertOutput(LOutput);
end;

end.
