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

unit ClpRsaBlindingEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpIRsaParameters,
  ClpIRsa,
  ClpRsaCoreEngine,
  ClpIAsymmetricBlockCipher,
  ClpIRsaBlindingEngine,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// This does your basic RSA Chaum's blinding and unblinding as outlined in
  /// "Handbook of Applied Cryptography", page 475. You need to use this if you are
  /// trying to get another party to generate signatures without them being aware
  /// of the message they are signing.
  /// </summary>
  TRsaBlindingEngine = class(TInterfacedObject, IAsymmetricBlockCipher, IRsaBlindingEngine)

  strict private
    FCore: IRsa;
    FKey: IRsaKeyParameters;
    FBlindingFactor: TBigInteger;
    FForEncryption: Boolean;

    function BlindMessage(const AMsg: TBigInteger): TBigInteger;
    function UnblindMessage(const ABlindedMsg: TBigInteger): TBigInteger;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;

  public
    constructor Create(); overload;
    constructor Create(const ARsa: IRsa); overload;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters);
    function ProcessBlock(const AInBuf: TCryptoLibByteArray;
      AInOff, AInLen: Int32): TCryptoLibByteArray;

    property AlgorithmName: String read GetAlgorithmName;
    property InputBlockSize: Int32 read GetInputBlockSize;
    property OutputBlockSize: Int32 read GetOutputBlockSize;

  end;

implementation

{ TRsaBlindingEngine }

constructor TRsaBlindingEngine.Create;
begin
  Create(TRsaCoreEngine.Create() as IRsa);
end;

constructor TRsaBlindingEngine.Create(const ARsa: IRsa);
begin
  inherited Create();
  FCore := ARsa;
end;

function TRsaBlindingEngine.GetAlgorithmName: String;
begin
  Result := 'RSA';
end;

procedure TRsaBlindingEngine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LP: IRsaBlindingParameters;
  LRParam: IParametersWithRandom;
begin
  if Supports(AParameters, IParametersWithRandom, LRParam) then
  begin
    if not Supports(LRParam.Parameters, IRsaBlindingParameters, LP) then
      raise EArgumentCryptoLibException.Create('Parameters must support IRsaBlindingParameters');
  end
  else
  begin
    if not Supports(AParameters, IRsaBlindingParameters, LP) then
      raise EArgumentCryptoLibException.Create('Parameters must support IRsaBlindingParameters');
  end;

  FCore.Init(AForEncryption, LP.PublicKey);

  FForEncryption := AForEncryption;
  FKey := LP.PublicKey;
  FBlindingFactor := LP.BlindingFactor;
end;

function TRsaBlindingEngine.GetInputBlockSize: Int32;
begin
  Result := FCore.InputBlockSize;
end;

function TRsaBlindingEngine.GetOutputBlockSize: Int32;
begin
  Result := FCore.OutputBlockSize;
end;

function TRsaBlindingEngine.ProcessBlock(const AInBuf: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LMsg: TBigInteger;
begin
  LMsg := FCore.ConvertInput(AInBuf, AInOff, AInLen);

  if FForEncryption then
    LMsg := BlindMessage(LMsg)
  else
    LMsg := UnblindMessage(LMsg);

  Result := FCore.ConvertOutput(LMsg);
end;

function TRsaBlindingEngine.BlindMessage(const AMsg: TBigInteger): TBigInteger;
var
  LBlindMsg: TBigInteger;
begin
  // msg * (blindingFactor ^ e) mod n
  LBlindMsg := FBlindingFactor.ModPow(FKey.Exponent, FKey.Modulus);
  LBlindMsg := AMsg.Multiply(LBlindMsg);
  Result := LBlindMsg.&Mod(FKey.Modulus);
end;

function TRsaBlindingEngine.UnblindMessage(const ABlindedMsg: TBigInteger): TBigInteger;
var
  LM, LBlindFactorInverse, LRes: TBigInteger;
begin
  LM := FKey.Modulus;
  LBlindFactorInverse := TBigIntegerUtilities.ModOddInverse(LM, FBlindingFactor);
  LRes := ABlindedMsg.Multiply(LBlindFactorInverse);
  Result := LRes.&Mod(LM);
end;

end.
