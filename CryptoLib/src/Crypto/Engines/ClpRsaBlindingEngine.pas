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

    function BlindMessage(const msg: TBigInteger): TBigInteger;
    function UnblindMessage(const blindedMsg: TBigInteger): TBigInteger;

  strict protected
    function GetAlgorithmName: String;
    function GetInputBlockSize: Int32;
    function GetOutputBlockSize: Int32;

  public
    constructor Create(); overload;
    constructor Create(const rsa: IRsa); overload;

    procedure Init(forEncryption: Boolean; const parameters: ICipherParameters);
    function ProcessBlock(const inBuf: TCryptoLibByteArray;
      inOff, inLen: Int32): TCryptoLibByteArray;

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

constructor TRsaBlindingEngine.Create(const rsa: IRsa);
begin
  inherited Create();
  FCore := rsa;
end;

function TRsaBlindingEngine.GetAlgorithmName: String;
begin
  Result := 'RSA';
end;

procedure TRsaBlindingEngine.Init(forEncryption: Boolean;
  const parameters: ICipherParameters);
var
  p: IRsaBlindingParameters;
  rParam: IParametersWithRandom;
begin
  if Supports(parameters, IParametersWithRandom, rParam) then
    p := rParam.Parameters as IRsaBlindingParameters
  else
    p := parameters as IRsaBlindingParameters;

  FCore.Init(forEncryption, p.PublicKey);

  FForEncryption := forEncryption;
  FKey := p.PublicKey;
  FBlindingFactor := p.BlindingFactor;
end;

function TRsaBlindingEngine.GetInputBlockSize: Int32;
begin
  Result := FCore.InputBlockSize;
end;

function TRsaBlindingEngine.GetOutputBlockSize: Int32;
begin
  Result := FCore.OutputBlockSize;
end;

function TRsaBlindingEngine.ProcessBlock(const inBuf: TCryptoLibByteArray;
  inOff, inLen: Int32): TCryptoLibByteArray;
var
  msg: TBigInteger;
begin
  msg := FCore.ConvertInput(inBuf, inOff, inLen);

  if FForEncryption then
    msg := BlindMessage(msg)
  else
    msg := UnblindMessage(msg);

  Result := FCore.ConvertOutput(msg);
end;

function TRsaBlindingEngine.BlindMessage(const msg: TBigInteger): TBigInteger;
var
  blindMsg: TBigInteger;
begin
  // msg * (blindingFactor ^ e) mod n
  blindMsg := FBlindingFactor.ModPow(FKey.Exponent, FKey.Modulus);
  blindMsg := msg.Multiply(blindMsg);
  Result := blindMsg.&Mod(FKey.Modulus);
end;

function TRsaBlindingEngine.UnblindMessage(const blindedMsg: TBigInteger): TBigInteger;
var
  m, blindFactorInverse, res: TBigInteger;
begin
  m := FKey.Modulus;
  blindFactorInverse := TBigIntegerUtilities.ModOddInverse(m, FBlindingFactor);
  res := blindedMsg.Multiply(blindFactorInverse);
  Result := res.&Mod(m);
end;

end.
