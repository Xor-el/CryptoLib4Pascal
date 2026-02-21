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

unit ClpGMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIGMac,
  ClpIMac,
  ClpMac,
  ClpIGcmBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpAeadParameters,
  ClpIAeadParameters,
  ClpCryptoLibTypes;

resourcestring
  SGMacRequiresParametersWithIV = 'GMAC requires ParametersWithIV';
  SGMacRequiresKeyParameter = 'GMAC requires a KeyParameter within ParametersWithIV';

type
  TGMac = class sealed(TMac, IGMac, IMac)

  strict private
  var
    FCipher: IGcmBlockCipher;
    FMacSizeBits: Int32;

  strict protected
    function GetAlgorithmName: String; override;

  public
    constructor Create(const ACipher: IGcmBlockCipher); overload;
    constructor Create(const ACipher: IGcmBlockCipher;
      AMacSizeBits: Int32); overload;

    procedure Init(const AParameters: ICipherParameters); override;
    function GetMacSize: Int32; override;
    procedure Update(AInput: Byte); override;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray;
      AInOff, ALen: Int32); override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;
    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TGMac }

constructor TGMac.Create(const ACipher: IGcmBlockCipher);
begin
  Create(ACipher, 128);
end;

constructor TGMac.Create(const ACipher: IGcmBlockCipher;
  AMacSizeBits: Int32);
begin
  inherited Create();
  FCipher := ACipher;
  FMacSizeBits := AMacSizeBits;
end;

procedure TGMac.Init(const AParameters: ICipherParameters);
var
  LParam: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LKeyParam: IKeyParameter;
begin
  if Supports(AParameters, IParametersWithIV, LParam) then
  begin
    LIv := LParam.GetIV();
    if not Supports(LParam.Parameters, IKeyParameter, LKeyParam) then
      raise EArgumentCryptoLibException.CreateRes(@SGMacRequiresKeyParameter);
    FCipher.Init(True, TAeadParameters.Create(LKeyParam, FMacSizeBits, LIv)
      as IAeadParameters);
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SGMacRequiresParametersWithIV);
  end;
end;

function TGMac.GetAlgorithmName: String;
begin
  Result := FCipher.GetUnderlyingCipher().AlgorithmName + '-GMAC';
end;

function TGMac.GetMacSize: Int32;
begin
  Result := FMacSizeBits div 8;
end;

procedure TGMac.Update(AInput: Byte);
begin
  FCipher.ProcessAadByte(AInput);
end;

procedure TGMac.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  FCipher.ProcessAadBytes(AInput, AInOff, ALen);
end;

function TGMac.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  try
    Result := FCipher.DoFinal(AOutput, AOutOff);
  except
    on E: EInvalidCipherTextCryptoLibException do
      raise EInvalidOperationCryptoLibException.Create(E.ToString());
  end;
end;

procedure TGMac.Reset;
begin
  FCipher.Reset();
end;

end.
