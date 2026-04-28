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

unit ClpKMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  HlpIHashInfo,
  HlpHashFactory,
  ClpIMac,
  ClpIKMac,
  ClpMac,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SInvalidParameterKMac = 'KMac requires KeyParameter';

type

  /// <summary>
  /// <para>
  /// KMAC implementation based on FIPS 202
  /// </para>
  /// <para>
  /// Note: This is Just a Wrapper for <b>KMAC</b> Implementation in
  /// HashLib4Pascal
  /// </para>
  /// </summary>
  TKMac = class(TMac, IKMac, IMac)

  strict protected
  var
    FKMAC: HlpIHashInfo.IKMac;
    FOutputLengthInBits: UInt64;

    function GetAlgorithmName: string; override;

  public

    destructor Destroy(); override;

    procedure Clear(); override;

    function GetMacSize: Int32; override;

    procedure Update(AInput: Byte); override;
    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); override;
    procedure Init(const AParameters: ICipherParameters); override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    /// <summary>
    /// Reset the mac generator.
    /// </summary>
    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;

  end;

type
  TKMac128 = class(TKMac, IKMac, IMac)

  public
    constructor Create(const ACustomization: TCryptoLibByteArray;
      AOutputLengthInBits: UInt64);

  end;

type
  TKMac256 = class(TKMac, IKMac, IMac)

  public
    constructor Create(const ACustomization: TCryptoLibByteArray;
      AOutputLengthInBits: UInt64);

  end;

implementation

{ TKMac }

function TKMac.GetMacSize: Int32;
begin
  Result := FOutputLengthInBits shr 3;
end;

procedure TKMac.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  FKMAC.TransformBytes(AInput, AInOff, ALen);
end;

procedure TKMac.Clear();
begin
  FKMAC.Clear();
end;

destructor TKMac.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TKMac.DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBuf: TCryptoLibByteArray;
begin
  if (System.Length(AOutput) - AOutOff) < GetMacSize then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  LBuf := FKMAC.TransformFinal.GetBytes();
  System.Move(LBuf[0], AOutput[AOutOff], System.Length(LBuf) * System.SizeOf(Byte));
  Result := System.Length(LBuf);
end;

function TKMac.GetAlgorithmName: string;
var
  LName: String;
  LLow, LHigh: Int32;
begin
  LName := Self.ClassName;

  LLow := 1;
  LHigh := System.Length(LName);

  Result := Copy(LName, LLow + 1, LHigh - 1);
end;

procedure TKMac.Init(const AParameters: ICipherParameters);
var
  LKeyParam: IKeyParameter;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParam) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterKMac);
  FKMAC.Key := LKeyParam.GetKey();
  FKMAC.Initialize;
end;

procedure TKMac.Reset;
begin
  FKMAC.Initialize;
end;

procedure TKMac.Update(AInput: Byte);
begin
  FKMAC.TransformUntyped(AInput, System.SizeOf(Byte));
end;

{ TKMac128 }

constructor TKMac128.Create(const ACustomization: TCryptoLibByteArray;
  AOutputLengthInBits: UInt64);
begin
  Inherited Create();
  FOutputLengthInBits := AOutputLengthInBits;
  FKMAC := THashFactory.TKMac.CreateKMAC128(nil, ACustomization,
    FOutputLengthInBits);
end;

{ TKMac256 }

constructor TKMac256.Create(const ACustomization: TCryptoLibByteArray;
  AOutputLengthInBits: UInt64);
begin
  Inherited Create();
  FOutputLengthInBits := AOutputLengthInBits;
  FKMAC := THashFactory.TKMac.CreateKMAC256(nil, ACustomization,
    FOutputLengthInBits);
end;

end.
