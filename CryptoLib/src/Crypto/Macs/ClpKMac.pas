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

unit ClpKMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  HlpIHashInfo,
  HlpHashFactory,
  ClpIMac,
  ClpIKMac,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output Buffer Too Short';

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
  TKMac = class(TInterfacedObject, IKMac, IMac)

  strict protected
  var
    FKMAC: HlpIHashInfo.IKMac;
    FOutputLengthInBits: UInt64;

    function GetAlgorithmName: string; inline;

  public

    destructor Destroy(); override;

    procedure Clear();

    function GetMacSize: Int32; inline;

    procedure Update(input: Byte);
    procedure BlockUpdate(const input: TCryptoLibByteArray; inOff, len: Int32);
    procedure Init(const parameters: ICipherParameters);
    function DoFinal(const output: TCryptoLibByteArray; outOff: Int32)
      : Int32; overload;
    function DoFinal: TCryptoLibByteArray; overload;

    /// <summary>
    /// Reset the mac generator.
    /// </summary>
    procedure Reset();

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
  result := FOutputLengthInBits shr 3;
end;

procedure TKMac.BlockUpdate(const input: TCryptoLibByteArray;
  inOff, len: Int32);
begin
  FKMAC.TransformBytes(input, inOff, len);
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

function TKMac.DoFinal(const output: TCryptoLibByteArray; outOff: Int32): Int32;
var
  buf: TCryptoLibByteArray;
begin

  if (System.Length(output) - outOff) < GetMacSize then
  begin
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);
  end
  else
  begin
    buf := DoFinal();
    System.Move(buf[0], output[outOff], System.Length(buf) *
      System.SizeOf(Byte));
  end;
  result := System.Length(buf);
end;

function TKMac.DoFinal: TCryptoLibByteArray;
begin
  result := FKMAC.TransformFinal.GetBytes();
end;

function TKMac.GetAlgorithmName: string;
var
  LName: String;
  LowPoint, HighPoint: Int32;
begin
  LName := Self.ClassName;
{$IFDEF DELPHIXE3_UP}
  LowPoint := System.Low(LName);
  HighPoint := System.High(LName);
{$ELSE}
  LowPoint := 1;
  HighPoint := System.Length(LName);
{$ENDIF DELPHIXE3_UP}
  result := Copy(LName, LowPoint + 1, HighPoint - 1);
end;

procedure TKMac.Init(const parameters: ICipherParameters);
begin
  FKMAC.Key := (parameters as IKeyParameter).GetKey();
  FKMAC.Initialize;
end;

procedure TKMac.Reset;
begin
  FKMAC.Initialize;
end;

procedure TKMac.Update(input: Byte);
begin
  FKMAC.TransformUntyped(input, System.SizeOf(Byte));
end;

{ TKMac128 }

constructor TKMac128.Create(const ACustomization: TCryptoLibByteArray;
  AOutputLengthInBits: UInt64);
begin
  Inherited Create();
  FOutputLengthInBits := AOutputLengthInBits;
  FKMAC := THashFactory.TKMac.CreateKMAC128(Nil, ACustomization,
    FOutputLengthInBits);
end;

{ TKMac256 }

constructor TKMac256.Create(const ACustomization: TCryptoLibByteArray;
  AOutputLengthInBits: UInt64);
begin
  Inherited Create();
  FOutputLengthInBits := AOutputLengthInBits;
  FKMAC := THashFactory.TKMac.CreateKMAC256(Nil, ACustomization,
    FOutputLengthInBits);
end;

end.
