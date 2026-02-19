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

unit ClpHMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  HlpIHashInfo,
  HlpHashFactory,
  ClpIMac,
  ClpIHMac,
  ClpMac,
  ClpIDigest,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SInvalidParameterHMac = 'HMAC requires KeyParameter';

type

  /// <summary>
  /// <para>
  /// HMAC implementation based on RFC2104 <br />H(K XOR opad, H(K XOR
  /// ipad, text))
  /// </para>
  /// <para>
  /// Note: This is Just a Wrapper for <b>HMAC</b> Implementation in
  /// HashLib4Pascal
  /// </para>
  /// </summary>
  THMac = class sealed(TMac, IHMac, IMac)

  strict private
  var
    FDigest: IDigest;
    FHMAC: HlpIHashInfo.IHMac;

    function GetAlgorithmName: string; inline;

  public
    constructor Create(const ADigest: IDigest);

    destructor Destroy(); override;

    procedure Clear(); override;

    function GetUnderlyingDigest: IDigest; inline;
    function GetMacSize: Int32; override;

    procedure Update(AInput: Byte);
    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32);
    procedure Init(const AParameters: ICipherParameters);
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    /// <summary>
    /// Reset the mac generator.
    /// </summary>
    procedure Reset();

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ THMac }

function THMac.GetMacSize: Int32;
begin
  Result := FHMAC.HashSize;
end;

procedure THMac.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  FHMAC.TransformBytes(AInput, AInOff, ALen);
end;

procedure THMac.Clear();
begin
  FHMAC.Clear();
end;

constructor THMac.Create(const ADigest: IDigest);
begin
  Inherited Create();
  FDigest := ADigest;
  FHMAC := THashFactory.THMac.CreateHMAC(FDigest.GetUnderlyingIHash);
end;

destructor THMac.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function THMac.DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBuf: TCryptoLibByteArray;
begin
  if (System.Length(AOutput) - AOutOff) < GetMacSize then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  LBuf := FHMAC.TransformFinal.GetBytes();
  System.Move(LBuf[0], AOutput[AOutOff], System.Length(LBuf) * System.SizeOf(Byte));
  Result := System.Length(LBuf);
end;

function THMac.GetAlgorithmName: string;
begin
  Result := FDigest.AlgorithmName + '/HMAC';
end;

function THMac.GetUnderlyingDigest: IDigest;
begin
  Result := FDigest;
end;

procedure THMac.Init(const AParameters: ICipherParameters);
var
  LKeyParam: IKeyParameter;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParam) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterHMac);
  FHMAC.Key := LKeyParam.GetKey();
  FHMAC.Initialize;
end;

procedure THMac.Reset;
begin
  FHMAC.Initialize;
end;

procedure THMac.Update(AInput: Byte);
begin
  FHMAC.TransformUntyped(AInput, System.SizeOf(Byte));
end;

end.
