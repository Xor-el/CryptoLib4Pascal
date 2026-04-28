{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                               * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                               * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }
{ *                                                                               * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpSipHashMac;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  HlpIHash,
  HlpIHashInfo,
  HlpSipHash,
  ClpIMac,
  ClpISipHashMac,
  ClpMac,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpCryptoLibTypes;

resourcestring
  SOutputBufferTooShort_SipHash = 'Output Buffer Too Short';
  SInvalidParameterSipHashMac = 'SipHashMac requires KeyParameter';
  SInvalidSipHashKeyLength = 'SipHashMac requires a 128-bit (16 byte) key';

type

  /// <summary>
  /// SipHash MAC wrapper over HashLib4Pascal TSipHash implementations.
  /// </summary>
  TSipHashMac = class sealed(TMac, ISipHashMac, IMac)

  strict private
  var
    FHash: IHash;

    class var FNameMap: TDictionary<string, string>;

    class function NormalizeHashLibName(const AName: string): string; static;

  strict protected
    function GetAlgorithmName: String; override;

  public
    class constructor Create;
    class destructor Destroy;

    constructor Create(const AHash: IHash);

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

implementation

{ TSipHashMac }

class constructor TSipHashMac.Create;
begin
  FNameMap := TDictionary<string, string>.Create;
  FNameMap.Add('SipHash2_4', 'SipHash-2-4');
end;

class destructor TSipHashMac.Destroy;
begin
  FNameMap.Free;
end;

class function TSipHashMac.NormalizeHashLibName(const AName: string): string;
begin
  if (AName <> '') and (AName[1] = 'T') then
    Result := Copy(AName, 2, System.Length(AName) - 1)
  else
    Result := AName;
end;

constructor TSipHashMac.Create(const AHash: IHash);
begin
  inherited Create();

  if not (AHash is TSipHash) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterSipHashMac);
  end;

  FHash := AHash;
end;

procedure TSipHashMac.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  FHash.TransformBytes(AInput, AInOff, ALen);
end;

procedure TSipHashMac.Clear;
begin
  // let the underlying hash manage its own lifetime; nothing special to clear here
end;

function TSipHashMac.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBuf: TCryptoLibByteArray;
begin
  if (System.Length(AOutput) - AOutOff) < GetMacSize then
  begin
    raise EDataLengthCryptoLibException.CreateRes
      (@SOutputBufferTooShort_SipHash);
  end;

  LBuf := FHash.TransformFinal.GetBytes();
  System.Move(LBuf[0], AOutput[AOutOff],
    System.Length(LBuf) * System.SizeOf(Byte));
  Result := System.Length(LBuf);
end;

function TSipHashMac.GetAlgorithmName: string;
var
  LRawName, LNormalized, LMapped: string;
begin
  LRawName := FHash.Name;
  LNormalized := NormalizeHashLibName(LRawName);

  Result := LNormalized;
  if FNameMap.TryGetValue(Result, LMapped) then
    Result := LMapped;
end;

function TSipHashMac.GetMacSize: Int32;
begin
  Result := FHash.HashSize;
end;

procedure TSipHashMac.Init(const AParameters: ICipherParameters);
var
  LKeyParam: IKeyParameter;
  LKey: TCryptoLibByteArray;
  LHashWithKey: IHashWithKey;
begin
  if not Supports(AParameters, IKeyParameter, LKeyParam) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterSipHashMac);
  end;

  LKey := LKeyParam.GetKey();
  if System.Length(LKey) <> 16 then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSipHashKeyLength);
  end;

  LHashWithKey := FHash as IHashWithKey;
  LHashWithKey.Key := LKey;

  FHash.Initialize;
end;

procedure TSipHashMac.Reset;
begin
  FHash.Initialize;
end;

procedure TSipHashMac.Update(AInput: Byte);
begin
  FHash.TransformUntyped(AInput, System.SizeOf(Byte));
end;

end.

