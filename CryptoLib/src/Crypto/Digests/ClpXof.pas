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

unit ClpXof;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  HlpIHash,
  HlpIHashInfo,
  ClpIDigest,
  ClpIXof,
  ClpDigest,
  ClpCheck,
  ClpCryptoLibTypes;

resourcestring
  SHashMustImplementIXof = 'hash must implement IXOF and IXOFStream';

type
  IXofCore = HlpIHashInfo.IXOF;
  IXofStreamCore = HlpIHashInfo.IXOFStream;
  TXof = class(TDigest, IDigest, IXof)

  strict private
    constructor Create(); overload;

  public
    constructor Create(const AHash: IHash); overload;

    function OutputFinal(const AOutput: TCryptoLibByteArray;
      AOutOff, AOutLen: Int32): Int32;

    function Output(const AOutput: TCryptoLibByteArray;
      AOutOff, AOutLen: Int32): Int32;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    function GetDigestSize(): Int32; override;

    function Clone(): IDigest; override;

  end;

implementation

{ TXof }

constructor TXof.Create;
begin
  inherited Create;
end;

constructor TXof.Create(const AHash: IHash);
begin
  if (not Supports(AHash, IXofCore)) or (not Supports(AHash, IXofStreamCore)) then
    raise EArgumentCryptoLibException.CreateRes(@SHashMustImplementIXof);
  inherited Create(AHash);
end;

function TXof.DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := OutputFinal(AOutput, AOutOff, GetDigestSize());
end;

function TXof.GetDigestSize: Int32;
var
 LXof: IXofCore;
begin
  LXof := FHash as IXofCore;
  Result := LXof.XOFSizeInBits shr 3;
end;

function TXof.OutputFinal(const AOutput: TCryptoLibByteArray;
  AOutOff, AOutLen: Int32): Int32;
var
 LLength: Int32;
begin
  TCheck.OutputLength(AOutput, AOutOff, AOutLen, 'output buffer is too short');
  LLength := Output(AOutput, AOutOff, AOutLen);
  Reset();
  Result := LLength;
end;

function TXof.Output(const AOutput: TCryptoLibByteArray;
  AOutOff, AOutLen: Int32): Int32;
var
 LStream: IXofStreamCore;
begin
  TCheck.OutputLength(AOutput, AOutOff, AOutLen, 'output buffer is too short');
  LStream := FHash as IXofStreamCore;
  LStream.Squeeze(AOutput, AOutOff, AOutLen);
  Result := AOutLen;
end;

function TXof.Clone(): IDigest;
var
 LXof: TXof;
begin
  LXof := TXof.Create();
  LXof.FHash := FHash.Clone();
  Result := LXof;
end;

end.
