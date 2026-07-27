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

unit ClpAbstractAeadBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpIAeadBlockCipher,
  ClpAbstractAeadCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base for the block-cipher-backed AEAD modes (GCM, EAX, OCB, CCM, GCM-SIV).
  /// Adds the <see cref="IAeadBlockCipher" /> surface (block size + underlying
  /// cipher) and the streaming output-size template: encrypt =
  /// <c>buffered+len+FMacSize</c>, decrypt = <c>max(0, buffered+len-FMacSize)</c>,
  /// update = the block-aligned round-down. Streaming modes (GCM/EAX/OCB) use it
  /// by overriding <see cref="GetBufferedLength" />; one-shot modes (CCM/GCM-SIV)
  /// override the size methods wholesale.
  /// </summary>
  TAbstractAeadBlockCipher = class abstract(TAbstractAeadCipher,
    IAeadBlockCipher)

  strict protected
  var
    FBlockSize: Int32;
    // Cipher reported by GetUnderlyingCipher; each mode sets it at construction
    // (raw block cipher for GCM/OCB/CCM/GCM-SIV, the CTR wrapper for EAX).
    FUnderlyingCipher: IBlockCipher;

    /// <summary>Bytes currently buffered (not yet emitted). Drives the streaming
    /// output-size template; overridden per mode to return its buffer position.</summary>
    function GetBufferedLength(): Int32; virtual; abstract;

    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    function GetBlockSize(): Int32; virtual;

    function GetUpdateOutputSize(ALen: Int32): Int32; override;
    function GetOutputSize(ALen: Int32): Int32; override;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
  end;

implementation

{ TAbstractAeadBlockCipher }

function TAbstractAeadBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FUnderlyingCipher;
end;

function TAbstractAeadBlockCipher.GetBlockSize: Int32;
begin
  Result := FBlockSize;
end;

function TAbstractAeadBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + GetBufferedLength();

  if FForEncryption then
  begin
    Result := LTotalData + FMacSize;
    Exit;
  end;

  if LTotalData < FMacSize then
    Result := 0
  else
    Result := LTotalData - FMacSize;
end;

function TAbstractAeadBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + GetBufferedLength();
  if not FForEncryption then
  begin
    if LTotalData < FMacSize then
    begin
      Result := 0;
      Exit;
    end;
    LTotalData := LTotalData - FMacSize;
  end;
  Result := LTotalData - (LTotalData mod FBlockSize);
end;

end.
