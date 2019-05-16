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

unit ClpShortenedDigest;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  HlpIHash,
  ClpIDigest,
  ClpIShortenedDigest,
  ClpCryptoLibTypes;

resourcestring
  SBaseDigestNil = 'BaseDigest Nil';
  SBaseDigestSizeInsufficient =
    'BaseDigest output not large enough to support length';

type

  /// <summary>
  /// Wrapper class that reduces the output length of a particular digest to
  /// only the first n bytes of the digest function.
  /// </summary>
  TShortenedDigest = class sealed(TInterfacedObject, IShortenedDigest)

  strict private
  var
    FBaseDigest: IDigest;
    FLength: Int32;

    function GetAlgorithmName: String; inline;

  public

    /// <summary>
    /// Base constructor.
    /// </summary>
    /// <param name="baseDigest">
    /// underlying digest to use.
    /// </param>
    /// <param name="length">
    /// length in bytes of the output of doFinal.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if length is greater than baseDigest.GetDigestSize().
    /// </exception>
    /// <exception cref="ClpCryptoLibTypes|EArgumentNilCryptoLibException">
    /// if baseDigest is null.
    /// </exception>
    constructor Create(const baseDigest: IDigest; length: Int32);

    function GetDigestSize(): Int32;

    function GetByteLength(): Int32;

    function GetUnderlyingIHash: IHash;

    procedure Update(input: Byte);

    procedure BlockUpdate(const input: TCryptoLibByteArray; inOff, len: Int32);

    function DoFinal(const output: TCryptoLibByteArray; outOff: Int32)
      : Int32; overload;
    function DoFinal: TCryptoLibByteArray; overload;

    procedure Reset();

    property AlgorithmName: String read GetAlgorithmName;

    function Clone(): IDigest;

  end;

implementation

{ TShortenedDigest }

constructor TShortenedDigest.Create(const baseDigest: IDigest; length: Int32);
begin
  if (baseDigest = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SBaseDigestNil);
  end;

  if (length > baseDigest.GetDigestSize()) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SBaseDigestSizeInsufficient);
  end;

  Inherited Create();
  FBaseDigest := baseDigest;
  FLength := length;
end;

function TShortenedDigest.GetAlgorithmName: String;
begin
  result := Format('%s(%d)', [FBaseDigest.AlgorithmName, FLength * 8]);;
end;

function TShortenedDigest.GetByteLength: Int32;
begin
  result := FBaseDigest.GetByteLength();
end;

function TShortenedDigest.GetDigestSize: Int32;
begin
  result := FLength;
end;

function TShortenedDigest.GetUnderlyingIHash: IHash;
begin
  result := FBaseDigest.GetUnderlyingIHash;
end;

procedure TShortenedDigest.Update(input: Byte);
begin
  FBaseDigest.Update(input);
end;

procedure TShortenedDigest.BlockUpdate(const input: TCryptoLibByteArray;
  inOff, len: Int32);
begin
  FBaseDigest.BlockUpdate(input, inOff, len);
end;

function TShortenedDigest.DoFinal(const output: TCryptoLibByteArray;
  outOff: Int32): Int32;
var
  tmp: TCryptoLibByteArray;
begin
  System.SetLength(tmp, FBaseDigest.GetDigestSize());

  FBaseDigest.DoFinal(tmp, 0);

  System.Move(tmp[0], output[outOff], FLength * System.SizeOf(Byte));

  result := FLength;
end;

function TShortenedDigest.DoFinal: TCryptoLibByteArray;
begin
  System.SetLength(result, FLength);
  DoFinal(result, 0);
end;

procedure TShortenedDigest.Reset;
begin
  FBaseDigest.Reset();
end;

function TShortenedDigest.Clone(): IDigest;
begin
  result := (TShortenedDigest.Create(FBaseDigest.Clone(), FLength)
    as IShortenedDigest) as IDigest;
end;

end.
