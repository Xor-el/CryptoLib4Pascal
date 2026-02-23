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
  ClpDigest,
  ClpIDigest,
  ClpCryptoLibTypes;

resourcestring
  SBaseDigestNil = 'BaseDigest Nil';
  SBaseDigestSizeInsufficient =
    'BaseDigest output not large enough to support length';

type
  IShortenedDigest = interface(IDigest)
    ['{E19D250B-CAE0-4959-9211-80853FCF4ADD}']
  end;

  /// <summary>
  /// Wrapper class that reduces the output length of a particular digest to
  /// only the first n bytes of the digest function.
  /// </summary>
  TShortenedDigest = class sealed(TDigest, IDigest, IShortenedDigest)

  strict private
  var
    FBaseDigest: IDigest;
    FLength: Int32;

   strict protected
    function GetAlgorithmName: string; override;
    function GetUnderlyingHasher: IHash; override;

  public

    /// <summary>
    /// Base constructor.
    /// </summary>
    /// <param name="ABaseDigest">
    /// underlying digest to use.
    /// </param>
    /// <param name="length">
    /// length in bytes of the output of doFinal.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if length is greater than baseDigest.GetDigestSize().
    /// </exception>
    /// <exception cref="ClpCryptoLibTypes|EArgumentNilCryptoLibException">
    /// if ABaseDigest is null.
    /// </exception>
    constructor Create(const ABaseDigest: IDigest; ALength: Int32);

    function GetDigestSize(): Int32; override;

    function GetByteLength(): Int32; override;

    procedure Update(AInput: Byte);

    procedure BlockUpdate(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32);

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;
    function DoFinal: TCryptoLibByteArray; overload; override;

    procedure Reset(); override;

    property AlgorithmName: String read GetAlgorithmName;

    function Clone(): IDigest; override;

  end;

implementation

{ TShortenedDigest }

constructor TShortenedDigest.Create(const ABaseDigest: IDigest; ALength: Int32);
begin
  if (ABaseDigest = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SBaseDigestNil);
  end;

  if (ALength > ABaseDigest.GetDigestSize()) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SBaseDigestSizeInsufficient);
  end;

  inherited Create();
  FBaseDigest := ABaseDigest;
  FLength := ALength;
end;

function TShortenedDigest.GetAlgorithmName: String;
begin
  Result := Format('%s(%d)', [FBaseDigest.AlgorithmName, FLength * 8]);;
end;

function TShortenedDigest.GetByteLength: Int32;
begin
  Result := FBaseDigest.GetByteLength();
end;

function TShortenedDigest.GetDigestSize: Int32;
begin
  Result := FLength;
end;

function TShortenedDigest.GetUnderlyingHasher: IHash;
begin
  Result := FBaseDigest.UnderlyingHasher;
end;

procedure TShortenedDigest.Update(AInput: Byte);
begin
  FBaseDigest.Update(AInput);
end;

procedure TShortenedDigest.BlockUpdate(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  FBaseDigest.BlockUpdate(AInput, AInOff, ALen);
end;

function TShortenedDigest.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LTmp: TCryptoLibByteArray;
begin
  System.SetLength(LTmp, FBaseDigest.GetDigestSize());

  FBaseDigest.DoFinal(LTmp, 0);

  System.Move(LTmp[0], AOutput[AOutOff], FLength * System.SizeOf(Byte));

  Result := FLength;
end;

function TShortenedDigest.DoFinal: TCryptoLibByteArray;
begin
  System.SetLength(Result, FLength);
  DoFinal(Result, 0);
end;

procedure TShortenedDigest.Reset;
begin
  FBaseDigest.Reset();
end;

function TShortenedDigest.Clone(): IDigest;
begin
  Result := TShortenedDigest.Create(FBaseDigest.Clone(), FLength);
end;

end.
