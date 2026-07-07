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

unit ClpParametersWithIV;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SIVNil = 'IV cannot be nil';

type
  /// <summary>
  /// Wrapper parameters object that carries an initialisation vector (<c>IV</c>) together with nested <see cref="ICipherParameters"/> (typically the key).
  /// </summary>
  /// <remarks>
  /// The nested <see cref="Parameters"/> reference may be nil to express "reuse previous key material" in some protocol paths;
  /// however the IV payload itself must always be supplied non-nil.
  /// </remarks>
  TParametersWithIV = class sealed(TInterfacedObject, IParametersWithIV,
    ICipherParameters)

  strict private
  var
    FParameters: ICipherParameters;
    FIv: TCryptoLibByteArray;

    function GetParameters: ICipherParameters; inline;

  public
    /// <summary>Copy the entire IV array into internal storage.</summary>
    /// <param name="AParameters">Underlying parameters (may be nil for key reuse scenarios).</param>
    /// <param name="AIv">Nonce/IV bytes.</param>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="AIv"/> is nil.</exception>
    constructor Create(const AParameters: ICipherParameters;
      const AIv: TCryptoLibByteArray); overload;
    /// <summary>Copy <paramref name="AIvLen"/> bytes starting at <paramref name="AIvOff"/>.</summary>
    constructor Create(const AParameters: ICipherParameters;
      const AIv: TCryptoLibByteArray; AIvOff, AIvLen: Int32); overload;
    destructor Destroy; override;
    /// <summary>Returns a defensive copy of the IV.</summary>
    function GetIV(): TCryptoLibByteArray; inline;
    property Parameters: ICipherParameters read GetParameters;
    /// <summary>Zeroise the cached IV buffer.</summary>
    procedure Clear(); inline;

  end;

implementation

{ TParametersWithIV }

constructor TParametersWithIV.Create(const AParameters: ICipherParameters;
  const AIv: TCryptoLibByteArray);
begin
  inherited Create();
  Create(AParameters, AIv, 0, System.Length(AIv))
end;

procedure TParametersWithIV.Clear;
begin
  TArrayUtilities.Fill(FIv, 0, System.Length(FIv), Byte(0));
end;

constructor TParametersWithIV.Create(const AParameters: ICipherParameters;
  const AIv: TCryptoLibByteArray; AIvOff, AIvLen: Int32);
begin
  inherited Create();
  // NOTE: 'parameters' may be null to imply key re-use
  if (AIv = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SIVNil);
  end;

  FParameters := AParameters;
  FIv := TArrayUtilities.CopyOfRange<Byte>(AIv, AIvOff, AIvOff + AIvLen);
end;

destructor TParametersWithIV.Destroy;
begin
  Clear();
  inherited Destroy;
end;

function TParametersWithIV.GetIV: TCryptoLibByteArray;
begin
  Result := System.Copy(FIv);
end;

function TParametersWithIV.GetParameters: ICipherParameters;
begin
  Result := FParameters;
end;

end.
