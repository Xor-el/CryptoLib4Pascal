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

unit ClpCryptoApiEntropySourceProvider;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpIRandomNumberGenerator,
  ClpRandomNumberGenerator;

resourcestring
  SRngNil = 'rng cannot be nil';

type
  /// <summary>
  /// <see cref="IEntropySourceProvider"/> implementation that
  /// wraps an <see cref="IRandomNumberGenerator"/>.
  /// </summary>
  TCryptoApiEntropySourceProvider = class sealed(TInterfacedObject,
    IEntropySourceProvider)
  strict private
  type
    /// <summary>
    /// Entropy source backed by a platform random number generator.
    /// </summary>
    TCryptoApiEntropySource = class sealed(TInterfacedObject, IEntropySource)
    strict private
      FRng: IRandomNumberGenerator;
      FIsPredictionResistant: Boolean;
      FEntropySize: Int32;
    strict protected
      function GetIsPredictionResistant: Boolean;
      function GetEntropy: TCryptoLibByteArray;
      function GetEntropySize: Int32;
    public
      constructor Create(const ARng: IRandomNumberGenerator;
        APredictionResistant: Boolean; AEntropySize: Int32);
    end;

  var
    FRng: IRandomNumberGenerator;
    FIsPredictionResistant: Boolean;

  public
    /// <summary>
    /// Create a provider using a default OS-backed random number generator with
    /// prediction resistance enabled.
    /// </summary>
    constructor Create(); overload;
    /// <summary>
    /// Create a provider that delegates entropy to <paramref name="ARng"/>.
    /// </summary>
    /// <param name="ARng">Underlying RNG; must not be nil.</param>
    /// <param name="AIsPredictionResistant">
    /// Whether returned sources are prediction-resistant.
    /// </param>
    constructor Create(const ARng: IRandomNumberGenerator;
      AIsPredictionResistant: Boolean); overload;
    /// <summary>
    /// Return an entropy source sized for <paramref name="ABitsRequired"/> bits.
    /// </summary>
    function Get(ABitsRequired: Int32): IEntropySource;
  end;

implementation

{ TCryptoApiEntropySourceProvider.TCryptoApiEntropySource }

constructor TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.Create(
  const ARng: IRandomNumberGenerator; APredictionResistant: Boolean;
  AEntropySize: Int32);
begin
  inherited Create;
  if ARng = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SRngNil);
  FRng := ARng;
  FIsPredictionResistant := APredictionResistant;
  FEntropySize := AEntropySize;
end;

function TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.GetEntropy
  : TCryptoLibByteArray;
begin
  System.SetLength(Result, (FEntropySize + 7) div 8);
  FRng.GetBytes(Result);
end;

function TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.GetEntropySize
  : Int32;
begin
  Result := FEntropySize;
end;

function TCryptoApiEntropySourceProvider.TCryptoApiEntropySource.
  GetIsPredictionResistant: Boolean;
begin
  Result := FIsPredictionResistant;
end;

{ TCryptoApiEntropySourceProvider }

constructor TCryptoApiEntropySourceProvider.Create;
begin
  Create(TRandomNumberGenerator.CreateRng(), True);
end;

constructor TCryptoApiEntropySourceProvider.Create(const ARng: IRandomNumberGenerator;
  AIsPredictionResistant: Boolean);
begin
  inherited Create;
  if ARng = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SRngNil);
  FRng := ARng;
  FIsPredictionResistant := AIsPredictionResistant;
end;

function TCryptoApiEntropySourceProvider.Get(ABitsRequired: Int32): IEntropySource;
begin
  Result := TCryptoApiEntropySource.Create(FRng, FIsPredictionResistant,
    ABitsRequired);
end;

end.
