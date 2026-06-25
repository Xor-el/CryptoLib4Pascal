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

unit ClpBasicEntropySourceProvider;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIEntropySource,
  ClpIEntropySourceProvider,
  ClpISecureRandom,
  ClpSecureRandom;

resourcestring
  SSecureRandomNil = 'secureRandom cannot be nil';

type
  /// <summary>
  /// <see cref="IEntropySourceProvider"/> implementation that
  /// wraps an <see cref="ISecureRandom"/> and uses GetNextBytes for each entropy request.
  /// </summary>
  TBasicEntropySourceProvider = class sealed(TInterfacedObject, IEntropySourceProvider)
  strict private
  type
    /// <summary>
    /// Entropy source backed by a secure random instance.
    /// </summary>
    TBasicEntropySource = class sealed(TInterfacedObject, IEntropySource)
    strict private
      FSecureRandom: ISecureRandom;
      FIsPredictionResistant: Boolean;
      FEntropySize: Int32;
    strict protected
      function GetIsPredictionResistant: Boolean;
      function GetEntropy: TCryptoLibByteArray;
      function GetEntropySize: Int32;
    public
      constructor Create(const ASecureRandom: ISecureRandom;
        APredictionResistant: Boolean; AEntropySize: Int32);
    end;

  var
    FSecureRandom: ISecureRandom;
    FIsPredictionResistant: Boolean;

  public
    /// <summary>
    /// Create a provider that delegates entropy to <paramref name="ASecureRandom"/>.
    /// </summary>
    /// <param name="ASecureRandom">Underlying secure random; must not be nil.</param>
    /// <param name="AIsPredictionResistant">
    /// Whether returned sources are prediction-resistant.
    /// </param>
    constructor Create(const ASecureRandom: ISecureRandom;
      AIsPredictionResistant: Boolean);
    /// <summary>
    /// Return an entropy source sized for <paramref name="ABitsRequired"/> bits.
    /// </summary>
    function Get(ABitsRequired: Int32): IEntropySource;
  end;

implementation

{ TBasicEntropySourceProvider.TBasicEntropySource }

constructor TBasicEntropySourceProvider.TBasicEntropySource.Create(
  const ASecureRandom: ISecureRandom; APredictionResistant: Boolean;
  AEntropySize: Int32);
begin
  inherited Create;
  if ASecureRandom = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSecureRandomNil);
  FSecureRandom := ASecureRandom;
  FIsPredictionResistant := APredictionResistant;
  FEntropySize := AEntropySize;
end;

function TBasicEntropySourceProvider.TBasicEntropySource.GetEntropy
  : TCryptoLibByteArray;
begin
  Result := TSecureRandom.GetNextBytes(FSecureRandom, (FEntropySize + 7) div 8);
end;

function TBasicEntropySourceProvider.TBasicEntropySource.GetEntropySize: Int32;
begin
  Result := FEntropySize;
end;

function TBasicEntropySourceProvider.TBasicEntropySource.GetIsPredictionResistant
  : Boolean;
begin
  Result := FIsPredictionResistant;
end;

{ TBasicEntropySourceProvider }

constructor TBasicEntropySourceProvider.Create(const ASecureRandom: ISecureRandom;
  AIsPredictionResistant: Boolean);
begin
  inherited Create;
  if ASecureRandom = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSecureRandomNil);
  FSecureRandom := ASecureRandom;
  FIsPredictionResistant := AIsPredictionResistant;
end;

function TBasicEntropySourceProvider.Get(ABitsRequired: Int32): IEntropySource;
begin
  Result := TBasicEntropySource.Create(FSecureRandom, FIsPredictionResistant,
    ABitsRequired);
end;

end.
