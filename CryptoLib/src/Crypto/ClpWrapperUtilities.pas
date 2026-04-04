{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpWrapperUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIWrapper,
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpIAsn1Objects,
  ClpCollectionUtilities,
  ClpCryptoLibComparers,
  ClpEnumUtilities,
  ClpNistObjectIdentifiers,
  ClpAesEngine,
  ClpIAesEngine,
  ClpAesWrapEngine,
  ClpAesWrapPadEngine,
  ClpRfc3211WrapEngine,
  ClpCipherUtilities,
  ClpCryptoLibTypes;

resourcestring
  SWrapperNotRecognised = 'Wrapper "%s" not recognised.';
  SNotInitialisedForWrapping = 'Not initialised for wrapping';
  SNotInitialisedForUnwrapping = 'Not initialised for unwrapping';

type
  TWrapperUtilities = class sealed(TObject)

  strict private
  type
    TWrapAlgorithm = (
      AESRFC3211WRAP,
      AESWRAP,
      AESWRAPPAD);

    TBufferedCipherWrapper = class(TInterfacedObject, IWrapper)
    strict private
      FCipher: IBufferedCipher;
      FForWrapping: Boolean;
    strict protected
     function GetAlgorithmName: String;
    public
      constructor Create(const ACipher: IBufferedCipher);
      property AlgorithmName: String read GetAlgorithmName;
      procedure Init(AForWrapping: Boolean; const AParameters: ICipherParameters);
      function Wrap(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray;
      function Unwrap(const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray;
    end;

  class var
    FAlgorithms: TDictionary<String, String>;

    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  public
    class function GetWrapper(const AOid: IDerObjectIdentifier): IWrapper; overload; static;
    class function GetWrapper(const AAlgorithm: String): IWrapper; overload; static;
    class function GetAlgorithmName(const AOid: IDerObjectIdentifier): String; static;

  end;

implementation

{ TWrapperUtilities }

class constructor TWrapperUtilities.Create;
begin
  Boot;
end;

class destructor TWrapperUtilities.Destroy;
begin
  FAlgorithms.Free;
end;

class procedure TWrapperUtilities.Boot;
begin
  FAlgorithms := TDictionary<String, String>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  TNistObjectIdentifiers.Boot;

  FAlgorithms.AddOrSetValue('AESKW', 'AESWRAP');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdAes128Wrap.Id, 'AESWRAP');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdAes192Wrap.Id, 'AESWRAP');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdAes256Wrap.Id, 'AESWRAP');

  FAlgorithms.AddOrSetValue('AESKWP', 'AESWRAPPAD');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdAes128WrapPad.Id, 'AESWRAPPAD');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdAes192WrapPad.Id, 'AESWRAPPAD');
  FAlgorithms.AddOrSetValue(TNistObjectIdentifiers.IdAes256WrapPad.Id, 'AESWRAPPAD');
  FAlgorithms.AddOrSetValue('AESRFC5649WRAP', 'AESWRAPPAD');
end;

class function TWrapperUtilities.GetWrapper(
  const AOid: IDerObjectIdentifier): IWrapper;
begin
  Result := GetWrapper(AOid.Id);
end;

class function TWrapperUtilities.GetWrapper(const AAlgorithm: String): IWrapper;
var
  LMechanism: String;
  LWrapAlgorithm: TWrapAlgorithm;
  LBlockCipher: IBufferedCipher;
begin
  LMechanism := UpperCase(TCollectionUtilities.GetValueOrKey<String>(
    FAlgorithms, AAlgorithm));

  if TEnumUtilities.TryGetEnumValue<TWrapAlgorithm>(LMechanism, LWrapAlgorithm) then
  begin
    case LWrapAlgorithm of
      TWrapAlgorithm.AESRFC3211WRAP:
        begin
          Result := TRfc3211WrapEngine.Create(TAesEngine.Create() as IAesEngine);
          Exit;
        end;
      TWrapAlgorithm.AESWRAP:
        begin
          Result := TAesWrapEngine.Create();
          Exit;
        end;
      TWrapAlgorithm.AESWRAPPAD:
        begin
          Result := TAesWrapPadEngine.Create();
          Exit;
        end;
    else
      raise ENotImplementedCryptoLibException.Create('');
    end;
  end;

  LBlockCipher := TCipherUtilities.GetCipher(AAlgorithm);
  if LBlockCipher <> nil then
  begin
    Result := TBufferedCipherWrapper.Create(LBlockCipher);
    Exit;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SWrapperNotRecognised,
    [AAlgorithm]);
end;

class function TWrapperUtilities.GetAlgorithmName(
  const AOid: IDerObjectIdentifier): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<String, String>(FAlgorithms, AOid.Id);
end;

{ TWrapperUtilities.TBufferedCipherWrapper }

constructor TWrapperUtilities.TBufferedCipherWrapper.Create(
  const ACipher: IBufferedCipher);
begin
  inherited Create;
  FCipher := ACipher;
end;

function TWrapperUtilities.TBufferedCipherWrapper.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName;
end;

procedure TWrapperUtilities.TBufferedCipherWrapper.Init(AForWrapping: Boolean;
  const AParameters: ICipherParameters);
begin
  FForWrapping := AForWrapping;
  FCipher.Init(AForWrapping, AParameters);
end;

function TWrapperUtilities.TBufferedCipherWrapper.Wrap(
  const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray;
begin
  if not FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitialisedForWrapping);
  Result := FCipher.DoFinal(AInput, AInOff, ALength);
end;

function TWrapperUtilities.TBufferedCipherWrapper.Unwrap(
  const AInput: TCryptoLibByteArray; AInOff, ALength: Int32): TCryptoLibByteArray;
begin
  if FForWrapping then
    raise EInvalidOperationCryptoLibException.CreateRes(@SNotInitialisedForUnwrapping);
  Result := FCipher.DoFinal(AInput, AInOff, ALength);
end;

end.
