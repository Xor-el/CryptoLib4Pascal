{ *********************************************************************************** }
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

unit ClpWrapperUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIWrapper,
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
  ClpCryptoLibTypes;

resourcestring
  SWrapperNotRecognised = 'Wrapper "%s" not recognised.';

type
  TWrapperUtilities = class sealed(TObject)

  strict private
  type
    TWrapAlgorithm = (
      AESRFC3211WRAP,
      AESWRAP,
      AESWRAPPAD);

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

  TEnumUtilities.GetArbitraryValue<TWrapAlgorithm>();

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
    end;
  end;

  raise ESecurityUtilityCryptoLibException.CreateResFmt(@SWrapperNotRecognised,
    [AAlgorithm]);
end;

class function TWrapperUtilities.GetAlgorithmName(
  const AOid: IDerObjectIdentifier): String;
begin
  Result := TCollectionUtilities.GetValueOrNull<String, String>(FAlgorithms, AOid.Id);
end;

end.
