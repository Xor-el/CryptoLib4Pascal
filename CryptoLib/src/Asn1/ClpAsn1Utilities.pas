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

unit ClpAsn1Utilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  TypInfo,
  ClpIAsn1Objects,
  ClpPlatformUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Utility class for ASN.1 operations.
  /// </summary>
  TAsn1Utilities = class sealed(TObject)
  public
    // Tag checking methods
    class function CheckContextTag(const ATaggedObject: IAsn1TaggedObject;
      ATagNo: Int32): IAsn1TaggedObject; overload; static;
    class function CheckContextTag(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo: Int32): IAsn1TaggedObjectParser; overload; static;
    class function CheckContextTagClass(const ATaggedObject: IAsn1TaggedObject)
      : IAsn1TaggedObject; overload; static;
    class function CheckContextTagClass(const ATaggedObjectParser: IAsn1TaggedObjectParser)
      : IAsn1TaggedObjectParser; overload; static;
    class function CheckTag(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32): IAsn1TaggedObject; overload; static;
    class function CheckTag(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo: Int32): IAsn1TaggedObjectParser; overload; static;
    class function CheckTagClass(const ATaggedObject: IAsn1TaggedObject;
      ATagClass: Int32): IAsn1TaggedObject; overload; static;
    class function CheckTagClass(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass: Int32): IAsn1TaggedObjectParser; overload; static;

    // Tag text methods
    class function GetTagClassText(const ATaggedObject: IAsn1TaggedObject): String; overload; static;
    class function GetTagClassText(const ATaggedObjectParser: IAsn1TaggedObjectParser): String; overload; static;
    class function GetTagClassText(ATagClass: Int32): String; overload; static;
    class function GetTagText(const ATaggedObject: IAsn1TaggedObject): String; overload; static;
    class function GetTagText(const ATaggedObjectParser: IAsn1TaggedObjectParser): String; overload; static;
    class function GetTagText(ATagClass, ATagNo: Int32): String; overload; static;

    // Choice methods
    class function GetInstanceChoice<TChoice>(AObj: TObject;
      const AOptionalConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice; overload; static;
    class function GetInstanceChoice<TChoice>(const AObj: IAsn1Object;
      const AOptionalConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice; overload; static;
    class function GetInstanceChoice<TChoice>(const ABytes: TCryptoLibByteArray;
      const AOptionalConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice; overload; static;
    class function GetInstanceChoice<TChoice>(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean; const AConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice; overload; static;
    class function GetTaggedChoice<TChoice>(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean; const AConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice; static;

    // Explicit base object methods
    class function GetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
      ATagClass: Int32): IAsn1Encodable; overload; static;
    class function GetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32): IAsn1Encodable; overload; static;
    class function GetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject)
      : IAsn1Encodable; overload; static;
    class function GetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject;
      ATagNo: Int32): IAsn1Encodable; overload; static;
    class function TryGetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
      ATagClass: Int32; out ABaseObject: IAsn1Encodable): Boolean; overload; static;
    class function TryGetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32; out ABaseObject: IAsn1Encodable): Boolean; overload; static;
    class function TryGetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject;
      out ABaseObject: IAsn1Encodable): Boolean; overload; static;
    class function TryGetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject;
      ATagNo: Int32; out ABaseObject: IAsn1Encodable): Boolean; overload; static;

    // Optional tagged methods
    class function GetOptionalContextTagged<TState, TResult>(const AElement: IAsn1Encodable;
      ATagNo: Int32; const AState: TState;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult; static;
    class function GetOptionalTagged<TState, TResult>(const AElement: IAsn1Encodable;
      ATagClass, ATagNo: Int32; const AState: TState;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult; static;
    class function TryGetOptionalContextTagged<TState, TResult>(const AElement: IAsn1Encodable;
      ATagNo: Int32; const AState: TState; out AResult: TResult;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean; static;
    class function TryGetOptionalTagged<TState, TResult>(const AElement: IAsn1Encodable;
      ATagClass, ATagNo: Int32; const AState: TState; out AResult: TResult;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean; static;

    // Explicit base tagged methods
    class function GetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagClass: Int32): IAsn1TaggedObject; overload; static;
    class function GetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32): IAsn1TaggedObject; overload; static;
    class function GetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject)
      : IAsn1TaggedObject; overload; static;
    class function GetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagNo: Int32): IAsn1TaggedObject; overload; static;
    class function TryGetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagClass: Int32; out ABaseTagged: IAsn1TaggedObject): Boolean; overload; static;
    class function TryGetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32; out ABaseTagged: IAsn1TaggedObject): Boolean; overload; static;
    class function TryGetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      out ABaseTagged: IAsn1TaggedObject): Boolean; overload; static;
    class function TryGetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagNo: Int32; out ABaseTagged: IAsn1TaggedObject): Boolean; overload; static;

    // Implicit base tagged methods
    class function GetImplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObject; static;
    class function GetImplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObject; static;
    class function TryGetImplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32;
      out ABaseTagged: IAsn1TaggedObject): Boolean; overload; static;
    class function TryGetImplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
      ATagNo, ABaseTagClass, ABaseTagNo: Int32;
      out ABaseTagged: IAsn1TaggedObject): Boolean; overload; static;

    // Base universal methods
    class function GetBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Object; static;
    class function GetContextBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
      ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Object; static;
    class function TryGetBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
      out ABaseUniversal: IAsn1Object): Boolean; overload; static;
    class function TryGetContextBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
      ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
      out ABaseUniversal: IAsn1Object): Boolean; overload; static;

    // Parser methods (for IAsn1TaggedObjectParser)
    class function ParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass: Int32): IAsn1TaggedObjectParser; overload; static;
    class function ParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo: Int32): IAsn1TaggedObjectParser; overload; static;
    class function ParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser)
      : IAsn1TaggedObjectParser; overload; static;
    class function ParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo: Int32): IAsn1TaggedObjectParser; overload; static;
    class function TryParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass: Int32; out ABaseTagged: IAsn1TaggedObjectParser): Boolean; overload; static;
    class function TryParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo: Int32; out ABaseTagged: IAsn1TaggedObjectParser): Boolean; overload; static;
    class function TryParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      out ABaseTagged: IAsn1TaggedObjectParser): Boolean; overload; static;
    class function TryParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo: Int32; out ABaseTagged: IAsn1TaggedObjectParser): Boolean; overload; static;
    class function ParseImplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser; static;
    class function ParseImplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser; static;
    class function TryParseImplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32;
      out ABaseTagged: IAsn1TaggedObjectParser): Boolean; overload; static;
    class function TryParseImplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo, ABaseTagClass, ABaseTagNo: Int32;
      out ABaseTagged: IAsn1TaggedObjectParser): Boolean; overload; static;
    class function ParseBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible; static;
    class function ParseContextBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible; static;
    class function TryParseBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
      out ABaseUniversal: IAsn1Convertible): Boolean; overload; static;
    class function TryParseContextBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
      out ABaseUniversal: IAsn1Convertible): Boolean; overload; static;
    class function ParseExplicitBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo: Int32): IAsn1Convertible; static;
    class function ParseExplicitContextBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo: Int32): IAsn1Convertible; static;
    class function TryParseExplicitBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagClass, ATagNo: Int32; out ABaseObject: IAsn1Convertible): Boolean; overload; static;
    class function TryParseExplicitContextBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
      ATagNo: Int32; out ABaseObject: IAsn1Convertible): Boolean; overload; static;

    // Sequence cursor methods
    class function ReadContextTagged<TState, TResult>(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32; ATagNo: Int32; const AState: TState;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult; static;
    class function ReadTagged<TState, TResult>(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32; ATagClass, ATagNo: Int32; const AState: TState;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult; static;
    class function ReadOptional<TResult>(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32;
      const AConstructor: TFunc<IAsn1Encodable, TResult>): TResult; static;
    class function ReadOptionalContextTagged<TState, TResult>(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32; ATagNo: Int32; const AState: TState;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult; static;
    class function ReadOptionalTagged<TState, TResult>(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32; ATagClass, ATagNo: Int32; const AState: TState;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult; static;
    class function TryReadOptionalContextTagged<TState, TResult>(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32; ATagNo: Int32; const AState: TState; out AResult: TResult;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean; static;
    class function TryReadOptionalTagged<TState, TResult>(const ASequence: IAsn1Sequence;
      var ASequencePosition: Int32; ATagClass, ATagNo: Int32; const AState: TState; out AResult: TResult;
      const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean; static;
  end;

implementation

uses
  ClpAsn1Objects;

{ TAsn1Utilities }

// Tag checking methods

class function TAsn1Utilities.CheckContextTag(const ATaggedObject: IAsn1TaggedObject;
  ATagNo: Int32): IAsn1TaggedObject;
begin
  Result := CheckTag(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo);
end;

class function TAsn1Utilities.CheckContextTag(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo: Int32): IAsn1TaggedObjectParser;
begin
  Result := CheckTag(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo);
end;

class function TAsn1Utilities.CheckContextTagClass(const ATaggedObject: IAsn1TaggedObject)
  : IAsn1TaggedObject;
begin
  Result := CheckTagClass(ATaggedObject, TAsn1Tags.ContextSpecific);
end;

class function TAsn1Utilities.CheckContextTagClass(const ATaggedObjectParser: IAsn1TaggedObjectParser)
  : IAsn1TaggedObjectParser;
begin
  Result := CheckTagClass(ATaggedObjectParser, TAsn1Tags.ContextSpecific);
end;

class function TAsn1Utilities.CheckTag(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32): IAsn1TaggedObject;
var
  LExpected, LFound: String;
begin
  if not ATaggedObject.HasTag(ATagClass, ATagNo) then
  begin
    LExpected := GetTagText(ATagClass, ATagNo);
    LFound := GetTagText(ATaggedObject);
    raise EInvalidOperationCryptoLibException.CreateFmt('Expected %s tag but found %s', [LExpected, LFound]);
  end;
  Result := ATaggedObject;
end;

class function TAsn1Utilities.CheckTag(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo: Int32): IAsn1TaggedObjectParser;
var
  LExpected, LFound: String;
begin
  if not ATaggedObjectParser.HasTag(ATagClass, ATagNo) then
  begin
    LExpected := GetTagText(ATagClass, ATagNo);
    LFound := GetTagText(ATaggedObjectParser);
    raise EInvalidOperationCryptoLibException.CreateFmt('Expected %s tag but found %s', [LExpected, LFound]);
  end;
  Result := ATaggedObjectParser;
end;

class function TAsn1Utilities.CheckTagClass(const ATaggedObject: IAsn1TaggedObject;
  ATagClass: Int32): IAsn1TaggedObject;
var
  LExpected, LFound: String;
begin
  if not ATaggedObject.HasTagClass(ATagClass) then
  begin
    LExpected := GetTagClassText(ATagClass);
    LFound := GetTagClassText(ATaggedObject);
    raise EInvalidOperationCryptoLibException.CreateFmt('Expected %s tag but found %s', [LExpected, LFound]);
  end;
  Result := ATaggedObject;
end;

class function TAsn1Utilities.CheckTagClass(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass: Int32): IAsn1TaggedObjectParser;
var
  LExpected, LFound: String;
begin
  if ATaggedObjectParser.TagClass <> ATagClass then
  begin
    LExpected := GetTagClassText(ATagClass);
    LFound := GetTagClassText(ATaggedObjectParser);
    raise EInvalidOperationCryptoLibException.CreateFmt('Expected %s tag but found %s', [LExpected, LFound]);
  end;
  Result := ATaggedObjectParser;
end;

// Tag text methods

class function TAsn1Utilities.GetTagClassText(const ATaggedObject: IAsn1TaggedObject): String;
begin
  Result := GetTagClassText(ATaggedObject.TagClass);
end;

class function TAsn1Utilities.GetTagClassText(const ATaggedObjectParser: IAsn1TaggedObjectParser): String;
begin
  Result := GetTagClassText(ATaggedObjectParser.TagClass);
end;

class function TAsn1Utilities.GetTagClassText(ATagClass: Int32): String;
begin
  case ATagClass of
    TAsn1Tags.Application:
      Result := 'APPLICATION';
    TAsn1Tags.ContextSpecific:
      Result := 'CONTEXT';
    TAsn1Tags.Private:
      Result := 'PRIVATE';
    TAsn1Tags.Universal:
      Result := 'UNIVERSAL';
  else
    Result := Format('UNKNOWN(%d)', [ATagClass]);
  end;
end;

class function TAsn1Utilities.GetTagText(const ATaggedObject: IAsn1TaggedObject): String;
begin
  Result := GetTagText(ATaggedObject.TagClass, ATaggedObject.TagNo);
end;

class function TAsn1Utilities.GetTagText(const ATaggedObjectParser: IAsn1TaggedObjectParser): String;
begin
  Result := GetTagText(ATaggedObjectParser.TagClass, ATaggedObjectParser.TagNo);
end;

class function TAsn1Utilities.GetTagText(ATagClass, ATagNo: Int32): String;
begin
  case ATagClass of
    TAsn1Tags.Application:
      Result := Format('[APPLICATION %d]', [ATagNo]);
    TAsn1Tags.ContextSpecific:
      Result := Format('[CONTEXT %d]', [ATagNo]);
    TAsn1Tags.Private:
      Result := Format('[PRIVATE %d]', [ATagNo]);
    TAsn1Tags.Universal:
      Result := Format('[UNIVERSAL %d]', [ATagNo]);
  else
    Result := Format('[UNKNOWN(%d) %d]', [ATagClass, ATagNo]);
  end;
end;

// Choice methods

class function TAsn1Utilities.GetInstanceChoice<TChoice>(AObj: TObject;
  const AOptionalConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice;
var
  LAsn1Object: IAsn1Object;
  LElement: IAsn1Encodable;
  LResult: TChoice;
  LResultPtr: Pointer;
begin
  if AObj = nil then
  begin
    Result := Default(TChoice);
    Exit;
  end;

  // Prefer IAsn1Object overload if available
  if Supports(AObj, IAsn1Object, LAsn1Object) then
  begin
    Result := GetInstanceChoice<TChoice>(LAsn1Object, AOptionalConstructor);
    Exit;
  end;

  // Fall back to IAsn1Encodable check
  if Supports(AObj, IAsn1Encodable, LElement) then
  begin
    LResult := AOptionalConstructor(LElement);
    LResultPtr := PPointer(@LResult)^;
    if LResultPtr <> nil then
    begin
      Result := LResult;
      Exit;
    end;
  end;

  raise EArgumentCryptoLibException.Create('Invalid object: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1Utilities.GetInstanceChoice<TChoice>(const AObj: IAsn1Object;
  const AOptionalConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice;
var
  LResult: TChoice;
  LResultPtr: Pointer;
begin
  if AObj = nil then
  begin
    Result := Default(TChoice);
    Exit;
  end;

  LResult := AOptionalConstructor(AObj);
  LResultPtr := PPointer(@LResult)^;
  if LResultPtr <> nil then
  begin
    Result := LResult;
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('Invalid object: ' + TPlatformUtilities.GetTypeName(AObj as TObject));
end;

class function TAsn1Utilities.GetInstanceChoice<TChoice>(const ABytes: TCryptoLibByteArray;
  const AOptionalConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice;
var
  LObj: IAsn1Object;
  LChoiceName: String;
begin
  if System.Length(ABytes) = 0 then
    Exit(Default(TChoice));

  try
    LObj := TAsn1Object.FromByteArray(ABytes);
  except
    on E: EIOCryptoLibException do
    begin
      LChoiceName := TypInfo.GetTypeName(TypeInfo(TChoice));
      raise EArgumentCryptoLibException.CreateFmt('failed to construct %s from byte[]: %s',
        [LChoiceName, E.Message]);
    end;
  end;

  Result := GetInstanceChoice<TChoice>(LObj, AOptionalConstructor);
end;

class function TAsn1Utilities.GetInstanceChoice<TChoice>(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean; const AConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice;
var
  LChoiceName: String;
  LMsg: String;
begin
  if not ADeclaredExplicit then
  begin
    LChoiceName := TypInfo.GetTypeName(TypeInfo(TChoice));
    LMsg := Format('Implicit tagging cannot be used with untagged choice type %s (X.680 30.6, 30.8).',
      [LChoiceName]);
    raise EArgumentCryptoLibException.Create(LMsg);
  end;
  if ATaggedObject = nil then
    raise EArgumentNilCryptoLibException.Create('taggedObject');

  Result := AConstructor(GetExplicitContextBaseObject(ATaggedObject));
end;

class function TAsn1Utilities.GetTaggedChoice<TChoice>(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean; const AConstructor: TFunc<IAsn1Encodable, TChoice>): TChoice;
var
  LChoiceName: String;
  LMsg: String;
begin
  if not ADeclaredExplicit then
  begin
    LChoiceName := TypInfo.GetTypeName(TypeInfo(TChoice));
    LMsg := Format('Implicit tagging cannot be used with untagged choice type %s (X.680 30.6, 30.8).',
      [LChoiceName]);
    raise EArgumentCryptoLibException.Create(LMsg);
  end;
  if ATaggedObject = nil then
    raise EArgumentNilCryptoLibException.Create('taggedObject');

  Result := AConstructor(ATaggedObject.GetExplicitBaseObject());
end;

// Explicit base object methods

class function TAsn1Utilities.GetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
  ATagClass: Int32): IAsn1Encodable;
begin
  Result := CheckTagClass(ATaggedObject, ATagClass).GetExplicitBaseObject();
end;

class function TAsn1Utilities.GetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32): IAsn1Encodable;
begin
  Result := CheckTag(ATaggedObject, ATagClass, ATagNo).GetExplicitBaseObject();
end;

class function TAsn1Utilities.GetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject)
  : IAsn1Encodable;
begin
  Result := GetExplicitBaseObject(ATaggedObject, TAsn1Tags.ContextSpecific);
end;

class function TAsn1Utilities.GetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject;
  ATagNo: Int32): IAsn1Encodable;
begin
  Result := GetExplicitBaseObject(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo);
end;

class function TAsn1Utilities.TryGetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
  ATagClass: Int32; out ABaseObject: IAsn1Encodable): Boolean;
begin
  Result := ATaggedObject.HasTagClass(ATagClass);
  if Result then
    ABaseObject := ATaggedObject.GetExplicitBaseObject()
  else
    ABaseObject := nil;
end;

class function TAsn1Utilities.TryGetExplicitBaseObject(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32; out ABaseObject: IAsn1Encodable): Boolean;
begin
  Result := ATaggedObject.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseObject := ATaggedObject.GetExplicitBaseObject()
  else
    ABaseObject := nil;
end;

class function TAsn1Utilities.TryGetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject;
  out ABaseObject: IAsn1Encodable): Boolean;
begin
  Result := TryGetExplicitBaseObject(ATaggedObject, TAsn1Tags.ContextSpecific, ABaseObject);
end;

class function TAsn1Utilities.TryGetExplicitContextBaseObject(const ATaggedObject: IAsn1TaggedObject;
  ATagNo: Int32; out ABaseObject: IAsn1Encodable): Boolean;
begin
  Result := TryGetExplicitBaseObject(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo, ABaseObject);
end;

// Optional tagged methods

class function TAsn1Utilities.GetOptionalContextTagged<TState, TResult>(const AElement: IAsn1Encodable;
  ATagNo: Int32; const AState: TState;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult;
begin
  Result := GetOptionalTagged<TState, TResult>(AElement, TAsn1Tags.ContextSpecific, ATagNo, AState, AConstructor);
end;

class function TAsn1Utilities.GetOptionalTagged<TState, TResult>(const AElement: IAsn1Encodable;
  ATagClass, ATagNo: Int32; const AState: TState;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult;
var
  LTaggedObject: IAsn1TaggedObject;
begin
  LTaggedObject := TAsn1TaggedObject.GetOptional(AElement, ATagClass, ATagNo);
  if LTaggedObject = nil then
    Result := Default(TResult)
  else
    Result := AConstructor(LTaggedObject, AState);
end;

class function TAsn1Utilities.TryGetOptionalContextTagged<TState, TResult>(const AElement: IAsn1Encodable;
  ATagNo: Int32; const AState: TState; out AResult: TResult;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean;
begin
  Result := TryGetOptionalTagged<TState, TResult>(AElement, TAsn1Tags.ContextSpecific, ATagNo, AState, AResult, AConstructor);
end;

class function TAsn1Utilities.TryGetOptionalTagged<TState, TResult>(const AElement: IAsn1Encodable;
  ATagClass, ATagNo: Int32; const AState: TState; out AResult: TResult;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean;
var
  LTaggedObject: IAsn1TaggedObject;
begin
  LTaggedObject := TAsn1TaggedObject.GetOptional(AElement, ATagClass, ATagNo);
  if LTaggedObject <> nil then
  begin
    AResult := AConstructor(LTaggedObject, AState);
    Result := True;
  end
  else
  begin
    AResult := Default(TResult);
    Result := False;
  end;
end;

// Explicit base tagged methods

class function TAsn1Utilities.GetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagClass: Int32): IAsn1TaggedObject;
begin
  Result := CheckTagClass(ATaggedObject, ATagClass).GetExplicitBaseTagged();
end;

class function TAsn1Utilities.GetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32): IAsn1TaggedObject;
begin
  Result := CheckTag(ATaggedObject, ATagClass, ATagNo).GetExplicitBaseTagged();
end;

class function TAsn1Utilities.GetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject)
  : IAsn1TaggedObject;
begin
  Result := GetExplicitBaseTagged(ATaggedObject, TAsn1Tags.ContextSpecific);
end;

class function TAsn1Utilities.GetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagNo: Int32): IAsn1TaggedObject;
begin
  Result := GetExplicitBaseTagged(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo);
end;

class function TAsn1Utilities.TryGetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagClass: Int32; out ABaseTagged: IAsn1TaggedObject): Boolean;
begin
  Result := ATaggedObject.HasTagClass(ATagClass);
  if Result then
    ABaseTagged := ATaggedObject.GetExplicitBaseTagged()
  else
    ABaseTagged := nil;
end;

class function TAsn1Utilities.TryGetExplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32; out ABaseTagged: IAsn1TaggedObject): Boolean;
begin
  Result := ATaggedObject.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseTagged := ATaggedObject.GetExplicitBaseTagged()
  else
    ABaseTagged := nil;
end;

class function TAsn1Utilities.TryGetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  out ABaseTagged: IAsn1TaggedObject): Boolean;
begin
  Result := TryGetExplicitBaseTagged(ATaggedObject, TAsn1Tags.ContextSpecific, ABaseTagged);
end;

class function TAsn1Utilities.TryGetExplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagNo: Int32; out ABaseTagged: IAsn1TaggedObject): Boolean;
begin
  Result := TryGetExplicitBaseTagged(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo, ABaseTagged);
end;

// Implicit base tagged methods

class function TAsn1Utilities.GetImplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObject;
begin
  Result := CheckTag(ATaggedObject, ATagClass, ATagNo).GetImplicitBaseTagged(ABaseTagClass, ABaseTagNo);
end;

class function TAsn1Utilities.GetImplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObject;
begin
  Result := GetImplicitBaseTagged(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo, ABaseTagClass, ABaseTagNo);
end;

class function TAsn1Utilities.TryGetImplicitBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32;
  out ABaseTagged: IAsn1TaggedObject): Boolean;
begin
  Result := ATaggedObject.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseTagged := ATaggedObject.GetImplicitBaseTagged(ABaseTagClass, ABaseTagNo)
  else
    ABaseTagged := nil;
end;

class function TAsn1Utilities.TryGetImplicitContextBaseTagged(const ATaggedObject: IAsn1TaggedObject;
  ATagNo, ABaseTagClass, ABaseTagNo: Int32;
  out ABaseTagged: IAsn1TaggedObject): Boolean;
begin
  Result := TryGetImplicitBaseTagged(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo, ABaseTagClass, ABaseTagNo, ABaseTagged);
end;

// Base universal methods

class function TAsn1Utilities.GetBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Object;
begin
  Result := CheckTag(ATaggedObject, ATagClass, ATagNo).GetBaseUniversal(ADeclaredExplicit, ABaseTagNo);
end;

class function TAsn1Utilities.GetContextBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
  ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Object;
begin
  Result := GetBaseUniversal(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo, ADeclaredExplicit, ABaseTagNo);
end;

class function TAsn1Utilities.TryGetBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
  out ABaseUniversal: IAsn1Object): Boolean;
begin
  Result := ATaggedObject.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseUniversal := ATaggedObject.GetBaseUniversal(ADeclaredExplicit, ABaseTagNo)
  else
    ABaseUniversal := nil;
end;

class function TAsn1Utilities.TryGetContextBaseUniversal(const ATaggedObject: IAsn1TaggedObject;
  ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
  out ABaseUniversal: IAsn1Object): Boolean;
begin
  Result := TryGetBaseUniversal(ATaggedObject, TAsn1Tags.ContextSpecific, ATagNo, ADeclaredExplicit, ABaseTagNo, ABaseUniversal);
end;

// Parser methods

class function TAsn1Utilities.ParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass: Int32): IAsn1TaggedObjectParser;
begin
  Result := CheckTagClass(ATaggedObjectParser, ATagClass).ParseExplicitBaseTagged();
end;

class function TAsn1Utilities.ParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo: Int32): IAsn1TaggedObjectParser;
begin
  Result := CheckTag(ATaggedObjectParser, ATagClass, ATagNo).ParseExplicitBaseTagged();
end;

class function TAsn1Utilities.ParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser)
  : IAsn1TaggedObjectParser;
begin
  Result := ParseExplicitBaseTagged(ATaggedObjectParser, TAsn1Tags.ContextSpecific);
end;

class function TAsn1Utilities.ParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo: Int32): IAsn1TaggedObjectParser;
begin
  Result := ParseExplicitBaseTagged(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo);
end;

class function TAsn1Utilities.TryParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass: Int32; out ABaseTagged: IAsn1TaggedObjectParser): Boolean;
begin
  Result := ATaggedObjectParser.TagClass = ATagClass;
  if Result then
    ABaseTagged := ATaggedObjectParser.ParseExplicitBaseTagged()
  else
    ABaseTagged := nil;
end;

class function TAsn1Utilities.TryParseExplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo: Int32; out ABaseTagged: IAsn1TaggedObjectParser): Boolean;
begin
  Result := ATaggedObjectParser.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseTagged := ATaggedObjectParser.ParseExplicitBaseTagged()
  else
    ABaseTagged := nil;
end;

class function TAsn1Utilities.TryParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  out ABaseTagged: IAsn1TaggedObjectParser): Boolean;
begin
  Result := TryParseExplicitBaseTagged(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ABaseTagged);
end;

class function TAsn1Utilities.TryParseExplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo: Int32; out ABaseTagged: IAsn1TaggedObjectParser): Boolean;
begin
  Result := TryParseExplicitBaseTagged(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo, ABaseTagged);
end;

class function TAsn1Utilities.ParseImplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser;
begin
  Result := CheckTag(ATaggedObjectParser, ATagClass, ATagNo).ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo);
end;

class function TAsn1Utilities.ParseImplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo, ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser;
begin
  Result := ParseImplicitBaseTagged(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo, ABaseTagClass, ABaseTagNo);
end;

class function TAsn1Utilities.TryParseImplicitBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo, ABaseTagClass, ABaseTagNo: Int32;
  out ABaseTagged: IAsn1TaggedObjectParser): Boolean;
begin
  Result := ATaggedObjectParser.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseTagged := ATaggedObjectParser.ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo)
  else
    ABaseTagged := nil;
end;

class function TAsn1Utilities.TryParseImplicitContextBaseTagged(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo, ABaseTagClass, ABaseTagNo: Int32;
  out ABaseTagged: IAsn1TaggedObjectParser): Boolean;
begin
  Result := TryParseImplicitBaseTagged(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo, ABaseTagClass, ABaseTagNo, ABaseTagged);
end;

class function TAsn1Utilities.ParseBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible;
begin
  Result := CheckTag(ATaggedObjectParser, ATagClass, ATagNo).ParseBaseUniversal(ADeclaredExplicit, ABaseTagNo);
end;

class function TAsn1Utilities.ParseContextBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible;
begin
  Result := ParseBaseUniversal(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo, ADeclaredExplicit, ABaseTagNo);
end;

class function TAsn1Utilities.TryParseBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
  out ABaseUniversal: IAsn1Convertible): Boolean;
begin
  Result := ATaggedObjectParser.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseUniversal := ATaggedObjectParser.ParseBaseUniversal(ADeclaredExplicit, ABaseTagNo)
  else
    ABaseUniversal := nil;
end;

class function TAsn1Utilities.TryParseContextBaseUniversal(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo: Int32; ADeclaredExplicit: Boolean; ABaseTagNo: Int32;
  out ABaseUniversal: IAsn1Convertible): Boolean;
begin
  Result := TryParseBaseUniversal(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo, ADeclaredExplicit, ABaseTagNo, ABaseUniversal);
end;

class function TAsn1Utilities.ParseExplicitBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo: Int32): IAsn1Convertible;
begin
  Result := CheckTag(ATaggedObjectParser, ATagClass, ATagNo).ParseExplicitBaseObject();
end;

class function TAsn1Utilities.ParseExplicitContextBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo: Int32): IAsn1Convertible;
begin
  Result := ParseExplicitBaseObject(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo);
end;

class function TAsn1Utilities.TryParseExplicitBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagClass, ATagNo: Int32; out ABaseObject: IAsn1Convertible): Boolean;
begin
  Result := ATaggedObjectParser.HasTag(ATagClass, ATagNo);
  if Result then
    ABaseObject := ATaggedObjectParser.ParseExplicitBaseObject()
  else
    ABaseObject := nil;
end;

class function TAsn1Utilities.TryParseExplicitContextBaseObject(const ATaggedObjectParser: IAsn1TaggedObjectParser;
  ATagNo: Int32; out ABaseObject: IAsn1Convertible): Boolean;
begin
  Result := TryParseExplicitBaseObject(ATaggedObjectParser, TAsn1Tags.ContextSpecific, ATagNo, ABaseObject);
end;

// Sequence cursor methods

class function TAsn1Utilities.ReadContextTagged<TState, TResult>(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32; ATagNo: Int32; const AState: TState;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult;
begin
  Result := ReadTagged<TState, TResult>(ASequence, ASequencePosition, TAsn1Tags.ContextSpecific, ATagNo, AState, AConstructor);
end;

class function TAsn1Utilities.ReadTagged<TState, TResult>(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32; ATagClass, ATagNo: Int32; const AState: TState;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult;
var
  LTagged: IAsn1TaggedObject;
  LElement: IAsn1Encodable;
  LObj: IAsn1Object;
begin
  // TODO: We might want to check the position and throw a better exception, but current ASN.1 types aren't
  // doing that, so leave it until it can be consistent.
  LElement := ASequence.Items[ASequencePosition];
  System.Inc(ASequencePosition);
  if LElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  LObj := LElement.ToAsn1Object();
  LTagged := TAsn1TaggedObject.GetInstance(LObj, ATagClass, ATagNo);
  Result := AConstructor(LTagged, AState);
end;

class function TAsn1Utilities.ReadOptional<TResult>(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32;
  const AConstructor: TFunc<IAsn1Encodable, TResult>): TResult;
var
  LResult: TResult;
  LResultPtr: Pointer;
begin
  if ASequencePosition < ASequence.Count then
  begin
    LResult := AConstructor(ASequence.Items[ASequencePosition]);
    // Check if result is not nil (for reference types)
    // Since we know TResult will always be a reference type, we check the pointer value
    LResultPtr := PPointer(@LResult)^;
    if LResultPtr <> nil then
    begin
      System.Inc(ASequencePosition);
      Result := LResult;
      Exit;
    end;
  end;
  Result := Default(TResult);
end;

class function TAsn1Utilities.ReadOptionalContextTagged<TState, TResult>(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32; ATagNo: Int32; const AState: TState;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult;
begin
  Result := ReadOptionalTagged<TState, TResult>(ASequence, ASequencePosition, TAsn1Tags.ContextSpecific, ATagNo, AState, AConstructor);
end;

class function TAsn1Utilities.ReadOptionalTagged<TState, TResult>(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32; ATagClass, ATagNo: Int32; const AState: TState;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): TResult;
var
  LResult: TResult;
begin
  if (ASequencePosition < ASequence.Count) and
    (TryGetOptionalTagged<TState, TResult>(ASequence.Items[ASequencePosition], ATagClass, ATagNo, AState, LResult, AConstructor)) then
  begin
    System.Inc(ASequencePosition);
    Result := LResult;
    Exit;
  end;
  Result := Default(TResult);
end;

class function TAsn1Utilities.TryReadOptionalContextTagged<TState, TResult>(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32; ATagNo: Int32; const AState: TState; out AResult: TResult;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean;
begin
  Result := TryReadOptionalTagged<TState, TResult>(ASequence, ASequencePosition, TAsn1Tags.ContextSpecific, ATagNo, AState, AResult, AConstructor);
end;

class function TAsn1Utilities.TryReadOptionalTagged<TState, TResult>(const ASequence: IAsn1Sequence;
  var ASequencePosition: Int32; ATagClass, ATagNo: Int32; const AState: TState; out AResult: TResult;
  const AConstructor: TFunc<IAsn1TaggedObject, TState, TResult>): Boolean;
begin
  if (ASequencePosition < ASequence.Count) and
    (TryGetOptionalTagged<TState, TResult>(ASequence.Items[ASequencePosition], ATagClass, ATagNo, AState, AResult, AConstructor)) then
  begin
    System.Inc(ASequencePosition);
    Result := True;
    Exit;
  end;
  AResult := Default(TResult);
  Result := False;
end;

end.
