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

unit ClpAsn1Dumper;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  Classes,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpAsn1Utilities,
  ClpAsn1Streams,
  ClpEncoders,
  ClpCryptoLibTypes,
  ClpArrayUtilities;

type
  /// <summary>
  /// Utility class for dumping ASN.1 objects as formatted strings.
  /// </summary>
  TAsn1Dumper = class sealed(TObject)
  strict private
    const
      Tab = '    ';
      SampleSize = 32;

    class procedure AsString(const AIndent: String; AVerbose: Boolean;
      const AObj: IAsn1Object; const ABuf: TStringBuilder); static;
    class procedure DumpBinaryDataAsString(const ABuf: TStringBuilder;
      const AIndent: String; const ABytes: TCryptoLibByteArray); static;
    class procedure AppendAscString(const ABuf: TStringBuilder;
      const ABytes: TCryptoLibByteArray; AOff, ALen: Int32); static;

  public
    /// <summary>
    /// Dump out a DER object as a formatted string, in non-verbose mode.
    /// </summary>
    /// <param name="AObj">the Asn1Encodable to be dumped out.</param>
    /// <returns>the resulting string.</returns>
    class function DumpAsString(const AObj: IAsn1Encodable): String; overload; static;
    /// <summary>
    /// Dump out the object as a string.
    /// </summary>
    /// <param name="AObj">the Asn1Encodable to be dumped out.</param>
    /// <param name="AVerbose">if true, dump out the contents of octet and bit strings.</param>
    /// <returns>the resulting string.</returns>
    class function DumpAsString(const AObj: IAsn1Encodable; AVerbose: Boolean): String; overload; static;
    /// <summary>
    /// Parse ASN.1 objects from input stream, and write them to the output.
    /// </summary>
    class procedure Dump(const AInput: TStream; const AOutput: TStringBuilder); static;
  end;

implementation

{ TAsn1Dumper }

class procedure TAsn1Dumper.AppendAscString(const ABuf: TStringBuilder;
  const ABytes: TCryptoLibByteArray; AOff, ALen: Int32);
var
  I: Int32;
  C: Char;
begin
  I := AOff;
  while I <> AOff + ALen do
  begin
    C := Char(ABytes[I]);
    if (C >= ' ') and (C <= '~') then
    begin
      ABuf.Append(C);
    end;
    System.Inc(I);
  end;
end;

class procedure TAsn1Dumper.AsString(const AIndent: String; AVerbose: Boolean;
  const AObj: IAsn1Object; const ABuf: TStringBuilder);
var
  LSequence: IAsn1Sequence;
  LSet: IAsn1Set;
  LTaggedObject: IAsn1TaggedObject;
  LOid: IDerObjectIdentifier;
  LRelativeOid: IAsn1RelativeOid;
  LBoolean: IDerBoolean;
  LInteger: IDerInteger;
  LOctetString: IAsn1OctetString;
  LBitString: IDerBitString;
  LIA5String: IDerIA5String;
  LUtf8String: IDerUtf8String;
  LPrintableString: IDerPrintableString;
  LVisibleString: IDerVisibleString;
  LBmpString: IDerBmpString;
  LT61String: IDerT61String;
  LGraphicString: IDerGraphicString;
  LVideotexString: IDerVideotexString;
  LUtcTime: IAsn1UtcTime;
  LGeneralizedTime: IAsn1GeneralizedTime;
  LEnumerated: IDerEnumerated;
  LExternal: IDerExternal;
  LBerSequence: IBerSequence;
  LBerSet: IBerSet;
  LBerTaggedObject: IBerTaggedObject;
  LBerOctetString: IBerOctetString;
  LBerBitString: IBerBitString;
  LDLSequence: IDLSequence;
  LDLSet: IDLSet;
  LDLTaggedObject: IDLTaggedObject;
  LDLBitString: IDLBitString;
  I, LCount: Int32;
  LElementsIndent, LBaseIndent, LTab: String;
begin
  ABuf.Append(AIndent);

  if Supports(AObj, IAsn1Null) then
  begin
    ABuf.AppendLine('NULL');
  end
  else if Supports(AObj, IAsn1Sequence, LSequence) then
  begin
    if Supports(LSequence, IBerSequence, LBerSequence) then
    begin
      ABuf.AppendLine('BER Sequence');
    end
    else if not Supports(LSequence, IDLSequence, LDLSequence) then
    begin
      ABuf.AppendLine('DER Sequence');
    end
    else
    begin
      ABuf.AppendLine('Sequence');
    end;

    LElementsIndent := AIndent + Tab;
    LCount := LSequence.Count;
    for I := 0 to LCount - 1 do
    begin
      AsString(LElementsIndent, AVerbose, LSequence[I].ToAsn1Object(), ABuf);
    end;
  end
  else if Supports(AObj, IAsn1Set, LSet) then
  begin
    if Supports(LSet, IBerSet, LBerSet) then
    begin
      ABuf.AppendLine('BER Set');
    end
    else if not Supports(LSet, IDLSet, LDLSet) then
    begin
      ABuf.AppendLine('DER Set');
    end
    else
    begin
      ABuf.AppendLine('Set');
    end;

    LElementsIndent := AIndent + Tab;
    LCount := LSet.Count;
    for I := 0 to LCount - 1 do
    begin
      AsString(LElementsIndent, AVerbose, LSet[I].ToAsn1Object(), ABuf);
    end;
  end
  else if Supports(AObj, IAsn1TaggedObject, LTaggedObject) then
  begin
    if Supports(LTaggedObject, IBerTaggedObject, LBerTaggedObject) then
    begin
      ABuf.Append('BER Tagged ');
    end
    else if not Supports(LTaggedObject, IDLTaggedObject, LDLTaggedObject) then
    begin
      ABuf.Append('DER Tagged ');
    end
    else
    begin
      ABuf.Append('Tagged ');
    end;

    ABuf.Append(TAsn1Utilities.GetTagText(LTaggedObject));

    if not LTaggedObject.IsExplicit() then
    begin
      ABuf.Append(' IMPLICIT');
    end;

    ABuf.AppendLine();

    LBaseIndent := AIndent + Tab;
    AsString(LBaseIndent, AVerbose, LTaggedObject.GetBaseObject().ToAsn1Object(), ABuf);
  end
  else if Supports(AObj, IDerObjectIdentifier, LOid) then
  begin
    ABuf.AppendLine('ObjectIdentifier(' + LOid.GetID() + ')');
  end
  else if Supports(AObj, IAsn1RelativeOid, LRelativeOid) then
  begin
    ABuf.AppendLine('RelativeOID(' + LRelativeOid.GetID() + ')');
  end
  else if Supports(AObj, IDerBoolean, LBoolean) then
  begin
    ABuf.AppendLine('Boolean(' + BoolToStr(LBoolean.IsTrue, True) + ')');
  end
  else if Supports(AObj, IDerInteger, LInteger) then
  begin
    ABuf.AppendLine('Integer(' + LInteger.Value.ToString() + ')');
  end
  else if Supports(AObj, IAsn1OctetString, LOctetString) then
  begin
    if Supports(LOctetString, IBerOctetString, LBerOctetString) then
    begin
      ABuf.Append('BER Octet String[');
    end
    else
    begin
      ABuf.Append('DER Octet String[');
    end;

    ABuf.AppendLine(IntToStr(LOctetString.GetOctetsLength()) + ']');

    if AVerbose then
    begin
      DumpBinaryDataAsString(ABuf, AIndent, LOctetString.GetOctets());
    end;
  end
  else if Supports(AObj, IDerBitString, LBitString) then
  begin
    if Supports(LBitString, IBerBitString, LBerBitString) then
    begin
      ABuf.Append('BER Bit String[');
    end
    else if Supports(LBitString, IDLBitString, LDLBitString) then
    begin
      ABuf.Append('DL Bit String[');
    end
    else
    begin
      ABuf.Append('DER Bit String[');
    end;

    ABuf.AppendLine(IntToStr(System.Length(LBitString.GetBytes())) + ', ' + IntToStr(LBitString.GetPadBits()) + ']');

    if AVerbose then
    begin
      DumpBinaryDataAsString(ABuf, AIndent, LBitString.GetBytes());
    end;
  end
  else if Supports(AObj, IDerIA5String, LIA5String) then
  begin
    ABuf.AppendLine('IA5String(' + LIA5String.GetString() + ')');
  end
  else if Supports(AObj, IDerUtf8String, LUtf8String) then
  begin
    ABuf.AppendLine('UTF8String(' + LUtf8String.GetString() + ')');
  end
  else if Supports(AObj, IDerPrintableString, LPrintableString) then
  begin
    ABuf.AppendLine('PrintableString(' + LPrintableString.GetString() + ')');
  end
  else if Supports(AObj, IDerVisibleString, LVisibleString) then
  begin
    ABuf.AppendLine('VisibleString(' + LVisibleString.GetString() + ')');
  end
  else if Supports(AObj, IDerBmpString, LBmpString) then
  begin
    ABuf.AppendLine('BMPString(' + LBmpString.GetString() + ')');
  end
  else if Supports(AObj, IDerT61String, LT61String) then
  begin
    ABuf.AppendLine('T61String(' + LT61String.GetString() + ')');
  end
  else if Supports(AObj, IDerGraphicString, LGraphicString) then
  begin
    ABuf.AppendLine('GraphicString(' + LGraphicString.GetString() + ')');
  end
  else if Supports(AObj, IDerVideotexString, LVideotexString) then
  begin
    ABuf.AppendLine('VideotexString(' + LVideotexString.GetString() + ')');
  end
  else if Supports(AObj, IAsn1UtcTime, LUtcTime) then
  begin
    ABuf.AppendLine('UTCTime(' + LUtcTime.TimeString + ')');
  end
  else if Supports(AObj, IAsn1GeneralizedTime, LGeneralizedTime) then
  begin
    ABuf.AppendLine('GeneralizedTime(' + LGeneralizedTime.TimeString + ')');
  end
  else if Supports(AObj, IDerEnumerated, LEnumerated) then
  begin
    ABuf.AppendLine('DER Enumerated(' + LEnumerated.Value.ToString() + ')');
  end
  else if Supports(AObj, IDerExternal, LExternal) then
  begin
    ABuf.AppendLine('External ');
    LTab := AIndent + Tab;

    if LExternal.GetDirectReference() <> nil then
    begin
      ABuf.Append(LTab);
      ABuf.AppendLine('Direct Reference: ' + LExternal.GetDirectReference().GetID());
    end;
    if LExternal.GetIndirectReference() <> nil then
    begin
      ABuf.Append(LTab);
      ABuf.AppendLine('Indirect Reference: ' + LExternal.GetIndirectReference().ToString());
    end;
    if LExternal.GetDataValueDescriptor() <> nil then
    begin
      AsString(LTab, AVerbose, LExternal.GetDataValueDescriptor(), ABuf);
    end;
    ABuf.Append(LTab);
    ABuf.AppendLine('Encoding: ' + IntToStr(LExternal.GetEncoding()));
    AsString(LTab, AVerbose, LExternal.GetExternalContent(), ABuf);
  end
  else
  begin
    ABuf.Append(AObj.ToString());
    ABuf.AppendLine();
  end;
end;

class procedure TAsn1Dumper.DumpBinaryDataAsString(const ABuf: TStringBuilder;
  const AIndent: String; const ABytes: TCryptoLibByteArray);
var
  I, LRemaining, LChunk, J: Int32;
  LIndent: String;
begin
  if System.Length(ABytes) < 1 then
    Exit;

  LIndent := AIndent + Tab;

  I := 0;
  while I < System.Length(ABytes) do
  begin
    LRemaining := System.Length(ABytes) - I;
    LChunk := Math.Min(LRemaining, SampleSize);

    ABuf.Append(LIndent);
    ABuf.Append(THex.Encode(TArrayUtilities.CopyOfRange<Byte>(ABytes, I, I + LChunk)));
    J := LChunk;
    while J < SampleSize do
    begin
      ABuf.Append('  ');
      System.Inc(J);
    end;
    ABuf.Append(Tab);
    AppendAscString(ABuf, ABytes, I, LChunk);
    ABuf.AppendLine();
    System.Inc(I, SampleSize);
  end;
end;

class function TAsn1Dumper.DumpAsString(const AObj: IAsn1Encodable): String;
begin
  Result := DumpAsString(AObj, False);
end;

class function TAsn1Dumper.DumpAsString(const AObj: IAsn1Encodable; AVerbose: Boolean): String;
var
  LBuf: TStringBuilder;
begin
  LBuf := TStringBuilder.Create();
  try
    AsString('', AVerbose, AObj.ToAsn1Object(), LBuf);
    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

class procedure TAsn1Dumper.Dump(const AInput: TStream; const AOutput: TStringBuilder);
var
  LAsn1In: TAsn1InputStream;
  LAsn1Object: IAsn1Object;
begin
  LAsn1In := TAsn1InputStream.Create(AInput, MaxInt, True);
  try
    LAsn1Object := LAsn1In.ReadObject();
    while LAsn1Object <> nil do
    begin
      AOutput.Append(DumpAsString(LAsn1Object));
      LAsn1Object := LAsn1In.ReadObject();
    end;
  finally
    LAsn1In.Free;
  end;
end;

end.
