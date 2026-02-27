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

unit ClpAsn1Tags;

{$I ..\Include\CryptoLib.inc}

interface

type
  /// <summary>
  /// ASN.1 tags constants.
  /// </summary>
  TAsn1Tags = class sealed(TObject)
  public
    // 0x00: Reserved for use by the encoding rules
    const
      Boolean = $01;
      Integer = $02;
      BitString = $03;
      OctetString = $04;
      Null = $05;
      ObjectIdentifier = $06;
      ObjectDescriptor = $07;
      &External = $08;
      Real = $09;
      Enumerated = $0A;
      EmbeddedPdv = $0B;
      Utf8String = $0C;
      RelativeOid = $0D;
      Time = $0E;
      // 0x0f: Reserved for future editions of this Recommendation | International Standard
      Sequence = $10;
      SequenceOf = $10; // for completeness
      &Set = $11;
      SetOf = $11; // for completeness
      NumericString = $12;
      PrintableString = $13;
      T61String = $14;
      VideotexString = $15;
      IA5String = $16;
      UtcTime = $17;
      GeneralizedTime = $18;
      GraphicString = $19;
      VisibleString = $1A;
      GeneralString = $1B;
      UniversalString = $1C;
      UnrestrictedString = $1D;
      BmpString = $1E;
      Date = $1F;
      TimeOfDay = $20;
      DateTime = $21;
      Duration = $22;
      ObjectIdentifierIri = $23;
      RelativeOidIri = $24;
      // 0x25..: Reserved for addenda to this Recommendation | International Standard

      Constructed = $20;

      Universal = $00;
      Application = $40;
      ContextSpecific = $80;
      &Private = $C0;

      Flags = $E0;
  end;

implementation

end.
