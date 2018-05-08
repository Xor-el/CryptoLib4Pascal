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
  TAsn1Tags = class sealed(TObject)

  public

    const
    &Boolean = Int32($01);
    &Integer = Int32($02);
    BitString = Int32($03);
    OctetString = Int32($04);
    Null = Int32($05);
    ObjectIdentifier = Int32($06);
    &External = Int32($08);
    Enumerated = Int32($0A);
    Sequence = Int32($10);
    SequenceOf = Int32($10); // for completeness
    &Set = Int32($11);
    SetOf = Int32($11); // for completeness

    NumericString = Int32($12);
    PrintableString = Int32($13);
    T61String = Int32($14);
    VideotexString = Int32($15);
    IA5String = Int32($16);
    UtcTime = Int32($17);
    GeneralizedTime = Int32($18);
    GraphicString = Int32($19);
    VisibleString = Int32($1A);
    GeneralString = Int32($1B);
    UniversalString = Int32($1C);
    BmpString = Int32($1E);
    Utf8String = Int32($0C);

    Constructed = Int32($20);
    Application = Int32($40);
    Tagged = Int32($80);
  end;

implementation

end.
