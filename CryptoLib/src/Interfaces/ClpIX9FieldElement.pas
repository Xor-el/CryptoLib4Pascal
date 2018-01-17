{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIX9FieldElement;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECFieldElement,
  ClpIProxiedInterface;

type
  IX9FieldElement = interface(IAsn1Encodable)
    ['{7B055B2C-04BB-438B-B590-9A157F6412C0}']

    function GetValue: IECFieldElement;

    // /**
    // * Produce an object suitable for an Asn1OutputStream.
    // * <pre>
    // *  FieldElement ::= OCTET STRING
    // * </pre>
    // * <p>
    // * <ol>
    // * <li> if <i>q</i> is an odd prime then the field element is
    // * processed as an Integer and converted to an octet string
    // * according to x 9.62 4.3.1.</li>
    // * <li> if <i>q</i> is 2<sup>m</sup> then the bit string
    // * contained in the field element is converted into an octet
    // * string with the same ordering padded at the front if necessary.
    // * </li>
    // * </ol>
    // * </p>
    // */
    function ToAsn1Object(): IAsn1Object;

    property Value: IECFieldElement read GetValue;

  end;

implementation

end.
