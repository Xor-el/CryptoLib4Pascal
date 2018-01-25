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

unit ClpIPrimeField;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIFiniteField;

type
  IPrimeField = interface(IFiniteField)
    ['{242D0BB8-1F38-4AC2-B7F7-D67AF94F7EEE}']

    function GetCharacteristic: TBigInteger;
    function GetDimension: Int32;

    function Equals(other: TObject): Boolean; overload;
    function Equals(const other: IPrimeField): Boolean; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
    property characteristic: TBigInteger read GetCharacteristic;
    property Dimension: Int32 read GetDimension;

  end;

implementation

end.
