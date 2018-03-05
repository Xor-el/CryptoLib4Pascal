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

unit ClpIGenericPolynomialExtensionField;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIPolynomialExtensionField;

type
  IGenericPolynomialExtensionField = interface(IPolynomialExtensionField)
    ['{BB3A963B-38E1-4DF0-A0C6-86DF5CE830FA}']

    function Equals(other: TObject): Boolean; overload;
    function Equals(const other: IGenericPolynomialExtensionField)
      : Boolean; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}

  end;

implementation

end.
