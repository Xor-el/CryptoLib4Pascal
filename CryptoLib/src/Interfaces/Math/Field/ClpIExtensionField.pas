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

unit ClpIExtensionField;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIFiniteField;

type
  IExtensionField = interface(IFiniteField)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567803}']

    function GetSubfield: IFiniteField;
    function GetDegree: Int32;

    property Subfield: IFiniteField read GetSubfield;
    property Degree: Int32 read GetDegree;
  end;

implementation

end.
