{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpIZTauElement;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger;

type
  /// <summary>
  /// Interface for an element of Z[tau], where lambda = u + v*tau.
  /// </summary>
  IZTauElement = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']

    function GetU: TBigInteger;
    function GetV: TBigInteger;

    property U: TBigInteger read GetU;
    property V: TBigInteger read GetV;
  end;

implementation

end.
