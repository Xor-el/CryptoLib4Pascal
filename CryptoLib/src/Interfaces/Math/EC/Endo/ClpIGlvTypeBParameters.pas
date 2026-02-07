{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpIGlvTypeBParameters;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIScalarSplitParameters;

type
  IGlvTypeBParameters = interface(IInterface)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567891}']
    function GetBeta: TBigInteger;
    function GetLambda: TBigInteger;
    function GetSplitParams: IScalarSplitParameters;
    property Beta: TBigInteger read GetBeta;
    property Lambda: TBigInteger read GetLambda;
    property SplitParams: IScalarSplitParameters read GetSplitParams;
  end;

implementation

end.
