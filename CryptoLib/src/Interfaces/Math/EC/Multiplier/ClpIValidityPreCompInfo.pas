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

unit ClpIValidityPreCompInfo;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPreCompInfo;

type
  IValidityPreCompInfo = interface(IPreCompInfo)
    ['{D4E5F6A7-B890-1234-D4E5-F6A7B8901235}']

    function HasFailed: Boolean;
    procedure ReportFailed;
    function HasCurveEquationPassed: Boolean;
    procedure ReportCurveEquationPassed;
    function HasOrderPassed: Boolean;
    procedure ReportOrderPassed;
  end;

implementation

end.
